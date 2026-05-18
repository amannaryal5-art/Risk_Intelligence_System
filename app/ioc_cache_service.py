"""SQLite-backed IOC lookup cache with 24h TTL and background flush queue."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("riskintel.ioc_cache")

_pending_checks: List[Tuple[str, str]] = []


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class IocCacheService:
    def __init__(self, conn_factory: Any) -> None:
        self._conn = conn_factory

    def get_cached(
        self,
        ioc_value: str,
        ioc_type: str,
        source: str,
    ) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT result, expires_at, is_flagged, verdict, score
                FROM ioc_lookup_cache
                WHERE ioc_value=? AND ioc_type=? AND source=? AND expires_at > ?
                """,
                (ioc_value, ioc_type, source, utc_now_iso()),
            ).fetchone()
        if not row:
            return None
        try:
            payload = json.loads(row["result"] or "{}")
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict):
            payload.setdefault("is_flagged", bool(row["is_flagged"]))
            payload.setdefault("verdict", row["verdict"] or "clean")
            payload.setdefault("score", row["score"])
            payload.setdefault("source", source)
        return payload

    def set_cached(
        self,
        ioc_value: str,
        ioc_type: str,
        source: str,
        result: Dict[str, Any],
        *,
        is_flagged: bool = False,
        verdict: str = "clean",
        score: Optional[int] = None,
    ) -> None:
        checked = utc_now_iso()
        expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO ioc_lookup_cache(
                    ioc_value, ioc_type, source, result, checked_at, expires_at,
                    is_flagged, verdict, score
                ) VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(ioc_value, ioc_type, source) DO UPDATE SET
                    result=excluded.result,
                    checked_at=excluded.checked_at,
                    expires_at=excluded.expires_at,
                    is_flagged=excluded.is_flagged,
                    verdict=excluded.verdict,
                    score=excluded.score
                """,
                (
                    ioc_value,
                    ioc_type,
                    source,
                    json.dumps(result, ensure_ascii=True),
                    checked,
                    expires,
                    int(is_flagged),
                    verdict,
                    score,
                ),
            )
            conn.commit()

    def queue_check(self, value: str, ioc_type: str) -> None:
        _pending_checks.append((value, ioc_type))

    async def flush_queue(self, feed_client: Any, local_ioc_checker: Any) -> int:
        """Process queued IOC checks with rate limits. Returns count processed."""
        processed = 0
        while _pending_checks:
            value, ioc_type = _pending_checks.pop(0)
            try:
                if ioc_type == "ip":
                    cached = self.get_cached(value, "ip", "abuseipdb")
                    if cached:
                        continue
                    from .rate_limited_queue import abuseipdb_queue

                    async def _abuse() -> Dict[str, Any]:
                        return await feed_client.request(
                            "abuseipdb",
                            "GET",
                            "https://api.abuseipdb.com/api/v2/check",
                            params={"ipAddress": value, "maxAgeInDays": 90},
                        )

                    resp = await abuseipdb_queue.add(_abuse)
                    score = 0
                    if resp.get("ok") and isinstance(resp.get("data"), dict):
                        data = resp["data"].get("data") if isinstance(resp["data"].get("data"), dict) else resp["data"]
                        score = int((data or {}).get("abuseConfidenceScore") or 0)
                    verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean"
                    flagged = verdict != "clean" or local_ioc_checker("ip", value)
                    self.set_cached(
                        value,
                        "ip",
                        "abuseipdb",
                        {"score": score, "raw": resp},
                        is_flagged=flagged,
                        verdict=verdict,
                        score=score,
                    )
                    processed += 1
                elif ioc_type == "hash":
                    cached = self.get_cached(value.lower(), "hash", "virustotal")
                    if cached:
                        continue
                    from .rate_limited_queue import virustotal_queue

                    async def _vt() -> Dict[str, Any]:
                        return await feed_client.request(
                            "virustotal",
                            "GET",
                            f"https://www.virustotal.com/api/v3/files/{value.lower()}",
                        )

                    resp = await virustotal_queue.add(_vt)
                    malicious = 0
                    if resp.get("ok") and isinstance(resp.get("data"), dict):
                        stats = (
                            ((resp["data"].get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
                        )
                        malicious = int(stats.get("malicious") or 0) + int(stats.get("suspicious") or 0)
                    verdict = "malicious" if malicious > 0 else "clean"
                    self.set_cached(
                        value.lower(),
                        "hash",
                        "virustotal",
                        {"malicious": malicious, "raw": resp},
                        is_flagged=malicious > 0,
                        verdict=verdict,
                        score=malicious,
                    )
                    processed += 1
            except Exception as exc:
                logger.warning("IOC flush failed for %s %s: %s", ioc_type, value, exc)
        return processed
