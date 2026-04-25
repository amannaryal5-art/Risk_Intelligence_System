from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit


class ScamCheckCacheStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS scamcheck_cache (
                        id TEXT PRIMARY KEY,
                        input_hash TEXT UNIQUE NOT NULL,
                        result TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_scamcheck_cache_created_at ON scamcheck_cache(created_at)"
                )
                conn.commit()

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def hash_input(value: str) -> str:
        return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()

    def get(self, input_value: str, ttl_seconds: int = 3600) -> Optional[Dict[str, Any]]:
        input_hash = self.hash_input(input_value)
        cutoff = (self._now() - timedelta(seconds=ttl_seconds)).isoformat()
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT result FROM scamcheck_cache WHERE input_hash = ? AND created_at >= ?",
                    (input_hash, cutoff),
                ).fetchone()
        if not row:
            return None
        try:
            return json.loads(row["result"])
        except Exception:
            return None

    def was_seen_before(self, input_value: str) -> bool:
        input_hash = self.hash_input(input_value)
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT 1 FROM scamcheck_cache WHERE input_hash = ? LIMIT 1",
                    (input_hash,),
                ).fetchone()
        return bool(row)

    def set(self, input_value: str, result: Dict[str, Any]) -> None:
        input_hash = self.hash_input(input_value)
        created_at = self._now().isoformat()
        payload = json.dumps(result, ensure_ascii=True)
        cache_id = str(hashlib.md5(f"{input_hash}:{created_at}".encode("utf-8")).hexdigest())
        with self._lock:
            with self._connect() as conn:
                conn.execute("DELETE FROM scamcheck_cache WHERE input_hash = ?", (input_hash,))
                conn.execute(
                    """
                    INSERT INTO scamcheck_cache(id, input_hash, result, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (cache_id, input_hash, payload, created_at),
                )
                conn.commit()


class ScamCheckService:
    def __init__(self, threat_intel_engine: Any, risk_engine: Any, cache_store: ScamCheckCacheStore) -> None:
        self.threat_intel_engine = threat_intel_engine
        self.risk_engine = risk_engine
        self.cache_store = cache_store
        self._executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="scamcheck")
        self._re_url = re.compile(r"(?:(?:https?|ftp)://|www\.)[^\s<>'\"()]+", re.IGNORECASE)
        self._re_ip = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        self._re_domain = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b")
        self._re_email = re.compile(r"\b([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b")

    async def check_async(self, input_value: str, detected_type: str) -> Dict[str, Any]:
        loop = __import__("asyncio").get_event_loop()
        return await loop.run_in_executor(self._executor, lambda: self.check(input_value, detected_type))

    def check(self, input_value: str, detected_type: str) -> Dict[str, Any]:
        cached = self.cache_store.get(input_value)
        if cached is not None:
            cached["cacheHit"] = True
            return cached

        normalized_type = (detected_type or "text").strip().lower()
        raw = (input_value or "").strip()
        if not raw:
            return self._empty_result(raw, normalized_type)

        if normalized_type in {"url", "domain"}:
            result = self._scan_domain_or_url(raw, normalized_type)
        elif normalized_type == "ip":
            result = self._scan_ip(raw)
        elif normalized_type == "email":
            result = self._scan_email(raw)
        elif normalized_type in {"phone", "upi"}:
            result = self._scan_identity_like(raw, normalized_type)
        else:
            result = self._scan_text(raw)

        result["cacheHit"] = False
        self.cache_store.set(raw, result)
        return result

    def _empty_result(self, input_value: str, detected_type: str) -> Dict[str, Any]:
        return {
            "input": input_value,
            "detectedType": detected_type,
            "verdict": "SAFE",
            "confidence": 0,
            "summary": "Paste a link, phone number, UPI ID, email, IP, or suspicious message to check it.",
            "details": {},
            "rawResults": {},
            "scannedAt": datetime.now(timezone.utc).isoformat(),
        }

    def _scan_domain_or_url(self, value: str, detected_type: str) -> Dict[str, Any]:
        target = value.strip()
        host = self._extract_host(target)
        otx = self._safe_lookup(self.threat_intel_engine._lookup_otx, "domain" if detected_type == "domain" else "url", host if detected_type == "domain" else target)
        vt = self._safe_lookup(self.threat_intel_engine._lookup_virustotal, "domain" if detected_type == "domain" else "url", host if detected_type == "domain" else target)
        abuse = self._safe_lookup(self.threat_intel_engine._lookup_abuseipdb, "domain", host)
        domain_age = self.risk_engine._whois_domain_age_profile(host) if host else {}
        return self._build_result(
            input_value=value,
            detected_type=detected_type,
            details=self._compose_details(host, abuse, vt, otx, domain_age),
            raw_results={"otx": otx, "abuseipdb": abuse, "virustotal": vt, "domainAge": domain_age},
        )

    def _scan_ip(self, value: str) -> Dict[str, Any]:
        otx = self._safe_lookup(self.threat_intel_engine._lookup_otx, "ip", value)
        abuse = self._safe_lookup(self.threat_intel_engine._lookup_abuseipdb, "ip", value)
        vt = self._safe_lookup(self.threat_intel_engine._lookup_virustotal, "ip", value)
        return self._build_result(
            input_value=value,
            detected_type="ip",
            details=self._compose_details(value, abuse, vt, otx, {}),
            raw_results={"otx": otx, "abuseipdb": abuse, "virustotal": vt},
        )

    def _scan_email(self, value: str) -> Dict[str, Any]:
        match = self._re_email.search(value)
        domain = match.group(2).lower() if match else ""
        otx = self._safe_lookup(self.threat_intel_engine._lookup_otx, "domain", domain)
        abuse = self._safe_lookup(self.threat_intel_engine._lookup_abuseipdb, "domain", domain)
        vt = self._safe_lookup(self.threat_intel_engine._lookup_virustotal, "domain", domain)
        domain_age = self.risk_engine._whois_domain_age_profile(domain) if domain else {}
        return self._build_result(
            input_value=value,
            detected_type="email",
            details=self._compose_details(domain, abuse, vt, otx, domain_age),
            raw_results={"otx": otx, "abuseipdb": abuse, "virustotal": vt, "domainAge": domain_age},
        )

    def _scan_identity_like(self, value: str, detected_type: str) -> Dict[str, Any]:
        seen_before = self.cache_store.was_seen_before(value)
        abuse = {
            "enabled": bool(getattr(self.threat_intel_engine, "abuseipdb_key", "")),
            "listed": not seen_before,
            "abuse_confidence": 15 if not seen_before else 0,
            "source": "abuseipdb",
            "note": "AbuseIPDB does not provide native phone or UPI reputation in this codebase; this result uses first-seen heuristics.",
            "newly_seen": not seen_before,
        }
        return self._build_result(
            input_value=value,
            detected_type=detected_type,
            details={
                "abuseConfidence": abuse["abuse_confidence"],
                "country": "IN",
                "newlySeen": not seen_before,
            },
            raw_results={"abuseipdb": abuse},
        )

    def _scan_text(self, value: str) -> Dict[str, Any]:
        items: List[Dict[str, Any]] = []
        seen: set[str] = set()
        for match in self._re_url.findall(value):
            cleaned = match.strip(".,);]}>\"'")
            if cleaned and cleaned.lower() not in seen:
                seen.add(cleaned.lower())
                items.append(self._scan_domain_or_url(cleaned, "url"))
        for match in self._re_ip.findall(value):
            if match and match not in seen:
                seen.add(match)
                items.append(self._scan_ip(match))
        for match in self._re_domain.findall(value):
            cleaned = match.lower().lstrip("www.")
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                items.append(self._scan_domain_or_url(cleaned, "domain"))

        if not items:
            return {
                "input": value,
                "detectedType": "text",
                "verdict": "CAUTION",
                "confidence": 25,
                "summary": "We could not find a link, domain, or IP in that message. Treat unsolicited forwards with caution.",
                "details": {"itemsScanned": 0},
                "rawResults": {"items": []},
                "scannedAt": datetime.now(timezone.utc).isoformat(),
            }

        ranked = sorted(items, key=lambda item: ("DANGER", "CAUTION", "SAFE").index(item["verdict"]))
        worst = ranked[0]
        return {
            "input": value,
            "detectedType": "text",
            "verdict": worst["verdict"],
            "confidence": max(item.get("confidence", 0) for item in items),
            "summary": f"Checked {len(items)} indicators from the message. Highest risk finding: {worst['summary']}",
            "details": {
                "itemsScanned": len(items),
                "aggregateVerdict": worst["verdict"],
            },
            "rawResults": {"items": items},
            "scannedAt": datetime.now(timezone.utc).isoformat(),
        }

    def _compose_details(
        self,
        subject: str,
        abuse: Dict[str, Any],
        vt: Dict[str, Any],
        otx: Dict[str, Any],
        domain_age: Dict[str, Any],
    ) -> Dict[str, Any]:
        age_days = domain_age.get("age_days")
        return {
            "whatWasFound": subject,
            "hostedOn": abuse.get("isp") or subject,
            "domainAge": f"{age_days} days" if isinstance(age_days, int) else None,
            "domainAgeDays": age_days,
            "vtDetections": vt.get("malicious_votes", 0),
            "vtTotal": (vt.get("malicious_votes", 0) or 0) + (vt.get("suspicious_votes", 0) or 0),
            "otxPulses": otx.get("pulse_count", 0),
            "abuseConfidence": abuse.get("abuse_confidence", 0),
            "country": abuse.get("country"),
            "isp": abuse.get("isp"),
        }

    def _build_result(
        self,
        input_value: str,
        detected_type: str,
        details: Dict[str, Any],
        raw_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        vt_detections = int(details.get("vtDetections") or 0)
        abuse_confidence = int(details.get("abuseConfidence") or 0)
        otx_pulses = int(details.get("otxPulses") or 0)
        domain_age_days = details.get("domainAgeDays")

        if vt_detections > 5 or abuse_confidence > 50 or otx_pulses > 2:
            verdict = "DANGER"
        elif (10 <= abuse_confidence <= 50) or (isinstance(domain_age_days, int) and domain_age_days < 30) or (1 <= vt_detections <= 5):
            verdict = "CAUTION"
        else:
            verdict = "SAFE"

        confidence = min(
            100,
            max(
                vt_detections * 12,
                abuse_confidence,
                otx_pulses * 22,
                35 if isinstance(domain_age_days, int) and domain_age_days < 30 else 0,
                5 if verdict == "SAFE" else 0,
            ),
        )

        summary = self._plain_summary(verdict, detected_type, details)
        return {
            "input": input_value,
            "detectedType": detected_type,
            "verdict": verdict,
            "confidence": confidence,
            "summary": summary,
            "details": details,
            "rawResults": raw_results,
            "scannedAt": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def _safe_lookup(method: Any, ioc_type: str, value: str) -> Dict[str, Any]:
        try:
            return method(ioc_type, value)
        except Exception as exc:
            return {"enabled": False, "listed": False, "source": getattr(method, "__name__", "lookup"), "error": str(exc)[:220]}

    @staticmethod
    def _extract_host(value: str) -> str:
        raw = value.strip()
        if re.match(r"^https?://", raw, re.IGNORECASE):
            return (urlsplit(raw).hostname or "").lower()
        return raw.lower().lstrip("www.")

    @staticmethod
    def _plain_summary(verdict: str, detected_type: str, details: Dict[str, Any]) -> str:
        vt = int(details.get("vtDetections") or 0)
        abuse = int(details.get("abuseConfidence") or 0)
        pulses = int(details.get("otxPulses") or 0)
        age = details.get("domainAge")
        newly_seen = details.get("newlySeen")

        if verdict == "DANGER":
            if vt > 5:
                return f"Do not trust this {detected_type} right now. VirusTotal flagged it across {vt} engines."
            if abuse > 50:
                return f"This looks risky. Abuse reports are unusually high with a confidence score of {abuse}."
            return f"This indicator has already been linked to multiple threat reports, including {pulses} OTX pulses."
        if verdict == "CAUTION":
            if vt:
                return f"Be careful before opening it. A few security engines already flagged it ({vt} detections)."
            if age:
                return f"Proceed carefully. The domain is very new ({age}), which is common in scam campaigns."
            if newly_seen:
                return "This phone or UPI identifier is newly seen in our local history, so we recommend caution."
            return "There are some warning signs, but not enough evidence to call it confirmed malicious."
        return "No strong threat signals were found in the connected feeds for this input."
