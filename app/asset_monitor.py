"""
ARIA — Asset Monitor
Handles asset registry, automated threat scanning, and scheduled monitoring.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("aria.monitor")

DEFAULT_DB_DIR = (
    Path(tempfile.gettempdir()) / "riskintel"
    if os.getenv("VERCEL")
    else Path(__file__).parent / "data"
)
DB_PATH = Path(os.getenv("RISKINTEL_DATA_DIR", str(DEFAULT_DB_DIR))) / "aria.db"

# ─── Database ─────────────────────────────────────────────────────────────────

class AssetDB:
    def __init__(self, path: Path = DB_PATH):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self):
        with self._conn() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL UNIQUE,
                    active INTEGER DEFAULT 1,
                    scan_interval_hours INTEGER DEFAULT 6,
                    last_scanned TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER NOT NULL,
                    risk_level TEXT DEFAULT 'Unknown',
                    risk_score INTEGER DEFAULT 0,
                    summary TEXT,
                    key_findings TEXT DEFAULT '[]',
                    threat_indicators TEXT DEFAULT '[]',
                    recommendations TEXT DEFAULT '[]',
                    threat_categories TEXT DEFAULT '[]',
                    raw_data TEXT DEFAULT '{}',
                    scanned_at TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY (asset_id) REFERENCES assets(id)
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER,
                    asset_value TEXT,
                    risk_level TEXT,
                    title TEXT,
                    message TEXT,
                    seen INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT,
                    content TEXT,
                    generated_at TEXT DEFAULT (datetime('now'))
                );
            """)

    # ── Assets ────────────────────────────────────────────────────────────────

    def add_asset(self, name: str, asset_type: str, value: str, interval: int = 6) -> int:
        with self._conn() as c:
            try:
                c.execute(
                    "INSERT INTO assets (name,type,value,scan_interval_hours) VALUES (?,?,?,?)",
                    (name.strip(), asset_type, value.strip(), interval),
                )
                return c.lastrowid
            except sqlite3.IntegrityError:
                row = c.execute("SELECT id FROM assets WHERE value=?", (value.strip(),)).fetchone()
                return row["id"]

    def get_assets(self) -> List[Dict]:
        with self._conn() as c:
            rows = c.execute("""
                SELECT
                    a.*,
                    sr.risk_level   AS last_risk_level,
                    sr.risk_score   AS last_risk_score,
                    sr.summary      AS last_summary,
                    sr.key_findings AS last_findings,
                    sr.scanned_at   AS last_scanned_at
                FROM assets a
                LEFT JOIN scan_results sr ON sr.id = (
                    SELECT id FROM scan_results WHERE asset_id=a.id
                    ORDER BY scanned_at DESC LIMIT 1
                )
                WHERE a.active=1
                ORDER BY a.created_at DESC
            """).fetchall()
            return [dict(r) for r in rows]

    def get_asset(self, aid: int) -> Optional[Dict]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
            return dict(row) if row else None

    def delete_asset(self, aid: int):
        with self._conn() as c:
            c.execute("UPDATE assets SET active=0 WHERE id=?", (aid,))

    def mark_scanned(self, aid: int):
        with self._conn() as c:
            c.execute(
                "UPDATE assets SET last_scanned=datetime('now') WHERE id=?", (aid,)
            )

    def get_due_assets(self) -> List[Dict]:
        """Return assets due for a scan based on their scan_interval_hours."""
        with self._conn() as c:
            rows = c.execute("""
                SELECT * FROM assets WHERE active=1 AND (
                    last_scanned IS NULL OR
                    datetime(last_scanned, '+' || scan_interval_hours || ' hours')
                        <= datetime('now')
                )
            """).fetchall()
            return [dict(r) for r in rows]

    # ── Scan Results ──────────────────────────────────────────────────────────

    def save_scan(self, asset_id: int, ai_result: Dict, raw_data: Dict) -> int:
        with self._conn() as c:
            c.execute("""
                INSERT INTO scan_results
                (asset_id,risk_level,risk_score,summary,key_findings,
                 threat_indicators,recommendations,threat_categories,raw_data)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (
                asset_id,
                ai_result.get("risk_level", "Unknown"),
                ai_result.get("risk_score", 0),
                ai_result.get("summary", ""),
                json.dumps(ai_result.get("key_findings", [])),
                json.dumps(ai_result.get("threat_indicators", [])),
                json.dumps(ai_result.get("recommendations", [])),
                json.dumps(ai_result.get("threat_categories", [])),
                json.dumps(raw_data),
            ))
            return c.lastrowid

    def get_recent_scans(self, hours: int = 24) -> List[Dict]:
        since = (datetime.now() - timedelta(hours=hours)).isoformat()
        with self._conn() as c:
            rows = c.execute("""
                SELECT sr.*, a.name AS asset_name, a.value AS asset_value, a.type AS asset_type
                FROM scan_results sr
                JOIN assets a ON sr.asset_id=a.id
                WHERE sr.scanned_at >= ?
                ORDER BY sr.scanned_at DESC
            """, (since,)).fetchall()
            return [dict(r) for r in rows]

    def get_asset_history(self, aid: int, limit: int = 30) -> List[Dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM scan_results WHERE asset_id=? ORDER BY scanned_at DESC LIMIT ?",
                (aid, limit),
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Alerts ────────────────────────────────────────────────────────────────

    def add_alert(self, asset_id: int, asset_value: str, risk_level: str,
                  title: str, message: str):
        with self._conn() as c:
            c.execute(
                "INSERT INTO alerts (asset_id,asset_value,risk_level,title,message) VALUES (?,?,?,?,?)",
                (asset_id, asset_value, risk_level, title, message),
            )

    def get_alerts(self, limit: int = 50) -> List[Dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def mark_seen(self, alert_id: int):
        with self._conn() as c:
            c.execute("UPDATE alerts SET seen=1 WHERE id=?", (alert_id,))

    def mark_all_seen(self):
        with self._conn() as c:
            c.execute("UPDATE alerts SET seen=1")

    def unseen_count(self) -> int:
        with self._conn() as c:
            return c.execute("SELECT COUNT(*) FROM alerts WHERE seen=0").fetchone()[0]

    # ── Reports ───────────────────────────────────────────────────────────────

    def save_report(self, title: str, content: str) -> int:
        with self._conn() as c:
            c.execute("INSERT INTO reports (title,content) VALUES (?,?)", (title, content))
            return c.lastrowid

    def get_reports(self, limit: int = 20) -> List[Dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT id,title,generated_at FROM reports ORDER BY generated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_report(self, rid: int) -> Optional[Dict]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
            return dict(row) if row else None

    # ── Context for AI chat ───────────────────────────────────────────────────

    def build_chat_context(self) -> str:
        assets  = self.get_assets()
        alerts  = self.get_alerts(10)
        recent  = self.get_recent_scans(24)

        critical = [a for a in assets if a.get("last_risk_level") in ("Critical", "High")]
        clean    = [a for a in assets if a.get("last_risk_level") == "Clean"]

        lines = [
            f"Total monitored assets: {len(assets)}",
            f"Critical/High risk: {len(critical)}",
            f"Clean: {len(clean)}",
            f"Unseen alerts: {self.unseen_count()}",
            f"Scans in last 24h: {len(recent)}",
        ]

        if critical:
            lines.append("HIGH RISK ASSETS: " + ", ".join(
                f"{a['value']} ({a['last_risk_level']}, score {a['last_risk_score']})"
                for a in critical[:8]
            ))

        if recent:
            lines.append("RECENT SCANS: " + ", ".join(
                f"{r['asset_value']}={r['risk_level']}"
                for r in recent[:10]
            ))

        if alerts:
            lines.append("LATEST ALERTS: " + "; ".join(
                f"{a['asset_value']}: {a['title']}" for a in alerts[:5]
            ))

        return "\n".join(lines)


# ─── Threat Scanner ────────────────────────────────────────────────────────────

async def _check_virustotal(target: str, asset_type: str) -> Dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {"source": "virustotal", "status": "no_api_key"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            if asset_type == "ip":
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            elif asset_type in ("domain", "url"):
                import base64
                encoded = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
                url = f"https://www.virustotal.com/api/v3/urls/{encoded}"
            else:
                return {"source": "virustotal", "status": "unsupported_type"}

            resp = await client.get(url, headers={"x-apikey": api_key})
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "source": "virustotal",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                }
            return {"source": "virustotal", "status": resp.status_code}
    except Exception as e:
        return {"source": "virustotal", "error": str(e)}


async def _check_abuseipdb(ip: str) -> Dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return {"source": "abuseipdb", "status": "no_api_key"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": api_key, "Accept": "application/json"},
            )
            if resp.status_code == 200:
                d = resp.json().get("data", {})
                return {
                    "source": "abuseipdb",
                    "abuse_score": d.get("abuseConfidenceScore", 0),
                    "total_reports": d.get("totalReports", 0),
                    "country": d.get("countryCode"),
                    "isp": d.get("isp"),
                    "usage_type": d.get("usageType"),
                }
            return {"source": "abuseipdb", "status": resp.status_code}
    except Exception as e:
        return {"source": "abuseipdb", "error": str(e)}


async def _check_otx(target: str, asset_type: str) -> Dict:
    api_key = os.getenv("OTX_API_KEY", "")
    if not api_key:
        return {"source": "otx", "status": "no_api_key"}
    try:
        type_map = {"ip": "IPv4", "domain": "domain", "url": "url"}
        otx_type = type_map.get(asset_type, "domain")
        url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{target}/general"
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, headers={"X-OTX-API-KEY": api_key})
            if resp.status_code == 200:
                d = resp.json()
                return {
                    "source": "otx",
                    "pulse_count": d.get("pulse_info", {}).get("count", 0),
                    "threat_score": d.get("pulse_info", {}).get("threat_score_value", 0),
                    "tags": d.get("pulse_info", {}).get("tags", [])[:10],
                    "country": d.get("country_name"),
                }
            return {"source": "otx", "status": resp.status_code}
    except Exception as e:
        return {"source": "otx", "error": str(e)}


async def scan_asset(asset: Dict) -> Dict[str, Any]:
    """
    Run all available threat intel checks on an asset, then use AI to analyze results.
    Returns the AI-structured result dict.
    """
    from ai_engine import analyze_threat

    target      = asset["value"]
    asset_type  = asset["type"]   # domain | ip | url | email

    tasks = [_check_virustotal(target, asset_type)]
    if asset_type == "ip":
        tasks.append(_check_abuseipdb(target))
    tasks.append(_check_otx(target, asset_type))

    raw_results = await asyncio.gather(*tasks, return_exceptions=True)
    raw_data    = {
        "target":     target,
        "asset_type": asset_type,
        "scanned_at": datetime.now().isoformat(),
        "intel":      [r for r in raw_results if isinstance(r, dict)],
    }

    ai_result = await analyze_threat(target, raw_data)
    return ai_result, raw_data


# ─── Scheduler Loop ────────────────────────────────────────────────────────────

db = AssetDB()


async def run_monitoring_cycle():
    """
    Check all assets due for scanning, run scans, save results, raise alerts.
    Called every 30 minutes by the scheduler — only scans assets whose
    interval has elapsed.
    """
    due = db.get_due_assets()
    if not due:
        logger.info("Monitoring cycle: no assets due")
        return

    logger.info(f"Monitoring cycle: scanning {len(due)} assets")
    for asset in due:
        try:
            ai_result, raw_data = await scan_asset(asset)
            db.save_scan(asset["id"], ai_result, raw_data)
            db.mark_scanned(asset["id"])

            # Raise alert if risk level is High or Critical
            if ai_result.get("risk_level") in ("Critical", "High"):
                findings = ai_result.get("key_findings", [])
                title    = f"{ai_result['risk_level']} risk detected on {asset['value']}"
                message  = ai_result.get("summary", "")
                if findings:
                    message += " Findings: " + "; ".join(findings[:3])
                db.add_alert(asset["id"], asset["value"], ai_result["risk_level"], title, message)

            logger.info(f"  ✓ {asset['value']} → {ai_result.get('risk_level')} (score {ai_result.get('risk_score')})")
            await asyncio.sleep(1)   # be polite to external APIs
        except Exception as e:
            logger.error(f"  ✗ Failed to scan {asset['value']}: {e}")


async def run_daily_report():
    """Generate and save an AI daily threat briefing. Called at 08:00 daily."""
    from ai_engine import generate_daily_report

    assets       = db.get_assets()
    recent_scans = db.get_recent_scans(24)
    alerts       = db.get_alerts(20)

    content = await generate_daily_report(assets, recent_scans, alerts)
    title   = f"Daily Threat Briefing — {datetime.now().strftime('%d %b %Y')}"
    rid     = db.save_report(title, content)
    logger.info(f"Daily report generated: #{rid}")
    return rid
