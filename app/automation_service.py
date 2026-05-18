from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import sqlite3
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

import httpx

logger = logging.getLogger("riskintel.automation")

DEFAULT_DB_DIR = (
    Path(tempfile.gettempdir()) / "riskintel"
    if os.getenv("VERCEL")
    else Path(__file__).parent / "data"
)
DB_PATH = Path(os.getenv("RISKINTEL_DATA_DIR", str(DEFAULT_DB_DIR))) / "riskintel.db"

DEMO_ASSETS = [
    {"label": "Google DNS", "type": "ip", "value": "8.8.8.8"},
    {"label": "Cloudflare DNS", "type": "ip", "value": "1.1.1.1"},
    {"label": "Example Domain", "type": "domain", "value": "example.com"},
    {"label": "Test Domain", "type": "domain", "value": "testdomain.net"},
]

IOC_PATTERNS = {
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "url": re.compile(r"(?:(?:https?|ftp)://|www\.)[^\s<>'\"()]+", re.IGNORECASE),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b"),
    "hash": re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"),
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def _json_loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _risk_level(score: Optional[float]) -> str:
    if score is None:
        return "unscanned"
    if score > 85:
        return "critical"
    if score > 70:
        return "high"
    if score > 40:
        return "medium"
    return "low"


@dataclass
class PipelineStepResult:
    task: str
    status: str
    summary: str
    data: Dict[str, Any]
    duration_ms: int
    error: Optional[str] = None


class FeedClient:
    def __init__(self) -> None:
        self._gate: Dict[str, asyncio.Lock] = {
            "otx": asyncio.Lock(),
            "abuseipdb": asyncio.Lock(),
            "virustotal": asyncio.Lock(),
            "urlscan": asyncio.Lock(),
        }
        self._last_call: Dict[str, float] = {name: 0.0 for name in self._gate}

    @staticmethod
    def _env(*names: str) -> str:
        for name in names:
            value = os.getenv(name, "").strip()
            if value:
                return value
        return ""

    def key_status(self) -> Dict[str, bool]:
        return {
            "otx": bool(self._env("OTX_API_KEY", "RISKINTEL_OTX_API_KEY")),
            "abuseipdb": bool(self._env("ABUSEIPDB_API_KEY", "RISKINTEL_ABUSEIPDB_API_KEY")),
            "vt": bool(self._env("VIRUSTOTAL_API_KEY", "RISKINTEL_VT_API_KEY")),
            "urlscan": bool(self._env("URLSCAN_API_KEY", "RISKINTEL_URLSCAN_API_KEY")),
        }

    async def request(
        self,
        provider: str,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        timeout: float = 20.0,
    ) -> Dict[str, Any]:
        headers = {"User-Agent": "CRIE/3.0"}
        key = ""
        if provider == "otx":
            key = self._env("OTX_API_KEY", "RISKINTEL_OTX_API_KEY")
            if key:
                headers["X-OTX-API-KEY"] = key
        elif provider == "abuseipdb":
            key = self._env("ABUSEIPDB_API_KEY", "RISKINTEL_ABUSEIPDB_API_KEY")
            if key:
                headers["Key"] = key
                headers["Accept"] = "application/json"
        elif provider == "virustotal":
            key = self._env("VIRUSTOTAL_API_KEY", "RISKINTEL_VT_API_KEY")
            if key:
                headers["x-apikey"] = key
        elif provider == "urlscan":
            key = self._env("URLSCAN_API_KEY", "RISKINTEL_URLSCAN_API_KEY")
            if key:
                headers["API-Key"] = key
        async def _do_request() -> Dict[str, Any]:
            started = time.perf_counter()
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.request(method, url, headers=headers, params=params, json=json_body)
                latency_ms = int((time.perf_counter() - started) * 1000)
                payload: Any
                try:
                    payload = response.json()
                except ValueError:
                    payload = {"text": response.text[:500]}
                return {
                    "ok": response.is_success,
                    "http_status": response.status_code,
                    "latency_ms": latency_ms,
                    "data": payload,
                    "auth_valid": response.status_code not in {401, 403},
                    "reachable": True,
                    "error": None if response.status_code != 429 else "rate_limited",
                }
            except Exception as exc:
                return {
                    "ok": False,
                    "http_status": None,
                    "latency_ms": int((time.perf_counter() - started) * 1000),
                    "data": {},
                    "auth_valid": None,
                    "reachable": False,
                    "error": str(exc),
                }

        from .rate_limited_queue import abuseipdb_queue, alienvault_queue, urlscan_queue, virustotal_queue

        queue_map = {
            "abuseipdb": abuseipdb_queue,
            "virustotal": virustotal_queue,
            "urlscan": urlscan_queue,
            "otx": alienvault_queue,
        }
        queue = queue_map.get(provider)
        if queue:
            return await queue.add(_do_request)
        return await _do_request()


class WebSocketHub:
    def __init__(self) -> None:
        self._clients: set[Any] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: Any) -> None:
        await websocket.accept()
        async with self._lock:
            self._clients.add(websocket)

    async def disconnect(self, websocket: Any) -> None:
        async with self._lock:
            self._clients.discard(websocket)

    async def broadcast(self, payload: Dict[str, Any]) -> None:
        async with self._lock:
            clients = list(self._clients)
        stale = []
        for websocket in clients:
            try:
                await websocket.send_json(payload)
            except Exception:
                stale.append(websocket)
        if stale:
            async with self._lock:
                for websocket in stale:
                    self._clients.discard(websocket)


class AutomationService:
    def __init__(
        self,
        db_path: Path = DB_PATH,
        *,
        case_store: Any = None,
        audit_writer: Optional[Callable[..., Any]] = None,
        risk_engine: Any = None,
        threat_intel_engine: Any = None,
        fusion_engine: Any = None,
        website_scan_builder: Optional[Callable[[str], Dict[str, Any]]] = None,
    ) -> None:
        self.db_path = db_path
        self.case_store = case_store
        self.audit_writer = audit_writer
        self.risk_engine = risk_engine
        self.threat_intel_engine = threat_intel_engine
        self.fusion_engine = fusion_engine
        self.website_scan_builder = website_scan_builder
        self.feed_client = FeedClient()
        self.ws_hub = WebSocketHub()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        from .ioc_cache_service import IocCacheService

        self.ioc_cache = IocCacheService(self._conn)
        self.seed_demo_assets()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=20, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    label TEXT NOT NULL,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL UNIQUE,
                    active INTEGER NOT NULL DEFAULT 1,
                    risk_score REAL,
                    last_scanned TEXT,
                    raw_data_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER,
                    asset_value TEXT,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    seen INTEGER NOT NULL DEFAULT 0,
                    active INTEGER NOT NULL DEFAULT 1,
                    case_id INTEGER,
                    alert_type TEXT DEFAULT 'risk_threshold',
                    source TEXT DEFAULT 'system',
                    metadata_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    generated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS risk_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER NOT NULL,
                    risk_score REAL NOT NULL,
                    raw_data_json TEXT DEFAULT '{}',
                    scanned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS pipeline_runs (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    current_task TEXT,
                    tasks_passed INTEGER NOT NULL DEFAULT 0,
                    tasks_failed INTEGER NOT NULL DEFAULT 0,
                    progress_pct INTEGER NOT NULL DEFAULT 0,
                    duration_ms INTEGER
                );
                CREATE TABLE IF NOT EXISTS pipeline_steps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    task_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    data_json TEXT DEFAULT '{}',
                    duration_ms INTEGER NOT NULL DEFAULT 0,
                    error TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS feed_status (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    reachable INTEGER,
                    auth_valid INTEGER,
                    latency_ms INTEGER,
                    http_status INTEGER,
                    warning TEXT,
                    last_checked TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS stats (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL UNIQUE,
                    source TEXT NOT NULL,
                    confidence REAL DEFAULT 0,
                    tags_json TEXT DEFAULT '[]',
                    metadata_json TEXT DEFAULT '{}',
                    vt_result_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS website_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER,
                    domain TEXT NOT NULL,
                    scan_uuid TEXT,
                    score REAL,
                    malicious INTEGER DEFAULT 0,
                    verdict TEXT,
                    screenshot_url TEXT,
                    result_json TEXT DEFAULT '{}',
                    scanned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS file_analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_id INTEGER,
                    hash_value TEXT NOT NULL,
                    file_name TEXT,
                    malicious_count INTEGER DEFAULT 0,
                    suspicious_count INTEGER DEFAULT 0,
                    result_json TEXT DEFAULT '{}',
                    scanned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS fusion_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_value TEXT NOT NULL,
                    text_risk REAL DEFAULT 0,
                    web_risk REAL DEFAULT 0,
                    feed_risk REAL DEFAULT 0,
                    fusion_score REAL DEFAULT 0,
                    result_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS intelligence_sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    triggered_at TEXT NOT NULL,
                    completed_at TEXT,
                    assets_scanned INTEGER NOT NULL DEFAULT 0,
                    threats_found INTEGER NOT NULL DEFAULT 0,
                    critical_count INTEGER NOT NULL DEFAULT 0,
                    overall_risk_score REAL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'running',
                    full_results TEXT DEFAULT '{}',
                    correlation_map TEXT DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS device_scan_sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL DEFAULT '',
                    triggered_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT NOT NULL DEFAULT 'running',
                    triggered_by TEXT NOT NULL DEFAULT 'manual',
                    os_platform TEXT,
                    hostname TEXT,
                    connections_found INTEGER NOT NULL DEFAULT 0,
                    connections_flagged INTEGER NOT NULL DEFAULT 0,
                    processes_found INTEGER NOT NULL DEFAULT 0,
                    processes_flagged INTEGER NOT NULL DEFAULT 0,
                    ports_open INTEGER NOT NULL DEFAULT 0,
                    ports_suspicious INTEGER NOT NULL DEFAULT 0,
                    software_count INTEGER NOT NULL DEFAULT 0,
                    dns_entries_checked INTEGER NOT NULL DEFAULT 0,
                    dns_flagged INTEGER NOT NULL DEFAULT 0,
                    startup_items INTEGER NOT NULL DEFAULT 0,
                    startup_flagged INTEGER NOT NULL DEFAULT 0,
                    overall_risk_score INTEGER NOT NULL DEFAULT 0,
                    full_results TEXT DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS device_network_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    local_ip TEXT,
                    local_port INTEGER,
                    remote_ip TEXT,
                    remote_port INTEGER,
                    protocol TEXT,
                    state TEXT,
                    pid INTEGER,
                    process_name TEXT,
                    process_path TEXT,
                    is_flagged INTEGER NOT NULL DEFAULT 0,
                    ioc_confidence INTEGER,
                    threat_type TEXT,
                    threat_source TEXT,
                    verdict TEXT NOT NULL DEFAULT 'clean',
                    FOREIGN KEY(session_id) REFERENCES device_scan_sessions(id)
                );
                CREATE TABLE IF NOT EXISTS device_processes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    pid INTEGER,
                    name TEXT,
                    path TEXT,
                    cpu_percent REAL,
                    memory_mb REAL,
                    sha256_hash TEXT,
                    is_flagged INTEGER NOT NULL DEFAULT 0,
                    vt_positives INTEGER,
                    vt_total INTEGER,
                    suspicious_path_reason TEXT,
                    verdict TEXT NOT NULL DEFAULT 'clean',
                    FOREIGN KEY(session_id) REFERENCES device_scan_sessions(id)
                );
                CREATE TABLE IF NOT EXISTS device_open_ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    port INTEGER,
                    protocol TEXT,
                    bound_address TEXT,
                    pid INTEGER,
                    process_name TEXT,
                    is_flagged INTEGER NOT NULL DEFAULT 0,
                    flag_reason TEXT,
                    FOREIGN KEY(session_id) REFERENCES device_scan_sessions(id)
                );
                CREATE TABLE IF NOT EXISTS device_software_inventory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    name TEXT,
                    version TEXT,
                    publisher TEXT,
                    install_date TEXT,
                    known_cves TEXT DEFAULT '[]',
                    FOREIGN KEY(session_id) REFERENCES device_scan_sessions(id)
                );
                CREATE TABLE IF NOT EXISTS device_startup_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    name TEXT,
                    command TEXT,
                    type TEXT,
                    is_flagged INTEGER NOT NULL DEFAULT 0,
                    flag_reason TEXT,
                    sha256_hash TEXT,
                    vt_positives INTEGER,
                    verdict TEXT NOT NULL DEFAULT 'clean',
                    FOREIGN KEY(session_id) REFERENCES device_scan_sessions(id)
                );
                CREATE TABLE IF NOT EXISTS ioc_lookup_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_value TEXT NOT NULL,
                    ioc_type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    result TEXT NOT NULL DEFAULT '{}',
                    checked_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    UNIQUE(ioc_value, ioc_type, source)
                );
                CREATE INDEX IF NOT EXISTS idx_device_net_session ON device_network_connections(session_id);
                CREATE INDEX IF NOT EXISTS idx_device_proc_session ON device_processes(session_id);
                CREATE INDEX IF NOT EXISTS idx_device_ports_session ON device_open_ports(session_id);
                CREATE INDEX IF NOT EXISTS idx_device_sw_session ON device_software_inventory(session_id);
                CREATE INDEX IF NOT EXISTS idx_device_startup_session ON device_startup_items(session_id);
                CREATE INDEX IF NOT EXISTS idx_ioc_cache_lookup ON ioc_lookup_cache(ioc_value, ioc_type, source);
                """
            )
            ioc_cols = {row["name"] for row in conn.execute("PRAGMA table_info(ioc_lookup_cache)").fetchall()}
            for column, sql in {
                "is_flagged": "ALTER TABLE ioc_lookup_cache ADD COLUMN is_flagged INTEGER NOT NULL DEFAULT 0",
                "verdict": "ALTER TABLE ioc_lookup_cache ADD COLUMN verdict TEXT DEFAULT 'clean'",
                "score": "ALTER TABLE ioc_lookup_cache ADD COLUMN score INTEGER",
            }.items():
                if column not in ioc_cols:
                    conn.execute(sql)
            conn.commit()

    def seed_demo_assets(self) -> None:
        with self._conn() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM assets WHERE active=1").fetchone()
            if row and int(row["count"]) > 0:
                return
            for asset in DEMO_ASSETS:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO assets(label, type, value, active, updated_at)
                    VALUES(?,?,?,?,?)
                    """,
                    (asset["label"], asset["type"], asset["value"], 1, utc_now_iso()),
                )
            conn.commit()

    async def upsert_setting(self, key: str, value: Dict[str, Any]) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO settings(key, value_json, updated_at)
                VALUES(?,?,?)
                ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at
                """,
                (key, json.dumps(value, ensure_ascii=True), utc_now_iso()),
            )
            conn.commit()

    def get_setting(self, key: str, default: Dict[str, Any]) -> Dict[str, Any]:
        with self._conn() as conn:
            row = conn.execute("SELECT value_json FROM settings WHERE key=?", (key,)).fetchone()
        return _json_loads(row["value_json"], default) if row else default

    async def probe_live_feeds(self) -> Dict[str, Any]:
        feed_specs = {
            "otx": ("AlienVault OTX", "GET", "https://otx.alienvault.com/api/v1/user/me", None),
            "abuseipdb": ("AbuseIPDB", "GET", "https://api.abuseipdb.com/api/v2/check", {"ipAddress": "1.1.1.1", "maxAgeInDays": 90}),
            "virustotal": ("VirusTotal", "GET", "https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1", None),
            "urlscan": ("URLScan.io", "GET", "https://urlscan.io/api/v1/search/", {"q": "domain:google.com", "size": 1}),
        }
        results = []
        for key, (name, method, url, params) in feed_specs.items():
            key_present = self.feed_client.key_status()["vt" if key == "virustotal" else key]
            if not key_present:
                result = {
                    "name": key,
                    "display_name": name,
                    "reachable": False,
                    "auth_valid": False,
                    "latency_ms": None,
                    "http_status": None,
                    "warning": "API key missing",
                    "degraded": True,
                }
            else:
                resp = await self.feed_client.request(key, method, url, params=params)
                warning = None
                degraded = False
                if key == "urlscan" and resp.get("http_status") == 403:
                    warning = "API key invalid or restricted"
                    degraded = True
                http_status = resp.get("http_status")
                warning = warning or resp.get("error")
                if http_status == 429:
                    warning = "Rate limited (HTTP 429) — cached results used where available"
                    degraded = True
                result = {
                    "name": key,
                    "display_name": name,
                    "reachable": bool(resp.get("reachable")),
                    "auth_valid": bool(resp.get("auth_valid")) if resp.get("auth_valid") is not None else False,
                    "latency_ms": resp.get("latency_ms"),
                    "http_status": http_status,
                    "warning": warning,
                    "degraded": degraded or not bool(resp.get("ok")),
                }
            results.append(result)
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO feed_status(name, reachable, auth_valid, latency_ms, http_status, warning, last_checked)
                    VALUES(?,?,?,?,?,?,?)
                    ON CONFLICT(name) DO UPDATE SET
                        reachable=excluded.reachable,
                        auth_valid=excluded.auth_valid,
                        latency_ms=excluded.latency_ms,
                        http_status=excluded.http_status,
                        warning=excluded.warning,
                        last_checked=excluded.last_checked
                    """,
                    (
                        key,
                        int(bool(result["reachable"])),
                        int(bool(result["auth_valid"])),
                        result["latency_ms"],
                        result["http_status"],
                        result["warning"],
                        utc_now_iso(),
                    ),
                )
                conn.commit()
            await self.ws_hub.broadcast({"type": "feed_status", "data": {"feeds": self.get_feed_status(), "summary": self.feed_summary()}})
        return {"feeds": results, "summary": self.feed_summary()}

    def normalize_feed_record(self, row: Dict[str, Any]) -> Dict[str, Any]:
        name = row.get("name") or ""
        keys = self.feed_client.key_status()
        configured = bool(keys.get("vt" if name == "virustotal" else name, False))
        reachable = bool(row.get("reachable"))
        auth_valid = bool(row.get("auth_valid"))
        http_status = row.get("http_status")
        warning = row.get("warning") or row.get("error")
        if http_status == 429:
            status_label = "rate_limited"
        elif not configured:
            status_label = "not_configured"
        elif auth_valid:
            status_label = "live"
        elif reachable:
            status_label = "auth_fail"
        else:
            status_label = "offline"
        return {
            "name": name,
            "display_name": {
                "otx": "AlienVault OTX",
                "abuseipdb": "AbuseIPDB",
                "virustotal": "VirusTotal",
                "urlscan": "URLScan.io",
            }.get(name, name),
            "configured": configured,
            "reachable": reachable,
            "auth_valid": auth_valid,
            "authValid": auth_valid,
            "latency_ms": row.get("latency_ms"),
            "latency": row.get("latency_ms"),
            "http_status": http_status,
            "httpStatus": http_status,
            "warning": warning,
            "last_checked": row.get("last_checked"),
            "lastChecked": row.get("last_checked"),
            "status": status_label,
            "degraded": row.get("degraded", False),
        }

    def get_feed_status(self) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM feed_status ORDER BY name ASC").fetchall()
        if not rows:
            keys = self.feed_client.key_status()
            return [
                self.normalize_feed_record(
                    {
                        "name": name,
                        "reachable": False,
                        "auth_valid": False,
                        "latency_ms": None,
                        "http_status": None,
                        "warning": "Not probed yet",
                    }
                )
                for name in ("otx", "abuseipdb", "virustotal", "urlscan")
            ]
        return [self.normalize_feed_record(dict(row)) for row in rows]

    def feed_summary(self) -> Dict[str, int]:
        feeds = self.get_feed_status()
        return {
            "total": len(feeds),
            "reachable": sum(1 for feed in feeds if feed["reachable"]),
            "auth_valid": sum(1 for feed in feeds if feed["auth_valid"]),
            "configured": sum(1 for value in self.feed_client.key_status().values() if value),
        }

    def list_assets(self) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT
                    a.*,
                    (
                        SELECT risk_score
                        FROM risk_snapshots rs
                        WHERE rs.asset_id = a.id
                        ORDER BY rs.scanned_at DESC
                        LIMIT 1
                    ) AS previous_risk_score
                FROM assets a
                WHERE active = 1
                ORDER BY a.created_at DESC
                """
            ).fetchall()
        assets = []
        for row in rows:
            current = row["risk_score"]
            previous = row["previous_risk_score"]
            trend = "stable"
            if current is not None and previous is not None:
                if current > previous:
                    trend = "up"
                elif current < previous:
                    trend = "down"
            assets.append(
                {
                    "id": row["id"],
                    "label": row["label"],
                    "name": row["label"],
                    "type": row["type"],
                    "value": row["value"],
                    "risk_score": current,
                    "last_scanned": row["last_scanned"],
                    "last_risk_score": current,
                    "last_risk_level": _risk_level(current).title() if current is not None else None,
                    "risk_level": _risk_level(current),
                    "trend": trend,
                    "raw_data_json": _json_loads(row["raw_data_json"], {}),
                }
            )
        return assets

    def add_asset(self, label: str, asset_type: str, value: str) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO assets(label, type, value, active, updated_at)
                VALUES(?,?,?,?,?)
                ON CONFLICT(value) DO UPDATE SET label=excluded.label, type=excluded.type, active=1, updated_at=excluded.updated_at
                """,
                (label, asset_type, value, 1, utc_now_iso()),
            )
            conn.commit()
            return int(cur.lastrowid or conn.execute("SELECT id FROM assets WHERE value=?", (value,)).fetchone()[0])

    def delete_asset(self, asset_id: int) -> None:
        with self._conn() as conn:
            conn.execute("UPDATE assets SET active=0, updated_at=? WHERE id=?", (utc_now_iso(), asset_id))
            conn.commit()

    def get_asset(self, asset_id: int) -> Optional[Dict[str, Any]]:
        for asset in self.list_assets():
            if asset["id"] == asset_id:
                return asset
        return None

    def asset_history(self, asset_id: int, limit: int = 30) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT asset_id, risk_score, raw_data_json, scanned_at
                FROM risk_snapshots
                WHERE asset_id=?
                ORDER BY scanned_at DESC
                LIMIT ?
                """,
                (asset_id, limit),
            ).fetchall()
        return [dict(row) | {"raw_data_json": _json_loads(row["raw_data_json"], {})} for row in rows]

    async def scan_asset(self, asset: Dict[str, Any]) -> Dict[str, Any]:
        raw: Dict[str, Any] = {"asset": {"id": asset["id"], "label": asset["label"], "type": asset["type"], "value": asset["value"]}, "feeds": {}, "scanned_at": utc_now_iso()}
        score = 0.0
        summary_bits = []
        if asset["type"] == "ip":
            abuse = await self.feed_client.request(
                "abuseipdb",
                "GET",
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": asset["value"], "maxAgeInDays": 90},
            )
            abuse_data = abuse.get("data", {}).get("data", {}) if abuse.get("ok") else {}
            raw["feeds"]["abuseipdb"] = abuse_data or {"status": abuse.get("http_status"), "error": abuse.get("error")}
            abuse_score = float(abuse_data.get("abuseConfidenceScore", 0) or 0)
            summary_bits.append(f"AbuseIPDB {int(abuse_score)}")
            otx = await self.feed_client.request(
                "otx",
                "GET",
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{asset['value']}/general",
            )
            otx_data = otx.get("data", {}) if otx.get("ok") else {}
            raw["feeds"]["otx"] = otx_data or {"status": otx.get("http_status"), "error": otx.get("error")}
            pulse_count = float(otx_data.get("pulse_info", {}).get("count", 0) or 0)
            score = min(abuse_score * 0.6 + pulse_count * 4, 100.0)
            summary_bits.append(f"OTX pulses {int(pulse_count)}")
        elif asset["type"] == "domain":
            otx = await self.feed_client.request(
                "otx",
                "GET",
                f"https://otx.alienvault.com/api/v1/indicators/domain/{asset['value']}/general",
            )
            otx_data = otx.get("data", {}) if otx.get("ok") else {}
            raw["feeds"]["otx"] = otx_data or {"status": otx.get("http_status"), "error": otx.get("error")}
            pulse_count = float(otx_data.get("pulse_info", {}).get("count", 0) or 0)
            vt = await self.feed_client.request(
                "virustotal",
                "GET",
                f"https://www.virustotal.com/api/v3/domains/{asset['value']}",
            )
            vt_data = vt.get("data", {}) if vt.get("ok") else {}
            stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) if isinstance(vt_data, dict) else {}
            vt_malicious = float(stats.get("malicious", 0) or 0)
            raw["feeds"]["virustotal"] = vt_data or {"status": vt.get("http_status"), "error": vt.get("error")}
            score = min(pulse_count * 5 + vt_malicious * 10, 100.0)
            summary_bits.append(f"OTX pulses {int(pulse_count)}")
            summary_bits.append(f"VT malicious {int(vt_malicious)}")
        else:
            score = 0.0
        severity = _risk_level(score).upper()
        with self._conn() as conn:
            conn.execute(
                """
                UPDATE assets
                SET risk_score=?, last_scanned=?, raw_data_json=?, updated_at=?
                WHERE id=?
                """,
                (score, utc_now_iso(), json.dumps(raw, ensure_ascii=True), utc_now_iso(), asset["id"]),
            )
            conn.execute(
                """
                INSERT INTO risk_snapshots(asset_id, risk_score, raw_data_json, scanned_at)
                VALUES(?,?,?,?)
                """,
                (asset["id"], score, json.dumps(raw, ensure_ascii=True), utc_now_iso()),
            )
            conn.commit()
        alert = None
        if score > 70:
            alert = await self.create_alert_for_asset(asset, score, "CRITICAL" if score > 85 else "HIGH", "risk_threshold")
        return {
            "asset_id": asset["id"],
            "risk_score": round(score, 2),
            "severity": severity,
            "summary": ", ".join(summary_bits) if summary_bits else "No provider data returned",
            "raw_data": raw,
            "alert": alert,
        }

    async def create_alert_for_asset(self, asset: Dict[str, Any], score: float, severity: str, alert_type: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            existing = conn.execute(
                """
                SELECT * FROM alerts
                WHERE asset_id=? AND alert_type=? AND created_at >= datetime('now', '-1 day') AND active=1
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (asset["id"], alert_type),
            ).fetchone()
            if existing:
                return dict(existing)
            title = f"{severity} risk detected on {asset['label']}"
            message = f"{severity.title()} risk detected on {asset['value']} (score: {round(score, 2)})"
            cur = conn.execute(
                """
                INSERT INTO alerts(asset_id, asset_value, severity, title, message, seen, active, alert_type, source, metadata_json, created_at, updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    asset["id"],
                    asset["value"],
                    severity,
                    title,
                    message,
                    0,
                    1,
                    alert_type,
                    "autopilot",
                    json.dumps({"risk_score": score, "asset_label": asset["label"]}, ensure_ascii=True),
                    utc_now_iso(),
                    utc_now_iso(),
                ),
            )
            alert_id = int(cur.lastrowid)
            conn.commit()
        alert = self.get_alert(alert_id)
        if severity == "CRITICAL":
            case_id = self.auto_create_case_for_alert(alert)
            if case_id:
                with self._conn() as conn:
                    conn.execute("UPDATE alerts SET case_id=?, updated_at=? WHERE id=?", (case_id, utc_now_iso(), alert_id))
                    conn.commit()
                alert = self.get_alert(alert_id)
        await self.ws_hub.broadcast(
            {
                "type": "new_alert",
                "alert_id": alert["id"],
                "severity": alert["severity"],
                "message": alert["message"],
                "asset": asset["label"],
            }
        )
        return alert

    def get_alert(self, alert_id: int) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not row:
            return None
        out = dict(row)
        out["seen"] = bool(out["seen"])
        out["active"] = bool(out["active"])
        out["risk_level"] = out["severity"]
        out["metadata"] = _json_loads(out["metadata_json"], {})
        return out

    def list_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [self.get_alert(int(row["id"])) for row in rows]

    def mark_alert_seen(self, alert_id: int) -> None:
        with self._conn() as conn:
            conn.execute("UPDATE alerts SET seen=1, updated_at=? WHERE id=?", (utc_now_iso(), alert_id))
            conn.commit()

    def mark_all_alerts_seen(self) -> None:
        with self._conn() as conn:
            conn.execute("UPDATE alerts SET seen=1, updated_at=?", (utc_now_iso(),))
            conn.commit()

    def unseen_alert_count(self) -> int:
        with self._conn() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM alerts WHERE seen=0 AND active=1").fetchone()
        return int(row["count"] if row else 0)

    def auto_create_case_for_alert(self, alert: Optional[Dict[str, Any]]) -> Optional[int]:
        if not alert or not self.case_store:
            return None
        existing_rows = self.case_store.list_cases(status=None, severity=None, assigned_to=None, limit=200, search=alert["asset_value"])
        for case in existing_rows:
            if case.get("status") in {"new", "triaged", "escalated", "open", "in_progress"} and alert["asset_value"] in (case.get("source_value") or case.get("title", "")):
                return int(case["id"])
        payload = {
            "source_type": "alert",
            "source_value": alert["asset_value"],
            "title": f"{alert['severity']} Risk: {alert['asset_value']}",
            "severity": alert["severity"].lower(),
            "status": "new",
            "assigned_to": "AUTO",
            "reporter": "SYSTEM",
            "findings": {"alert_id": alert["id"], "message": alert["message"], "metadata": alert.get("metadata", {})},
            "tags": ["auto-created", "autopilot"],
            "recommendations": ["Review associated asset telemetry", "Validate feed evidence and containment actions"],
            "ioc_type": "asset",
            "ioc_value": alert["asset_value"],
            "risk_score": int(alert.get("metadata", {}).get("risk_score", 0) or 0),
            "scan_result": {"alert": alert},
            "notes": alert["message"],
        }
        created = self.case_store.create_case(payload)
        if self.audit_writer:
            self.audit_writer("SYSTEM", "system", "auto_create_case", "case", str(created["id"]), {"alert_id": alert["id"]})
        return int(created["id"])

    async def run_aria_monitoring_cycle(self, *, rescan_all: bool = False) -> Dict[str, Any]:
        assets = self.list_assets()
        if not rescan_all:
            cutoff = utc_now() - timedelta(hours=6)
            assets = [
                asset
                for asset in assets
                if not asset["last_scanned"] or datetime.fromisoformat(asset["last_scanned"].replace("Z", "+00:00")) <= cutoff
            ]
        semaphore = asyncio.Semaphore(5)
        results = []

        async def _scan(asset: Dict[str, Any]) -> None:
            async with semaphore:
                try:
                    results.append(await self.scan_asset(asset))
                except Exception as exc:
                    logger.exception("Asset scan failed for %s", asset["value"])
                    results.append({"asset_id": asset["id"], "risk_score": 0, "severity": "FAILED", "summary": str(exc), "raw_data": {}, "alert": None})

        await asyncio.gather(*[_scan(asset) for asset in assets])
        high = sum(1 for result in results if result["risk_score"] > 70)
        critical = sum(1 for result in results if result["risk_score"] > 85)
        avg_score = round(sum(result["risk_score"] for result in results) / max(len(results), 1), 2) if results else 0.0
        return {"scanned": len(results), "high_risk": high, "critical": critical, "avg_score": avg_score, "results": results}

    def risk_trend(self, hours: int = 24, limit: int = 20) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT strftime('%Y-%m-%dT%H:00:00', scanned_at) AS bucket, AVG(risk_score) AS avg_score
                FROM risk_snapshots
                WHERE scanned_at >= datetime('now', ?)
                GROUP BY bucket
                ORDER BY bucket DESC
                LIMIT ?
                """,
                (f"-{hours} hours", limit),
            ).fetchall()
        ordered = list(reversed(rows))
        out = []
        for row in ordered:
            bucket = row["bucket"]
            label = bucket[11:16] if bucket else "n/a"
            out.append({"label": label, "timestamp": bucket, "score": round(float(row["avg_score"] or 0), 2)})
        return out

    def dashboard_stats(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        assets = self.list_assets()
        alerts = self.list_alerts(5)
        feed_status = self.get_feed_status()
        with self._conn() as conn:
            pipeline = conn.execute("SELECT * FROM pipeline_runs ORDER BY started_at DESC LIMIT 1").fetchone()
        last_session = self.last_intelligence_session(user_id) if user_id else None
        cases = self.case_store.list_cases(status=None, severity=None, assigned_to=None, limit=5, search=None) if self.case_store else []
        distribution = last_session.get("full_results", {}).get("assets", []) if last_session else []
        if distribution:
            aria_distribution = {
                "critical": sum(1 for item in distribution if (item.get("risk_score") or 0) > 85),
                "high": sum(1 for item in distribution if 70 < (item.get("risk_score") or 0) <= 85),
                "medium": sum(1 for item in distribution if 40 < (item.get("risk_score") or 0) <= 70),
                "low": sum(1 for item in distribution if (item.get("risk_score") or 0) <= 40),
            }
        else:
            aria_distribution = {
                "critical": sum(1 for asset in assets if (asset["risk_score"] or 0) > 85),
                "high": sum(1 for asset in assets if 70 < (asset["risk_score"] or 0) <= 85),
                "medium": sum(1 for asset in assets if 40 < (asset["risk_score"] or 0) <= 70),
                "low": sum(1 for asset in assets if (asset["risk_score"] or 0) <= 40),
            }
        last_device = self.last_device_session(user_id) if user_id else self.last_device_session()
        asset_risk = float(last_session["overall_risk_score"]) if last_session else 0.0
        device_risk = float(last_device["overall_risk_score"]) if last_device else 0.0
        device_threats = 0
        if last_device:
            device_threats = int(last_device.get("connections_flagged") or 0) + int(last_device.get("processes_flagged") or 0)
        return {
            "total_cases": len(cases),
            "critical_alerts": sum(1 for alert in self.list_alerts(500) if alert["severity"] == "CRITICAL" and not alert["seen"]),
            "assets_monitored": len(assets),
            "system_risk_score": max(asset_risk, device_risk),
            "asset_risk_score": asset_risk,
            "device_risk_score": device_risk,
            "device_threats": device_threats,
            "last_system_scan": last_session["completed_at"] if last_session else None,
            "last_device_scan": last_device["completed_at"] if last_device else None,
            "last_device_session": last_device,
            "risk_trend": self.intelligence_risk_trend(user_id, hours=24 * 7) if last_session else self.risk_trend(),
            "aria_risk_distribution": aria_distribution,
            "recent_cases": cases[:5],
            "recent_alerts": alerts[:5],
            "feed_status": feed_status,
            "pipeline_status": dict(pipeline) if pipeline else None,
            "last_intelligence_session": last_session,
        }

    def aria_stats(self) -> Dict[str, Any]:
        assets = self.list_assets()
        distribution = {
            "critical": sum(1 for asset in assets if (asset["risk_score"] or 0) > 85),
            "high": sum(1 for asset in assets if 70 < (asset["risk_score"] or 0) <= 85),
            "medium": sum(1 for asset in assets if 40 < (asset["risk_score"] or 0) <= 70),
            "low": sum(1 for asset in assets if (asset["risk_score"] or 0) <= 40),
        }
        last_scan = max((asset["last_scanned"] for asset in assets if asset["last_scanned"]), default=None)
        avg = round(sum((asset["risk_score"] or 0) for asset in assets) / max(len(assets), 1), 2) if assets else 0.0
        return {
            "total": len(assets),
            "assets_monitored": len(assets),
            "unseen_alerts": self.unseen_alert_count(),
            "risk_distribution": distribution,
            "avg_risk_score": avg,
            "last_scan_time": last_scan,
            "critical": distribution["critical"],
            "high": distribution["high"],
            "medium": distribution["medium"],
            "low": distribution["low"],
            "clean": 0,
            "unknown": sum(1 for asset in assets if asset["risk_score"] is None),
        }

    def report_payload(self) -> Dict[str, Any]:
        assets = self.list_assets()
        alerts = self.list_alerts(200)
        cases = self.case_store.list_cases(status=None, severity=None, assigned_to=None, limit=200, search=None) if self.case_store else []
        with self._conn() as conn:
            sessions = conn.execute("SELECT * FROM intelligence_sessions ORDER BY triggered_at DESC LIMIT 2").fetchall()
        top_assets = sorted(assets, key=lambda item: item["risk_score"] or 0, reverse=True)[:5]
        highest = top_assets[0] if top_assets else None
        summary = {
            "asset_count": len(assets),
            "avg_risk_score": round(sum((asset["risk_score"] or 0) for asset in assets) / max(len(assets), 1), 2) if assets else 0,
            "highest_risk_asset": highest["label"] if highest else None,
            "highest_risk_score": highest["risk_score"] if highest else None,
        }
        report = {
            "summary": summary,
            "risk_trend": self.risk_trend(hours=24 * 7, limit=20),
            "top_assets": top_assets,
            "alerts": {
                "critical": sum(1 for alert in alerts if alert["severity"] == "CRITICAL"),
                "high": sum(1 for alert in alerts if alert["severity"] == "HIGH"),
                "medium": sum(1 for alert in alerts if alert["severity"] == "MEDIUM"),
                "low": sum(1 for alert in alerts if alert["severity"] == "LOW"),
                "total": len(alerts),
            },
            "cases": {
                "total": len(cases),
                "open": sum(1 for case in cases if case.get("status") in {"new", "triaged", "escalated", "open", "in_progress"}),
            },
            "iocs": self.ioc_summary(),
            "feed_health": self.get_feed_status(),
            "unified_intelligence_summary": self._report_intelligence_summary(sessions),
            "device_posture": self._report_device_posture(),
            "recommendations": self.build_recommendations(),
        }
        return report

    def _report_device_posture(self) -> Dict[str, Any]:
        session = self.last_device_session()
        if not session:
            return {"available": False}
        with self._conn() as conn:
            prev = conn.execute(
                """
                SELECT overall_risk_score FROM device_scan_sessions
                WHERE status='complete' AND id != ?
                ORDER BY triggered_at DESC LIMIT 1
                """,
                (session["id"],),
            ).fetchone()
        score = int(session.get("overall_risk_score") or 0)
        prev_score = int(prev["overall_risk_score"]) if prev else None
        delta = score - prev_score if prev_score is not None else None
        top_conn = None
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT process_name, remote_ip, threat_type FROM device_network_connections
                WHERE session_id=? AND is_flagged=1 ORDER BY id LIMIT 1
                """,
                (session["id"],),
            ).fetchone()
            if row:
                top_conn = {"process": row["process_name"], "ip": row["remote_ip"], "threat": row["threat_type"]}
        verdict = "SECURE" if score < 30 else "AT RISK" if score < 70 else "COMPROMISED"
        return {
            "available": True,
            "device_risk_score": score,
            "previous_risk_score": prev_score,
            "delta": delta,
            "connections_total": session.get("connections_found"),
            "connections_flagged": session.get("connections_flagged"),
            "processes_total": session.get("processes_found"),
            "processes_flagged": session.get("processes_flagged"),
            "ports_open": session.get("ports_open"),
            "ports_suspicious": session.get("ports_suspicious"),
            "startup_items": session.get("startup_items"),
            "startup_flagged": session.get("startup_flagged"),
            "top_flagged_connection": top_conn,
            "verdict": verdict,
        }

    def _report_intelligence_summary(self, sessions: List[sqlite3.Row]) -> Dict[str, Any]:
        if not sessions:
            return {"latest": None, "delta": None, "trend": []}
        latest = dict(sessions[0]) | {
            "full_results": _json_loads(sessions[0]["full_results"], {}),
            "correlation_map": _json_loads(sessions[0]["correlation_map"], {}),
        }
        previous = dict(sessions[1]) | {"full_results": _json_loads(sessions[1]["full_results"], {})} if len(sessions) > 1 else None
        delta = None
        if previous:
            delta = round(float(latest.get("overall_risk_score", 0) or 0) - float(previous.get("overall_risk_score", 0) or 0), 2)
        return {
            "latest": latest,
            "delta": delta,
            "trend": self.intelligence_risk_trend(hours=24),
            "top_threats": [item for item in (latest.get("full_results", {}).get("assets", [])) if (item.get("risk_score") or 0) > 55][:5],
            "ioc_correlation_summary": latest.get("correlation_map", {}),
        }

    def build_recommendations(self) -> List[str]:
        recs = []
        feed_rows = self.get_feed_status()
        if any(feed["name"] == "urlscan" and not feed["auth_valid"] for feed in feed_rows):
            recs.append("Fix URLScan.io API key to enable website automation.")
        if len(self.list_assets()) < 5:
            recs.append("Register additional production assets to broaden monitoring coverage.")
        if self.unseen_alert_count():
            recs.append("Review unseen alerts and confirm whether new cases require escalation.")
        return recs or ["Continue scheduled monitoring and review the next automated pipeline run."]

    async def generate_daily_report(self) -> Dict[str, Any]:
        payload = self.report_payload()
        title = f"Daily Threat Briefing - {utc_now().strftime('%d %b %Y')}"
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO reports(title, content, generated_at) VALUES(?,?,?)",
                (title, json.dumps(payload, ensure_ascii=True), utc_now_iso()),
            )
            conn.commit()
            report_id = int(cur.lastrowid)
        return {"report_id": report_id, "title": title, "content": payload}

    def list_reports(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute("SELECT id, title, generated_at FROM reports ORDER BY generated_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def get_report(self, report_id: int) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if not row:
            return None
        return {"id": row["id"], "title": row["title"], "generated_at": row["generated_at"], "content": _json_loads(row["content"], {})}

    def extract_iocs(self, text: str) -> List[Dict[str, str]]:
        found: list[dict[str, str]] = []
        seen = set()
        for ioc_type, pattern in IOC_PATTERNS.items():
            for match in pattern.findall(text or ""):
                value = match.strip(".,);]}>\"'")
                if ioc_type == "url":
                    found.append({"type": "url", "value": value})
                    host_match = re.sub(r"^https?://", "", value).split("/")[0].lower()
                    if host_match and host_match not in seen:
                        seen.add(host_match)
                        found.append({"type": "domain", "value": host_match})
                    continue
                key = f"{ioc_type}:{value.lower()}"
                if key in seen:
                    continue
                seen.add(key)
                found.append({"type": ioc_type, "value": value.lower() if ioc_type in {"domain", "hash"} else value})
        return found

    async def upsert_ioc(self, ioc_type: str, value: str, source: str, confidence: float, tags: List[str], metadata: Dict[str, Any]) -> int:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO iocs(type, value, source, confidence, tags_json, metadata_json, updated_at)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(value) DO UPDATE SET
                    type=excluded.type,
                    source=excluded.source,
                    confidence=excluded.confidence,
                    tags_json=excluded.tags_json,
                    metadata_json=excluded.metadata_json,
                    updated_at=excluded.updated_at
                """,
                (ioc_type, value, source, confidence, json.dumps(tags, ensure_ascii=True), json.dumps(metadata, ensure_ascii=True), utc_now_iso()),
            )
            conn.commit()
            row = conn.execute("SELECT id FROM iocs WHERE value=?", (value,)).fetchone()
            return int(row["id"])

    async def analyze_text(self, text: str, source: str = "manual") -> Dict[str, Any]:
        extracted = self.extract_iocs(text)
        enriched = []
        risk_hits = 0
        for ioc in extracted:
            score = 0.0
            evidence = {}
            if ioc["type"] == "ip":
                abuse = await self.feed_client.request("abuseipdb", "GET", "https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ioc["value"], "maxAgeInDays": 90})
                abuse_data = abuse.get("data", {}).get("data", {}) if abuse.get("ok") else {}
                otx = await self.feed_client.request("otx", "GET", f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc['value']}/general")
                otx_data = otx.get("data", {}) if otx.get("ok") else {}
                score = min(float(abuse_data.get("abuseConfidenceScore", 0) or 0) * 0.6 + float(otx_data.get("pulse_info", {}).get("count", 0) or 0) * 4, 100.0)
                evidence = {"abuseipdb": abuse_data, "otx": otx_data}
            elif ioc["type"] == "domain":
                otx = await self.feed_client.request("otx", "GET", f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc['value']}/general")
                vt = await self.feed_client.request("virustotal", "GET", f"https://www.virustotal.com/api/v3/domains/{ioc['value']}")
                otx_data = otx.get("data", {}) if otx.get("ok") else {}
                vt_stats = vt.get("data", {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) if vt.get("ok") else {}
                score = min(float(otx_data.get("pulse_info", {}).get("count", 0) or 0) * 5 + float(vt_stats.get("malicious", 0) or 0) * 10, 100.0)
                evidence = {"otx": otx_data, "virustotal": vt_stats}
            confidence = round(score, 2)
            ioc_id = await self.upsert_ioc(ioc["type"], ioc["value"], source, confidence, [source], evidence)
            enriched_item = {"id": ioc_id, "type": ioc["type"], "value": ioc["value"], "risk_score": confidence, "risk_level": _risk_level(confidence), "evidence": evidence}
            if confidence > 60:
                risk_hits += 1
            enriched.append(enriched_item)
        return {"text": text, "iocs": enriched, "iocs_extracted": len(extracted), "risks_found": risk_hits}

    async def auto_scan_all_cases(self) -> Dict[str, Any]:
        if not self.case_store:
            return {"cases_scanned": 0, "iocs_extracted": 0, "risks_found": 0, "results": []}
        cases = self.case_store.list_cases(status=None, severity=None, assigned_to=None, limit=200, search=None)
        results = []
        total_iocs = 0
        total_risks = 0
        for case in cases:
            text = f"{case.get('title', '')}\n{case.get('notes', '')}\n{json.dumps(case.get('findings', {}), ensure_ascii=True)}"
            result = await self.analyze_text(text, source="case_auto_scan")
            total_iocs += result["iocs_extracted"]
            total_risks += result["risks_found"]
            results.append({"case_id": case["id"], "iocs_found": result["iocs_extracted"], "risk_level": "high" if result["risks_found"] else "low", "action_taken": "alerts created" if result["risks_found"] else "none"})
        return {"cases_scanned": len(cases), "iocs_extracted": total_iocs, "risks_found": total_risks, "results": results}

    async def auto_pull_iocs(self) -> Dict[str, Any]:
        pulled = []
        otx = await self.feed_client.request("otx", "GET", "https://otx.alienvault.com/api/v1/pulses/subscribed", params={"limit": 20, "modified_since": (utc_now() - timedelta(days=1)).isoformat()})
        for pulse in otx.get("data", {}).get("results", []) if otx.get("ok") else []:
            for indicator in pulse.get("indicators", []) or []:
                indicator_type = (indicator.get("type") or "").lower()
                value = indicator.get("indicator")
                if not value:
                    continue
                normalized = "domain" if "domain" in indicator_type else "ip" if "ip" in indicator_type else "url" if "url" in indicator_type else "hash" if "filehash" in indicator_type or "hash" in indicator_type else None
                if not normalized:
                    continue
                pulled.append({"type": normalized, "value": value, "source": "otx", "confidence": 80, "tags": pulse.get("tags", [])[:10]})
        abuse = await self.feed_client.request("abuseipdb", "GET", "https://api.abuseipdb.com/api/v2/blacklist", params={"limit": 1000, "confidenceMinimum": 75})
        for row in abuse.get("data", {}).get("data", []) if abuse.get("ok") else []:
            pulled.append({"type": "ip", "value": row.get("ipAddress"), "source": "abuseipdb", "confidence": float(row.get("abuseConfidenceScore", 75) or 75), "tags": ["blacklist"]})
        new_count = 0
        matches = 0
        assets_by_value = {asset["value"]: asset for asset in self.list_assets()}
        for item in pulled:
            if not item["value"]:
                continue
            with self._conn() as conn:
                before = conn.execute("SELECT id FROM iocs WHERE value=?", (item["value"],)).fetchone()
            await self.upsert_ioc(item["type"], item["value"], item["source"], item["confidence"], item["tags"], {})
            if before is None:
                new_count += 1
            if item["value"] in assets_by_value:
                matches += 1
                await self.create_alert_for_asset(assets_by_value[item["value"]], float(item["confidence"]), "HIGH" if item["confidence"] < 85 else "CRITICAL", "ioc_match")
        return {"iocs_pulled": len(pulled), "new_iocs": new_count, "asset_matches": matches}

    def list_iocs(self, *, page: int = 1, limit: int = 50, ioc_type: Optional[str] = None, source: Optional[str] = None, min_confidence: float = 0, search: Optional[str] = None) -> Dict[str, Any]:
        clauses = ["confidence >= ?"]
        params: list[Any] = [min_confidence]
        if ioc_type:
            clauses.append("type = ?")
            params.append(ioc_type)
        if source:
            clauses.append("source = ?")
            params.append(source)
        if search:
            clauses.append("value LIKE ?")
            params.append(f"%{search}%")
        where = " WHERE " + " AND ".join(clauses)
        offset = max(page - 1, 0) * limit
        with self._conn() as conn:
            rows = conn.execute(f"SELECT * FROM iocs{where} ORDER BY updated_at DESC LIMIT ? OFFSET ?", params + [limit, offset]).fetchall()
            total = conn.execute(f"SELECT COUNT(*) AS count FROM iocs{where}", params).fetchone()["count"]
        results = []
        for row in rows:
            record = dict(row)
            record["tags"] = _json_loads(record["tags_json"], [])
            record["metadata"] = _json_loads(record["metadata_json"], {})
            results.append(record)
        return {"page": page, "limit": limit, "total": total, "results": results}

    def ioc_summary(self) -> Dict[str, Any]:
        with self._conn() as conn:
            rows = conn.execute("SELECT type, source, confidence FROM iocs").fetchall()
        by_type: Dict[str, int] = {}
        by_source: Dict[str, int] = {}
        high_conf = 0
        for row in rows:
            by_type[row["type"]] = by_type.get(row["type"], 0) + 1
            by_source[row["source"]] = by_source.get(row["source"], 0) + 1
            if float(row["confidence"] or 0) >= 75:
                high_conf += 1
        return {"total": len(rows), "by_type": by_type, "by_source": by_source, "high_confidence": high_conf}

    def detect_target_type(self, target: str) -> str:
        value = (target or "").strip()
        if not value:
            return "text"
        if IOC_PATTERNS["ip"].fullmatch(value):
            return "ip"
        if IOC_PATTERNS["hash"].fullmatch(value):
            return "hash"
        if value.startswith(("http://", "https://")):
            return "domain"
        if IOC_PATTERNS["domain"].fullmatch(value.lower()):
            return "domain"
        return "text"

    def _collect_existing_ioc_matches(self, values: List[str]) -> List[Dict[str, Any]]:
        if not values:
            return []
        placeholders = ",".join("?" for _ in values)
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM iocs WHERE value IN ({placeholders}) ORDER BY confidence DESC",
                values,
            ).fetchall()
        return [
            {
                "id": row["id"],
                "type": row["type"],
                "value": row["value"],
                "source": row["source"],
                "confidence": row["confidence"],
            }
            for row in rows
        ]

    async def unified_scan(
        self,
        target: str,
        target_type: str = "auto",
        *,
        context: Optional[str] = None,
        user_id: Optional[str] = None,
        engines: Optional[Dict[str, bool]] = None,
    ) -> Dict[str, Any]:
        target = (target or "").strip()
        if not target:
            raise ValueError("target is required")
        resolved_type = self.detect_target_type(target) if target_type == "auto" else target_type
        engines = engines or {
            "threatIntel": True,
            "websiteScan": True,
            "hashLookup": True,
            "iocMatch": True,
            "aiAnalysis": True,
        }

        async def run_ai() -> Dict[str, Any]:
            if not engines.get("aiAnalysis", True) or not self.risk_engine:
                return {"enabled": False, "summary": None}
            if resolved_type == "text":
                result = await self.risk_engine.analyze_async(target if not context else f"{target}\n{context}")
                return {"enabled": True, "summary": result.get("summary"), "result": result, "score": result.get("score", 0)}
            if context:
                result = await self.risk_engine.analyze_async(context)
                return {"enabled": True, "summary": result.get("summary"), "result": result, "score": result.get("score", 0)}
            return {"enabled": True, "summary": None, "result": {}, "score": 0}

        async def run_threat_intel() -> Dict[str, Any]:
            if not engines.get("threatIntel", True) or not self.threat_intel_engine:
                return {"enabled": False, "results": []}
            kwargs: Dict[str, Any] = {"live_feeds": True}
            if resolved_type == "ip":
                kwargs["ips"] = [target]
            elif resolved_type == "domain":
                kwargs["domains"] = [target.replace("https://", "").replace("http://", "").split("/")[0]]
            elif resolved_type == "hash":
                kwargs["hashes"] = [target.lower()]
            else:
                kwargs["text"] = f"{target}\n{context or ''}".strip()
            result = await self.threat_intel_engine.scan_async(**kwargs)
            return {"enabled": True, "result": result}

        async def run_website() -> Dict[str, Any]:
            if not engines.get("websiteScan", True):
                return {"enabled": False}
            if resolved_type not in {"domain"}:
                return {"enabled": False}
            website_target = target if target.startswith(("http://", "https://")) else f"https://{target}"
            if self.website_scan_builder:
                try:
                    result = await asyncio.to_thread(self.website_scan_builder, website_target)
                    return {"enabled": True, "result": result}
                except Exception as exc:
                    return {"enabled": True, "error": str(exc)}
            domain = website_target.replace("https://", "").replace("http://", "").split("/")[0]
            result = await self.feed_client.request("urlscan", "GET", "https://urlscan.io/api/v1/search/", params={"q": f"domain:{domain}", "size": 3})
            return {"enabled": True, "result": result.get("data", {}), "error": result.get("error")}

        async def run_hash_lookup() -> Dict[str, Any]:
            if not engines.get("hashLookup", True):
                return {"enabled": False}
            if resolved_type != "hash":
                return {"enabled": False}
            result = await self.feed_client.request("virustotal", "GET", f"https://www.virustotal.com/api/v3/files/{target.lower()}")
            return {"enabled": True, "result": result.get("data", {}), "error": result.get("error")}

        async def run_fusion() -> Dict[str, Any]:
            if not self.fusion_engine:
                return {"enabled": False}
            text_input = target if resolved_type == "text" else context
            url_input = target if resolved_type == "domain" else None
            if not text_input and not url_input:
                return {"enabled": False}
            try:
                result = await self.fusion_engine.fusion_scan_async(text=text_input, website_url=url_input)
                return {"enabled": True, "result": result}
            except Exception as exc:
                return {"enabled": True, "error": str(exc)}

        ai_result, ti_result, website_result, hash_result, fusion_result = await asyncio.gather(
            run_ai(),
            run_threat_intel(),
            run_website(),
            run_hash_lookup(),
            run_fusion(),
        )

        extracted = []
        if self.threat_intel_engine:
            extracted = [
                {"type": ioc.ioc_type, "value": ioc.value}
                for ioc in self.threat_intel_engine._extract_iocs(f"{target}\n{context or ''}".strip())
            ][:30]
        if resolved_type in {"ip", "domain", "hash"} and not any(item["value"] == target for item in extracted):
            extracted.insert(0, {"type": resolved_type, "value": target})
        match_values = [item["value"].lower() for item in extracted if isinstance(item.get("value"), str)]
        ioc_matches = self._collect_existing_ioc_matches(match_values) if engines.get("iocMatch", True) else []

        threat_rows = (ti_result.get("result") or {}).get("results", []) if ti_result.get("enabled") else []
        top_intel = threat_rows[0] if threat_rows else {}
        vt_file_stats = (((hash_result.get("result") or {}).get("data") or {}).get("attributes") or {}).get("last_analysis_stats", {}) if hash_result.get("enabled") else {}
        website_score = 0
        website_verdict = "unknown"
        if website_result.get("enabled"):
            if "riskScore" in (website_result.get("result") or {}):
                website_score = float(website_result["result"].get("riskScore") or 0)
                website_verdict = website_result["result"].get("verdict", "unknown")
            else:
                rows = (website_result.get("result") or {}).get("results", [])
                if rows:
                    overall = ((rows[0].get("verdicts") or {}).get("overall") or {})
                    website_score = float(overall.get("score") or 0)
                    website_verdict = "malicious" if overall.get("malicious") else "clean"

        scores = [
            float(ai_result.get("score") or 0),
            float((ti_result.get("result") or {}).get("max_ioc_score") or 0),
            float(website_score or 0),
            float((vt_file_stats.get("malicious", 0) or 0) * 8),
            float((fusion_result.get("result") or {}).get("posture_score") or 0),
        ]
        active_scores = [score for score in scores if score > 0]
        risk_score = round(sum(active_scores) / max(len(active_scores), 1), 2) if active_scores else 0.0
        verdict = "MALICIOUS" if risk_score > 80 else "SUSPICIOUS" if risk_score > 55 else "CLEAN"
        severity = "CRITICAL" if risk_score > 85 else "HIGH" if risk_score > 70 else "MEDIUM" if risk_score > 40 else "LOW"

        correlated_assets = [
            asset for asset in self.list_assets()
            if asset["value"].lower() in match_values and asset["value"].lower() != target.lower()
        ]
        correlation = {
            "existing_ioc_matches": ioc_matches,
            "monitored_asset_matches": [{"id": asset["id"], "label": asset["label"], "value": asset["value"]} for asset in correlated_assets],
            "match_count": len(ioc_matches) + len(correlated_assets),
        }

        return {
            "target": target,
            "targetType": resolved_type,
            "context": context,
            "scanned_at": utc_now_iso(),
            "risk_score": risk_score,
            "verdict": verdict,
            "severity": severity,
            "engines": engines,
            "text_analysis": ai_result,
            "threat_intel": ti_result,
            "website_scan": website_result,
            "hash_lookup": hash_result,
            "fusion": fusion_result,
            "ioc_correlation": correlation,
            "extracted_iocs": extracted,
            "summary": {
                "abuseipdb": next((feed for feed in top_intel.get("feeds", []) if feed.get("source") == "abuseipdb"), {}),
                "otx": next((feed for feed in top_intel.get("feeds", []) if feed.get("source") == "otx"), {}),
                "virustotal": next((feed for feed in top_intel.get("feeds", []) if feed.get("source") == "virustotal"), {}),
                "urlscan_verdict": website_verdict,
            },
            "errors": {
                "website_scan": website_result.get("error"),
                "hash_lookup": hash_result.get("error"),
                "fusion": fusion_result.get("error"),
            },
        }

    def _persist_intelligence_session(self, session_id: str, payload: Dict[str, Any]) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                UPDATE intelligence_sessions
                SET completed_at=?, assets_scanned=?, threats_found=?, critical_count=?,
                    overall_risk_score=?, status=?, full_results=?, correlation_map=?
                WHERE id=?
                """,
                (
                    payload.get("completed_at"),
                    payload.get("assets_scanned", 0),
                    payload.get("threats_found", 0),
                    payload.get("critical_count", 0),
                    payload.get("overall_risk_score", 0),
                    payload.get("status", "complete"),
                    json.dumps(payload.get("full_results", {}), ensure_ascii=True),
                    json.dumps(payload.get("correlation_map", {}), ensure_ascii=True),
                    session_id,
                ),
            )
            conn.commit()

    def _build_correlation_map(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        correlation: Dict[str, List[str]] = {}
        for item in results:
            asset_label = item.get("asset", {}).get("label") or item.get("target")
            for ioc in item.get("extracted_iocs", []):
                value = str(ioc.get("value", "")).lower()
                if not value:
                    continue
                correlation.setdefault(value, []).append(asset_label)
        return {
            key: sorted(set(value))
            for key, value in correlation.items()
            if len(set(value)) > 1
        }

    async def start_system_scan(self, user_id: str) -> str:
        with self._conn() as conn:
            existing = conn.execute(
                "SELECT id FROM intelligence_sessions WHERE user_id=? AND status='running' ORDER BY triggered_at DESC LIMIT 1",
                (user_id,),
            ).fetchone()
            if existing:
                return str(existing["id"])
            session_id = str(uuid.uuid4())
            conn.execute(
                """
                INSERT INTO intelligence_sessions(id, user_id, triggered_at, status, full_results, correlation_map)
                VALUES(?,?,?,?,?,?)
                """,
                (session_id, user_id, utc_now_iso(), "running", "{}", "{}"),
            )
            conn.commit()
        asyncio.create_task(self.run_system_scan(user_id, session_id))
        return session_id

    async def run_system_scan(self, user_id: str, session_id: str) -> Dict[str, Any]:
        assets = self.list_assets()
        total = len(assets)
        results: List[Dict[str, Any]] = []
        semaphore = asyncio.Semaphore(5)

        async def _scan(index: int, asset: Dict[str, Any]) -> None:
            async with semaphore:
                await self.ws_hub.broadcast(
                    {
                        "type": "system_scan_progress",
                        "session_id": session_id,
                        "user_id": user_id,
                        "progress_pct": int((index / max(total, 1)) * 100),
                        "current_asset": asset["label"],
                        "assets_scanned": len(results),
                        "total_assets": total,
                    }
                )
                result = await self.unified_scan(asset["value"], asset["type"], context=asset["label"], user_id=user_id)
                result["asset"] = {"id": asset["id"], "label": asset["label"], "type": asset["type"], "value": asset["value"]}
                results.append(result)
                if result["risk_score"] > 70:
                    await self.create_alert_for_asset(asset, result["risk_score"], "CRITICAL" if result["risk_score"] > 85 else "HIGH", "intelligence_unified")

        await asyncio.gather(*[_scan(index + 1, asset) for index, asset in enumerate(assets)])

        correlation_map = self._build_correlation_map(results)
        threats_found = sum(1 for item in results if item["risk_score"] > 55)
        critical_count = sum(1 for item in results if item["risk_score"] > 85)
        overall_risk_score = round(sum(item["risk_score"] for item in results) / max(len(results), 1), 2) if results else 0.0

        case_id = None
        if overall_risk_score > 70 and self.case_store:
            case = self.case_store.create_case(
                {
                    "source_type": "intelligence_session",
                    "source_value": session_id,
                    "title": f"Unified Intelligence Session Risk - {user_id}",
                    "severity": "critical" if overall_risk_score > 85 else "high",
                    "status": "new",
                    "assigned_to": "AUTO",
                    "reporter": "SYSTEM",
                    "findings": {"session_id": session_id, "results": results},
                    "tags": ["intelligence-session", "auto-created"],
                    "recommendations": ["Review cross-asset IOC overlap", "Prioritize correlated assets for triage"],
                    "ioc_type": "session",
                    "ioc_value": session_id,
                    "risk_score": int(overall_risk_score),
                    "scan_result": {"results": results, "correlation_map": correlation_map},
                    "notes": f"System scan across {total} assets found {threats_found} threats.",
                }
            )
            case_id = case["id"]

        payload = {
            "completed_at": utc_now_iso(),
            "assets_scanned": total,
            "threats_found": threats_found,
            "critical_count": critical_count,
            "overall_risk_score": overall_risk_score,
            "status": "complete",
            "full_results": {"assets": results, "case_id": case_id},
            "correlation_map": correlation_map,
        }
        self._persist_intelligence_session(session_id, payload)
        summary = self.get_intelligence_session(session_id)
        await self.ws_hub.broadcast(
            {
                "type": "system_scan_complete",
                "session_id": session_id,
                "user_id": user_id,
                "summary": {
                    "assets_scanned": total,
                    "threats_found": threats_found,
                    "critical_count": critical_count,
                    "overall_risk_score": overall_risk_score,
                    "case_id": case_id,
                },
            }
        )
        return summary or {}

    def get_intelligence_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM intelligence_sessions WHERE id=?", (session_id,)).fetchone()
        if not row:
            return None
        return dict(row) | {
            "full_results": _json_loads(row["full_results"], {}),
            "correlation_map": _json_loads(row["correlation_map"], {}),
        }

    def last_intelligence_session(self, user_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id FROM intelligence_sessions WHERE user_id=? ORDER BY triggered_at DESC LIMIT 1",
                (user_id,),
            ).fetchone()
        return self.get_intelligence_session(str(row["id"])) if row else None

    # ─── Device EDR scan persistence ─────────────────────────────────────────

    def device_ioc_cache_get(self, ioc_value: str, ioc_type: str, source: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT result, expires_at FROM ioc_lookup_cache
                WHERE ioc_value=? AND ioc_type=? AND source=? AND expires_at > ?
                """,
                (ioc_value, ioc_type, source, utc_now_iso()),
            ).fetchone()
        if not row:
            return None
        return _json_loads(row["result"], {})

    def device_ioc_cache_set(self, ioc_value: str, ioc_type: str, source: str, result: Dict[str, Any]) -> None:
        checked = utc_now_iso()
        expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO ioc_lookup_cache(ioc_value, ioc_type, source, result, checked_at, expires_at)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(ioc_value, ioc_type, source) DO UPDATE SET
                    result=excluded.result,
                    checked_at=excluded.checked_at,
                    expires_at=excluded.expires_at
                """,
                (ioc_value, ioc_type, source, json.dumps(result, ensure_ascii=True), checked, expires),
            )
            conn.commit()

    def device_local_ioc_exists(self, ioc_type: str, value: str) -> bool:
        with self._conn() as conn:
            row = conn.execute("SELECT 1 FROM iocs WHERE type=? AND value=? LIMIT 1", (ioc_type, value)).fetchone()
        return bool(row)

    def device_session_insert_running(self, session_id: str, user_id: str, triggered_by: str) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO device_scan_sessions(
                    id, user_id, triggered_at, status, triggered_by, full_results
                ) VALUES(?,?,?,?,?,?)
                """,
                (session_id, user_id, utc_now_iso(), "running", triggered_by, "{}"),
            )
            conn.commit()

    def device_session_update_fields(self, session_id: str, fields: Dict[str, Any]) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        vals = list(fields.values()) + [session_id]
        with self._conn() as conn:
            conn.execute(f"UPDATE device_scan_sessions SET {cols} WHERE id=?", vals)
            conn.commit()

    def device_get_full_results(self, session_id: str) -> Dict[str, Any]:
        with self._conn() as conn:
            row = conn.execute("SELECT full_results FROM device_scan_sessions WHERE id=?", (session_id,)).fetchone()
        return _json_loads(row["full_results"], {}) if row else {}

    def device_merge_full_results(self, session_id: str, patch: Dict[str, Any]) -> None:
        full = self.device_get_full_results(session_id)
        full.update(patch)
        with self._conn() as conn:
            conn.execute(
                "UPDATE device_scan_sessions SET full_results=? WHERE id=?",
                (json.dumps(full, ensure_ascii=True), session_id),
            )
            conn.commit()

    def device_session_finalize(self, session_id: str, payload: Dict[str, Any]) -> None:
        full = payload.get("full_results") or {}
        system = full.get("system") or {}
        hostname = payload.get("hostname") or system.get("hostname")
        os_platform = payload.get("os_platform") or system.get("platform")
        with self._conn() as conn:
            conn.execute(
                """
                UPDATE device_scan_sessions SET
                    completed_at=?, status=?, hostname=?, os_platform=?, overall_risk_score=?,
                    connections_found=?, connections_flagged=?,
                    processes_found=?, processes_flagged=?,
                    ports_open=?, ports_suspicious=?,
                    software_count=?, dns_entries_checked=?, dns_flagged=?,
                    startup_items=?, startup_flagged=?,
                    full_results=?
                WHERE id=?
                """,
                (
                    payload.get("completed_at"),
                    payload.get("status", "complete"),
                    hostname,
                    os_platform,
                    int(payload.get("overall_risk_score") or 0),
                    int(payload.get("connections_found") or 0),
                    int(payload.get("connections_flagged") or 0),
                    int(payload.get("processes_found") or 0),
                    int(payload.get("processes_flagged") or 0),
                    int(payload.get("ports_open") or 0),
                    int(payload.get("ports_suspicious") or 0),
                    int(payload.get("software_count") or 0),
                    int(payload.get("dns_entries_checked") or 0),
                    int(payload.get("dns_flagged") or 0),
                    int(payload.get("startup_items") or 0),
                    int(payload.get("startup_flagged") or 0),
                    json.dumps(payload.get("full_results") or {}, ensure_ascii=True),
                    session_id,
                ),
            )
            conn.commit()

    def device_session_mark_failed(self, session_id: str, error: str) -> None:
        full = self.device_get_full_results(session_id)
        full["error"] = error
        with self._conn() as conn:
            conn.execute(
                """
                UPDATE device_scan_sessions SET status='failed', completed_at=?, full_results=?
                WHERE id=?
                """,
                (utc_now_iso(), json.dumps(full, ensure_ascii=True), session_id),
            )
            conn.commit()

    def _device_row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        out = dict(row)
        out["full_results"] = _json_loads(row["full_results"], {})
        return out

    def get_device_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM device_scan_sessions WHERE id=?", (session_id,)).fetchone()
        return self._device_row_to_dict(row) if row else None

    def last_device_session(self, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            if user_id:
                row = conn.execute(
                    "SELECT id FROM device_scan_sessions WHERE user_id=? ORDER BY triggered_at DESC LIMIT 1",
                    (user_id,),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT id FROM device_scan_sessions ORDER BY triggered_at DESC LIMIT 1",
                ).fetchone()
        return self.get_device_session(str(row["id"])) if row else None

    def device_scan_history(self, limit: int = 30) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT id, triggered_at, completed_at, status, triggered_by, hostname,
                       connections_found, connections_flagged, processes_found, processes_flagged,
                       overall_risk_score
                FROM device_scan_sessions
                ORDER BY triggered_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            started = row["triggered_at"]
            ended = row["completed_at"]
            duration_ms = None
            if started and ended:
                try:
                    a = datetime.fromisoformat(started.replace("Z", "+00:00"))
                    b = datetime.fromisoformat(ended.replace("Z", "+00:00"))
                    duration_ms = int((b - a).total_seconds() * 1000)
                except ValueError:
                    duration_ms = None
            item["duration_ms"] = duration_ms
            out.append(item)
        return out

    def device_risk_trend(self, limit: int = 30) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT triggered_at, overall_risk_score
                FROM device_scan_sessions
                WHERE status='complete'
                ORDER BY triggered_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        ordered = list(reversed(rows))
        return [
            {
                "label": (row["triggered_at"] or "")[11:16] if row["triggered_at"] else "n/a",
                "timestamp": row["triggered_at"],
                "score": int(row["overall_risk_score"] or 0),
            }
            for row in ordered
        ]

    def device_sysinfo(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        from .device_scan_agent import get_builtin_system_info

        builtin = get_builtin_system_info()
        session = self.last_device_session(user_id)
        if not session:
            return {
                **builtin,
                "session_id": None,
                "last_scan": None,
                "risk_score": 0,
                "system": builtin,
            }
        sysinfo = (session.get("full_results") or {}).get("system") or {}
        merged = {**builtin, **{k: v for k, v in sysinfo.items() if v is not None}}
        return {
            "session_id": session["id"],
            "hostname": session.get("hostname") or merged.get("hostname") or builtin.get("hostname"),
            "os_platform": session.get("os_platform") or merged.get("platform"),
            "os_name": merged.get("os_name"),
            "os_version": merged.get("os_version"),
            "current_user": merged.get("current_user"),
            "firewall_status": merged.get("firewall_status"),
            "av_status": merged.get("av_status"),
            "uptime_seconds": merged.get("uptime_seconds"),
            "uptime_raw": merged.get("uptime_raw"),
            "ram_total_gb": merged.get("ram_total_gb"),
            "ram_free_gb": merged.get("ram_free_gb"),
            "cpu_cores": merged.get("cpu_cores"),
            "arch": merged.get("arch"),
            "network_interfaces": merged.get("network_interfaces", []),
            "last_scan": session.get("completed_at") or session.get("triggered_at"),
            "risk_score": int(session.get("overall_risk_score") or 0),
            "system": merged,
        }

    def device_insert_connections(self, session_id: str, rows: List[Dict[str, Any]]) -> None:
        with self._conn() as conn:
            conn.executemany(
                """
                INSERT INTO device_network_connections(
                    session_id, timestamp, local_ip, local_port, remote_ip, remote_port,
                    protocol, state, pid, process_name, process_path,
                    is_flagged, ioc_confidence, threat_type, threat_source, verdict
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                [
                    (
                        session_id,
                        r["timestamp"],
                        r.get("local_ip"),
                        r.get("local_port"),
                        r.get("remote_ip"),
                        r.get("remote_port"),
                        r.get("protocol"),
                        r.get("state"),
                        r.get("pid"),
                        r.get("process_name"),
                        r.get("process_path"),
                        int(bool(r.get("is_flagged"))),
                        r.get("ioc_confidence"),
                        r.get("threat_type"),
                        r.get("threat_source"),
                        r.get("verdict") or "clean",
                    )
                    for r in rows
                ],
            )
            conn.commit()

    def device_insert_processes(self, session_id: str, rows: List[Dict[str, Any]]) -> None:
        with self._conn() as conn:
            conn.executemany(
                """
                INSERT INTO device_processes(
                    session_id, timestamp, pid, name, path, cpu_percent, memory_mb,
                    sha256_hash, is_flagged, vt_positives, vt_total, suspicious_path_reason, verdict
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                [
                    (
                        session_id,
                        r["timestamp"],
                        r.get("pid"),
                        r.get("name"),
                        r.get("path"),
                        r.get("cpu_percent"),
                        r.get("memory_mb"),
                        r.get("sha256_hash"),
                        int(bool(r.get("is_flagged"))),
                        r.get("vt_positives"),
                        r.get("vt_total"),
                        r.get("suspicious_path_reason"),
                        r.get("verdict") or "clean",
                    )
                    for r in rows
                ],
            )
            conn.commit()

    def device_insert_ports(self, session_id: str, rows: List[Dict[str, Any]]) -> None:
        with self._conn() as conn:
            conn.executemany(
                """
                INSERT INTO device_open_ports(
                    session_id, port, protocol, bound_address, pid, process_name, is_flagged, flag_reason
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                [
                    (
                        session_id,
                        r.get("port"),
                        r.get("protocol"),
                        r.get("bound_address"),
                        r.get("pid"),
                        r.get("process_name"),
                        int(bool(r.get("is_flagged"))),
                        r.get("flag_reason"),
                    )
                    for r in rows
                ],
            )
            conn.commit()

    def device_insert_software(self, session_id: str, rows: List[Dict[str, Any]]) -> None:
        with self._conn() as conn:
            conn.executemany(
                """
                INSERT INTO device_software_inventory(
                    session_id, name, version, publisher, install_date, known_cves
                ) VALUES(?,?,?,?,?,?)
                """,
                [
                    (
                        session_id,
                        r.get("name"),
                        r.get("version"),
                        r.get("publisher"),
                        r.get("install_date"),
                        json.dumps(r.get("known_cves") or [], ensure_ascii=True),
                    )
                    for r in rows
                ],
            )
            conn.commit()

    def device_insert_startup(self, session_id: str, rows: List[Dict[str, Any]]) -> None:
        with self._conn() as conn:
            conn.executemany(
                """
                INSERT INTO device_startup_items(
                    session_id, name, command, type, is_flagged, flag_reason, sha256_hash, vt_positives, verdict
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                [
                    (
                        session_id,
                        r.get("name"),
                        r.get("command"),
                        r.get("type"),
                        int(bool(r.get("is_flagged"))),
                        r.get("flag_reason"),
                        r.get("sha256_hash"),
                        r.get("vt_positives"),
                        r.get("verdict") or "clean",
                    )
                    for r in rows
                ],
            )
            conn.commit()

    def _device_paginate(
        self,
        table: str,
        session_id: str,
        *,
        page: int = 1,
        limit: int = 20,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        filters = filters or {}
        where = ["session_id=?"]
        params: List[Any] = [session_id]
        if filters.get("is_flagged") is not None:
            where.append("is_flagged=?")
            params.append(1 if filters["is_flagged"] else 0)
        if filters.get("verdict"):
            where.append("verdict=?")
            params.append(filters["verdict"])
        if filters.get("process_name"):
            where.append("(process_name LIKE ? OR name LIKE ?)")
            like = f"%{filters['process_name']}%"
            params.extend([like, like])
        where_sql = " AND ".join(where)
        offset = max(0, (page - 1) * limit)
        with self._conn() as conn:
            total = conn.execute(f"SELECT COUNT(*) AS c FROM {table} WHERE {where_sql}", params).fetchone()["c"]
            rows = conn.execute(
                f"SELECT * FROM {table} WHERE {where_sql} ORDER BY id ASC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        items = [dict(row) for row in rows]
        for item in items:
            if "is_flagged" in item:
                item["is_flagged"] = bool(item["is_flagged"])
        return {"items": items, "page": page, "limit": limit, "total": int(total)}

    def device_list_connections(self, session_id: str, **kwargs: Any) -> Dict[str, Any]:
        return self._device_paginate("device_network_connections", session_id, **kwargs)

    def device_list_processes(self, session_id: str, **kwargs: Any) -> Dict[str, Any]:
        return self._device_paginate("device_processes", session_id, **kwargs)

    def device_list_ports(self, session_id: str, **kwargs: Any) -> Dict[str, Any]:
        return self._device_paginate("device_open_ports", session_id, **kwargs)

    def device_list_software(self, session_id: str, **kwargs: Any) -> Dict[str, Any]:
        return self._device_paginate("device_software_inventory", session_id, **kwargs)

    def device_list_startup(self, session_id: str, **kwargs: Any) -> Dict[str, Any]:
        return self._device_paginate("device_startup_items", session_id, **kwargs)

    async def create_device_scan_alert(
        self,
        severity: str,
        title: str,
        message: str,
        asset_label: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO alerts(asset_id, asset_value, severity, title, message, seen, active, alert_type, source, metadata_json, created_at, updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    None,
                    asset_label,
                    severity,
                    title,
                    message,
                    0,
                    1,
                    "device_scan",
                    "device_scan",
                    json.dumps(metadata or {}, ensure_ascii=True),
                    utc_now_iso(),
                    utc_now_iso(),
                ),
            )
            alert_id = int(cur.lastrowid)
            conn.commit()
        alert = self.get_alert(alert_id)
        if severity == "CRITICAL":
            case_id = self.auto_create_case_for_alert(alert)
            if case_id:
                with self._conn() as conn:
                    conn.execute("UPDATE alerts SET case_id=?, updated_at=? WHERE id=?", (case_id, utc_now_iso(), alert_id))
                    conn.commit()
                alert = self.get_alert(alert_id)
        await self.ws_hub.broadcast(
            {
                "type": "new_alert",
                "alert_id": alert["id"],
                "severity": alert["severity"],
                "message": alert["message"],
                "asset": asset_label,
            }
        )
        return alert

    async def device_scan_create_alerts_and_case(
        self,
        session_id: str,
        risk: int,
        net: Any,
        proc: Any,
        st: Any,
    ) -> None:
        with self._conn() as conn:
            conns = conn.execute(
                "SELECT * FROM device_network_connections WHERE session_id=? AND verdict='malicious' LIMIT 20",
                (session_id,),
            ).fetchall()
            procs = conn.execute(
                "SELECT * FROM device_processes WHERE session_id=? AND verdict='malicious' LIMIT 20",
                (session_id,),
            ).fetchall()
            startups = conn.execute(
                "SELECT * FROM device_startup_items WHERE session_id=? AND verdict IN ('suspicious','malicious') LIMIT 20",
                (session_id,),
            ).fetchall()
        for row in conns:
            await self.create_device_scan_alert(
                "CRITICAL",
                f"Malicious connection: {row['process_name']} → {row['remote_ip']}",
                (
                    f"{row['process_name']} (PID {row['pid']}) is connected to {row['remote_ip']}:{row['remote_port']}. "
                    f"AbuseIPDB confidence: {row['ioc_confidence'] or 0}%. Threat: {row['threat_type'] or 'unknown'}"
                ),
                str(row["process_name"] or row["remote_ip"] or "host"),
                {"session_id": session_id, "remote_ip": row["remote_ip"]},
            )
        for row in procs:
            await self.create_device_scan_alert(
                "HIGH",
                f"Malicious process detected: {row['name']}",
                (
                    f"{row['name']} at {row['path']} — VirusTotal: "
                    f"{row['vt_positives'] or 0}/{row['vt_total'] or 87} engines flagged"
                ),
                str(row["name"] or "process"),
                {"session_id": session_id, "pid": row["pid"]},
            )
        for row in startups:
            await self.create_device_scan_alert(
                "MEDIUM",
                f"Suspicious startup: {row['name']}",
                f'Startup item "{row["name"]}" runs from: {row["command"]}. Reason: {row["flag_reason"] or "unusual path"}',
                str(row["name"] or "startup"),
                {"session_id": session_id},
            )
        if risk > 60 and self.case_store:
            session = self.get_device_session(session_id) or {}
            self.case_store.create_case(
                {
                    "source_type": "device_scan",
                    "source_value": session_id,
                    "title": f"Device Scan High Risk - {session.get('hostname') or 'host'}",
                    "severity": "critical" if risk > 85 else "high",
                    "status": "new",
                    "assigned_to": "AUTO",
                    "reporter": "SYSTEM",
                    "findings": {"session_id": session_id, "risk_score": risk},
                    "tags": ["device-scan", "auto-created"],
                    "recommendations": ["Review flagged connections and processes", "Isolate host if compromise confirmed"],
                    "ioc_type": "session",
                    "ioc_value": session_id,
                    "risk_score": risk,
                    "scan_result": session.get("full_results") or {},
                    "notes": f"Automated device scan risk score {risk}/100.",
                }
            )

    async def start_device_scan(self, user_id: str, triggered_by: str = "manual") -> str:
        with self._conn() as conn:
            existing = conn.execute(
                "SELECT id FROM device_scan_sessions WHERE user_id=? AND status='running' ORDER BY triggered_at DESC LIMIT 1",
                (user_id,),
            ).fetchone()
            if existing:
                return str(existing["id"])
        session_id = str(uuid.uuid4())
        self.device_session_insert_running(session_id, user_id, triggered_by)
        from .device_scan_agent import run_device_scan_async

        asyncio.create_task(run_device_scan_async(self, user_id, session_id, triggered_by))
        return session_id

    def intelligence_risk_trend(self, user_id: Optional[str] = None, hours: int = 24) -> List[Dict[str, Any]]:
        params: List[Any] = [f"-{hours} hours"]
        sql = """
            SELECT strftime('%Y-%m-%dT%H:00:00', triggered_at) AS bucket, AVG(overall_risk_score) AS avg_score
            FROM intelligence_sessions
            WHERE triggered_at >= datetime('now', ?)
        """
        if user_id:
            sql += " AND user_id = ?"
            params.append(user_id)
        sql += " GROUP BY bucket ORDER BY bucket ASC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [{"label": row["bucket"][11:16] if row["bucket"] else "n/a", "timestamp": row["bucket"], "score": round(float(row["avg_score"] or 0), 2)} for row in rows]

    async def auto_scan_domains(self) -> Dict[str, Any]:
        domains = [asset for asset in self.list_assets() if asset["type"] == "domain"]
        malicious_found = 0
        stored = []
        for asset in domains:
            start = await self.feed_client.request("urlscan", "POST", "https://urlscan.io/api/v1/scan/", json_body={"url": f"https://{asset['value']}", "visibility": "private"})
            result_uuid = start.get("data", {}).get("uuid") if start.get("ok") else None
            result_payload = {}
            if result_uuid:
                await asyncio.sleep(2)
                result = await self.feed_client.request("urlscan", "GET", f"https://urlscan.io/api/v1/result/{result_uuid}/")
                result_payload = result.get("data", {}) if result.get("ok") else {}
            verdict = (
                (result_payload.get("verdicts") or {}).get("overall", {}).get("malicious")
                if isinstance(result_payload, dict)
                else False
            )
            score = ((result_payload.get("verdicts") or {}).get("overall", {}).get("score") or 0) if isinstance(result_payload, dict) else 0
            if verdict:
                malicious_found += 1
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO website_scans(asset_id, domain, scan_uuid, score, malicious, verdict, screenshot_url, result_json, scanned_at)
                    VALUES(?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        asset["id"],
                        asset["value"],
                        result_uuid,
                        score,
                        int(bool(verdict)),
                        "malicious" if verdict else "clean",
                        ((result_payload.get("task") or {}).get("screenshotURL") if isinstance(result_payload, dict) else None),
                        json.dumps(result_payload or {"status": start.get("http_status"), "error": start.get("error")}, ensure_ascii=True),
                        utc_now_iso(),
                    ),
                )
                conn.commit()
            stored.append({"domain": asset["value"], "score": score, "malicious": bool(verdict), "verdict": "malicious" if verdict else "clean", "scan_uuid": result_uuid})
        return {"domains_scanned": len(domains), "malicious_found": malicious_found, "results": stored}

    def recent_website_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM website_scans ORDER BY scanned_at DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["result"] = _json_loads(item["result_json"], {})
            out.append(item)
        return out

    async def auto_check_hashes(self) -> Dict[str, Any]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM iocs WHERE type='hash' ORDER BY updated_at DESC").fetchall()
        malicious = 0
        checked = 0
        for row in rows:
            resp = await self.feed_client.request("virustotal", "GET", f"https://www.virustotal.com/api/v3/files/{row['value']}")
            checked += 1
            data = resp.get("data", {}) if resp.get("ok") else {}
            attrs = data.get("data", {}).get("attributes", {}) if isinstance(data, dict) else {}
            stats = attrs.get("last_analysis_stats", {})
            mal_count = int(stats.get("malicious", 0) or 0)
            susp_count = int(stats.get("suspicious", 0) or 0)
            if mal_count > 3:
                malicious += 1
            with self._conn() as conn:
                conn.execute("UPDATE iocs SET vt_result_json=?, updated_at=? WHERE id=?", (json.dumps(data, ensure_ascii=True), utc_now_iso(), row["id"]))
                conn.execute(
                    """
                    INSERT INTO file_analyses(ioc_id, hash_value, file_name, malicious_count, suspicious_count, result_json, scanned_at)
                    VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        row["id"],
                        row["value"],
                        attrs.get("meaningful_name") or attrs.get("names", [None])[0],
                        mal_count,
                        susp_count,
                        json.dumps(data or {"status": resp.get("http_status"), "error": resp.get("error")}, ensure_ascii=True),
                        utc_now_iso(),
                    ),
                )
                conn.commit()
        return {"hashes_checked": checked, "malicious": malicious, "clean": max(checked - malicious, 0)}

    def recent_files(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM file_analyses ORDER BY scanned_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) | {"result": _json_loads(row["result_json"], {})} for row in rows]

    async def auto_fusion(self) -> Dict[str, Any]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM iocs ORDER BY updated_at DESC LIMIT 50").fetchall()
        high = 0
        created_cases = 0
        results = []
        for row in rows:
            metadata = _json_loads(row["metadata_json"], {})
            text_risk = float(row["confidence"] or 0)
            feed_risk = text_risk
            web_risk = 0.0
            if row["type"] in {"domain", "url"}:
                website_matches = [scan for scan in self.recent_website_scans(50) if scan["domain"] == row["value"]]
                if website_matches:
                    web_risk = float(website_matches[0].get("score") or 0)
            fusion_score = round(text_risk * 0.4 + web_risk * 0.3 + feed_risk * 0.3, 2)
            if fusion_score > 75:
                high += 1
                fake_asset = {"id": None, "label": row["value"], "value": row["value"], "type": row["type"]}
                alert = await self.create_alert_for_asset(fake_asset, fusion_score, "HIGH", "fusion_risk")
                if alert and alert.get("case_id"):
                    created_cases += 1
            payload = {"ioc": row["value"], "text_risk": text_risk, "web_risk": web_risk, "feed_risk": feed_risk, "fusion_score": fusion_score, "metadata": metadata}
            with self._conn() as conn:
                conn.execute(
                    "INSERT INTO fusion_results(ioc_value, text_risk, web_risk, feed_risk, fusion_score, result_json, created_at) VALUES(?,?,?,?,?,?,?)",
                    (row["value"], text_risk, web_risk, feed_risk, fusion_score, json.dumps(payload, ensure_ascii=True), utc_now_iso()),
                )
                conn.commit()
            results.append(payload)
        return {"iocs_processed": len(rows), "high_fusion_risk": high, "cases_created": created_cases, "results": results}

    def sync_case_store(self) -> Dict[str, Any]:
        if not self.case_store:
            return {"open": 0, "auto_closed": 0, "avg_resolution_hours": 0}
        cases = self.case_store.list_cases(status=None, severity=None, assigned_to=None, limit=500, search=None)
        open_cases = [case for case in cases if case.get("status") in {"new", "triaged", "escalated", "open", "in_progress"}]
        closed_cases = [case for case in cases if case.get("status") == "closed"]
        avg_resolution = 0.0
        if closed_cases:
            total_hours = 0.0
            for case in closed_cases:
                created = datetime.fromisoformat(case["created_at"].replace("Z", "+00:00"))
                updated = datetime.fromisoformat(case["updated_at"].replace("Z", "+00:00"))
                total_hours += max((updated - created).total_seconds() / 3600, 0)
            avg_resolution = round(total_hours / len(closed_cases), 2)
        relinked = 0
        with self._conn() as conn:
            alert_rows = conn.execute("SELECT * FROM alerts WHERE case_id IS NULL AND active=1").fetchall()
            for alert_row in alert_rows:
                alert = self.get_alert(int(alert_row["id"]))
                case_id = self.auto_create_case_for_alert(alert)
                if case_id:
                    conn.execute("UPDATE alerts SET case_id=?, updated_at=? WHERE id=?", (case_id, utc_now_iso(), alert["id"]))
                    relinked += 1
            conn.commit()
        return {"open": len(open_cases), "auto_closed": 0, "avg_resolution_hours": avg_resolution, "relinked": relinked}

    def update_aria_stats(self) -> Dict[str, Any]:
        stats = self.aria_stats()
        payload = {
            "risk_distribution": stats["risk_distribution"],
            "avg_risk": stats["avg_risk_score"],
            "assets_scanned_last_24h": sum(1 for asset in self.list_assets() if asset["last_scanned"]),
            "monitored": stats["assets_monitored"],
            "critical": stats["critical"],
            "high": stats["high"],
        }
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO stats(key, value_json, updated_at)
                VALUES(?,?,?)
                ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at
                """,
                ("aria", json.dumps(payload, ensure_ascii=True), utc_now_iso()),
            )
            conn.commit()
        return payload

    def create_pipeline_run(self, task_name: Optional[str] = None) -> str:
        run_id = str(uuid.uuid4())
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO pipeline_runs(id, status, started_at, current_task, progress_pct)
                VALUES(?,?,?,?,?)
                """,
                (run_id, "running", utc_now_iso(), task_name, 0),
            )
            conn.commit()
        return run_id

    def record_step(self, run_id: str, result: PipelineStepResult, progress_pct: int) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO pipeline_steps(run_id, task_name, status, summary, data_json, duration_ms, error, created_at)
                VALUES(?,?,?,?,?,?,?,?)
                """,
                (run_id, result.task, result.status, result.summary, json.dumps(result.data, ensure_ascii=True), result.duration_ms, result.error, utc_now_iso()),
            )
            conn.execute(
                """
                UPDATE pipeline_runs
                SET current_task=?, progress_pct=?,
                    tasks_passed=(SELECT COUNT(*) FROM pipeline_steps WHERE run_id=? AND status='success'),
                    tasks_failed=(SELECT COUNT(*) FROM pipeline_steps WHERE run_id=? AND status='failed')
                WHERE id=?
                """,
                (result.task, progress_pct, run_id, run_id, run_id),
            )
            conn.commit()

    def complete_pipeline_run(self, run_id: str) -> None:
        with self._conn() as conn:
            run = conn.execute("SELECT started_at FROM pipeline_runs WHERE id=?", (run_id,)).fetchone()
            steps = conn.execute("SELECT status FROM pipeline_steps WHERE run_id=?", (run_id,)).fetchall()
            started_at = datetime.fromisoformat(run["started_at"].replace("Z", "+00:00"))
            duration_ms = int((utc_now() - started_at).total_seconds() * 1000)
            failed = sum(1 for step in steps if step["status"] == "failed")
            status = "completed_with_errors" if failed else "completed"
            conn.execute(
                """
                UPDATE pipeline_runs
                SET status=?, completed_at=?, duration_ms=?, progress_pct=100,
                    tasks_passed=(SELECT COUNT(*) FROM pipeline_steps WHERE run_id=? AND status='success'),
                    tasks_failed=(SELECT COUNT(*) FROM pipeline_steps WHERE run_id=? AND status='failed')
                WHERE id=?
                """,
                (status, utc_now_iso(), duration_ms, run_id, run_id, run_id),
            )
            conn.commit()

    def pipeline_status(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            run = conn.execute("SELECT * FROM pipeline_runs WHERE id=?", (run_id,)).fetchone()
            steps = conn.execute("SELECT * FROM pipeline_steps WHERE run_id=? ORDER BY id ASC", (run_id,)).fetchall()
        if not run:
            return None
        return {
            "run_id": run["id"],
            "status": run["status"],
            "current_task": run["current_task"],
            "progress_pct": run["progress_pct"],
            "started_at": run["started_at"],
            "completed_at": run["completed_at"],
            "duration_ms": run["duration_ms"],
            "tasks_passed": run["tasks_passed"],
            "tasks_failed": run["tasks_failed"],
            "steps": [
                {
                    "task": row["task_name"],
                    "status": row["status"],
                    "summary": row["summary"],
                    "data": _json_loads(row["data_json"], {}),
                    "duration_ms": row["duration_ms"],
                    "error": row["error"],
                    "created_at": row["created_at"],
                }
                for row in steps
            ],
        }

    def last_pipeline_run(self) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute("SELECT id FROM pipeline_runs ORDER BY started_at DESC LIMIT 1").fetchone()
        return self.pipeline_status(row["id"]) if row else None

    async def _step(self, task: str, coro: Callable[[], Awaitable[Dict[str, Any]]]) -> PipelineStepResult:
        started = time.perf_counter()
        try:
            data = await coro()
            status = "success"
            summary = data.get("summary") or data.get("message") or ", ".join(f"{k}={v}" for k, v in list(data.items())[:4])
            error = None
        except Exception as exc:
            logger.exception("Pipeline step failed: %s", task)
            data = {}
            status = "failed"
            summary = str(exc)
            error = str(exc)
        return PipelineStepResult(task=task, status=status, summary=summary, data=data, duration_ms=int((time.perf_counter() - started) * 1000), error=error)

    async def run_full_pipeline(self, run_id: Optional[str] = None, single_task: Optional[str] = None) -> str:
        run_id = run_id or self.create_pipeline_run(single_task)
        steps: List[tuple[str, str, Callable[[], Awaitable[Dict[str, Any]]]]] = [
            ("run_device_scan", "Run Device Scan", self.task_run_device_scan),
            ("health_check", "Health check", self.task_health_check),
            ("probe_live_feeds", "Probe live feeds", self.task_probe_feeds),
            ("run_aria_monitoring_cycle", "Run ARIA monitoring cycle", self.task_run_aria_monitoring_cycle),
            ("run_unified_intelligence_scan", "Run Unified Intelligence Scan", self.task_run_unified_intelligence_scan),
            ("sync_software_inventory", "Sync Software Inventory", self.task_sync_software_inventory),
            ("rescan_all_assets", "Rescan all assets", self.task_rescan_all_assets),
            ("refresh_alert_queue", "Refresh alert queue", self.task_refresh_alert_queue),
            ("generate_daily_report", "Generate daily report", self.task_generate_daily_report),
            ("sync_case_store", "Sync case store", self.task_sync_case_store),
            ("update_aria_stats", "Update ARIA stats", self.task_update_aria_stats),
        ]
        if single_task:
            steps = [step for step in steps if step[0] == single_task]
        await self.ws_hub.broadcast({"type": "pipeline_start", "run_id": run_id, "total_tasks": len(steps), "started_at": utc_now_iso()})
        for index, (task_key, label, handler) in enumerate(steps, start=1):
            await self.ws_hub.broadcast({"type": "task_start", "run_id": run_id, "task": task_key, "task_index": index, "total": len(steps), "label": label})
            result = await self._step(task_key, handler)
            progress = int(index / max(len(steps), 1) * 100)
            self.record_step(run_id, result, progress)
            await self.ws_hub.broadcast(
                {
                    "type": "task_complete",
                    "run_id": run_id,
                    "task": task_key,
                    "status": result.status,
                    "summary": result.summary,
                    "duration_ms": result.duration_ms,
                    "progress_pct": progress,
                    "data": result.data,
                }
            )
        self.complete_pipeline_run(run_id)
        latest = self.pipeline_status(run_id)
        await self.ws_hub.broadcast(
            {
                "type": "pipeline_done",
                "run_id": run_id,
                "status": latest["status"],
                "duration_ms": latest["duration_ms"],
                "passed": latest["tasks_passed"],
                "failed": latest["tasks_failed"],
                "completed_at": latest["completed_at"],
            }
        )
        return run_id

    async def task_run_device_scan(self) -> Dict[str, Any]:
        session_id = await self.start_device_scan("SYSTEM", "autopilot")
        session = self.get_device_session(session_id)
        deadline = time.monotonic() + 300
        while session and session.get("status") == "running" and time.monotonic() < deadline:
            await asyncio.sleep(1.0)
            session = self.get_device_session(session_id)
        session = session or {}
        return {
            "session_id": session_id,
            "connections_found": session.get("connections_found", 0),
            "connections_flagged": session.get("connections_flagged", 0),
            "processes_found": session.get("processes_found", 0),
            "overall_risk_score": session.get("overall_risk_score", 0),
            "summary": (
                f"{session.get('connections_found', 0)} connections checked "
                f"({session.get('connections_flagged', 0)} flagged), "
                f"{session.get('processes_found', 0)} processes analyzed"
            ),
        }

    async def task_sync_software_inventory(self) -> Dict[str, Any]:
        from .device_scan_agent import run_device_scan_software_only

        result = await run_device_scan_software_only(self, "SYSTEM")
        return {
            "session_id": result.get("session_id"),
            "count": result.get("count", 0),
            "summary": f"Software inventory refreshed ({result.get('count', 0)} applications)",
        }

    async def task_health_check(self) -> Dict[str, Any]:
        try:
            with self._conn() as conn:
                conn.execute("SELECT 1").fetchone()
            db_ok = True
        except sqlite3.Error:
            db_ok = False
        keys = self.feed_client.key_status()
        summary = f"API {'ok'} DB {'ok' if db_ok else 'fail'} Keys: {sum(1 for value in keys.values() if value)}/4"
        return {"api": True, "db": db_ok, "keys": keys, "summary": summary}

    async def task_probe_feeds(self) -> Dict[str, Any]:
        result = await self.probe_live_feeds()
        feed_bits = []
        for feed in result["feeds"]:
            marker = "✓" if feed["auth_valid"] else "✗"
            if feed["name"] == "urlscan" and feed["warning"]:
                await self.create_alert_for_asset(
                    {"id": -1, "label": "URLScan.io", "value": "urlscan.io", "type": "feed"},
                    90,
                    "CRITICAL",
                    "feed_degraded",
                )
                feed_bits.append(f"URLScan {marker} ({feed['http_status']})")
            else:
                feed_bits.append(f"{feed['display_name']} {marker}")
        result["summary"] = " ".join(feed_bits)
        return result

    async def task_run_aria_monitoring_cycle(self) -> Dict[str, Any]:
        result = await self.run_aria_monitoring_cycle(rescan_all=False)
        result["summary"] = f"Scanned {result['scanned']} assets, {result['high_risk']} high, {result['critical']} critical"
        return result

    async def task_rescan_all_assets(self) -> Dict[str, Any]:
        result = await self.run_aria_monitoring_cycle(rescan_all=True)
        result["summary"] = f"Rescanned {result['scanned']} assets"
        return result

    async def task_run_unified_intelligence_scan(self) -> Dict[str, Any]:
        session_id = await self.start_system_scan("SYSTEM")
        session = self.get_intelligence_session(session_id)
        if session and session["status"] == "running":
            while session and session["status"] == "running":
                await asyncio.sleep(0.5)
                session = self.get_intelligence_session(session_id)
        session = session or {}
        return {
            "session_id": session_id,
            "assets_scanned": session.get("assets_scanned", 0),
            "threats_found": session.get("threats_found", 0),
            "overall_risk_score": session.get("overall_risk_score", 0),
            "summary": f"{session.get('assets_scanned', 0)} assets scanned, {session.get('threats_found', 0)} threats found, risk score: {session.get('overall_risk_score', 0)}",
        }

    async def task_refresh_alert_queue(self) -> Dict[str, Any]:
        alerts = self.list_alerts(500)
        critical_unseen = sum(1 for alert in alerts if alert["severity"] == "CRITICAL" and not alert["seen"])
        auto_cases = 0
        for alert in alerts:
            if alert["severity"] == "CRITICAL" and not alert.get("case_id"):
                case_id = self.auto_create_case_for_alert(alert)
                if case_id:
                    auto_cases += 1
                    with self._conn() as conn:
                        conn.execute("UPDATE alerts SET case_id=?, updated_at=? WHERE id=?", (case_id, utc_now_iso(), alert["id"]))
                        conn.commit()
        return {
            "total_alerts": len(alerts),
            "new_alerts": self.unseen_alert_count(),
            "cases_auto_created": auto_cases,
            "critical_unacknowledged": critical_unseen,
            "summary": f"{len(alerts)} alerts, {critical_unseen} critical unseen",
        }

    async def task_generate_daily_report(self) -> Dict[str, Any]:
        report = await self.generate_daily_report()
        content = report["content"]
        return {"report_id": report["report_id"], "assets_covered": content["summary"]["asset_count"], "alerts_included": content["alerts"]["total"], "summary": f"Report #{report['report_id']} generated"}

    async def task_sync_case_store(self) -> Dict[str, Any]:
        result = self.sync_case_store()
        result["summary"] = f"{result['open']} open cases, {result['relinked']} relinked"
        return result

    async def task_update_aria_stats(self) -> Dict[str, Any]:
        result = self.update_aria_stats()
        result["summary"] = f"{result['monitored']} monitored, {result['critical']} critical"
        return result

    def admin_metrics(self) -> Dict[str, Any]:
        with self._conn() as conn:
            today_count = conn.execute("SELECT COUNT(*) AS count FROM pipeline_runs WHERE started_at >= date('now')").fetchone()["count"]
            avg_duration = conn.execute("SELECT AVG(duration_ms) AS avg_ms FROM pipeline_runs WHERE duration_ms IS NOT NULL").fetchone()["avg_ms"] or 0
            failed_steps = conn.execute("SELECT COUNT(*) AS count FROM pipeline_steps WHERE status='failed' AND created_at >= datetime('now', '-7 day')").fetchone()["count"]
            alerts_last_7d = conn.execute("SELECT COUNT(*) AS count FROM alerts WHERE created_at >= datetime('now', '-7 day')").fetchone()["count"]
            iocs_total = conn.execute("SELECT COUNT(*) AS count FROM iocs").fetchone()["count"]
        cases_auto_created = 0
        if self.case_store:
            cases = self.case_store.list_cases(status=None, severity=None, assigned_to=None, limit=500, search="AUTO")
            cases_auto_created = len([case for case in cases if case.get("assigned_to") == "AUTO"])
        return {
            "pipeline_runs_today": int(today_count or 0),
            "avg_pipeline_duration_ms": round(float(avg_duration or 0), 2),
            "tasks_failed_last_7d": int(failed_steps or 0),
            "alerts_generated_last_7d": int(alerts_last_7d or 0),
            "cases_auto_created_last_7d": cases_auto_created,
            "iocs_collected_total": int(iocs_total or 0),
            "last_runs": self._last_runs(),
        }

    def _last_runs(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM pipeline_runs ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]
