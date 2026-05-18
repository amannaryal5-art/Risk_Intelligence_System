from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import socket
import sys
import time
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit
from urllib.request import Request as UrlRequest, urlopen

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

if __package__:
    from .automation_service import AutomationService
    from .cyber_fusion import CyberFusionEngine
    from .enterprise import AuthManager, CaseStore, UserContext
    from .risk_engine import RiskEngine
    from .scamcheck import ScamCheckCacheStore, ScamCheckService
    from .scheduler_service import SchedulerService
    from .threat_intel import ThreatIntelEngine
else:
    from automation_service import AutomationService
    from cyber_fusion import CyberFusionEngine
    from enterprise import AuthManager, CaseStore, UserContext
    from risk_engine import RiskEngine
    from scamcheck import ScamCheckCacheStore, ScamCheckService
    from scheduler_service import SchedulerService
    from threat_intel import ThreatIntelEngine


# ─────────────────────────────────────────────────────
# Request/response models
# ─────────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1)


class BatchAnalyzeRequest(BaseModel):
    texts: List[str] = Field(..., min_length=1, max_length=100)


class WebsiteTraceRequest(BaseModel):
    url: str = Field(..., min_length=3)
    max_pages: int = Field(default=120, ge=1, le=500)
    max_depth: int = Field(default=4, ge=0, le=8)
    include_external: bool = Field(default=False)
    exhaustive: bool = Field(default=True)


class FusionScanRequest(BaseModel):
    text: Optional[str] = None
    website_url: Optional[str] = None
    max_pages: int = Field(default=80, ge=1, le=500)
    max_depth: int = Field(default=3, ge=0, le=8)
    include_external: bool = False
    exhaustive: bool = True


class ThreatIntelRequest(BaseModel):
    text: Optional[str] = None
    urls: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)
    live_feeds: Optional[bool] = None


class ScamCheckRequest(BaseModel):
    input: str = Field(..., min_length=1, max_length=8000)
    detectedType: str = Field(..., min_length=1, max_length=24)


class WebsiteIntelRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2000)


class FileAnalysisResult(BaseModel):
    filename: str
    size_bytes: int
    sha256: str
    risk_score: int
    risk_level: str
    suspicious_signals: List[str]
    ioc_intelligence: Dict[str, Any] = Field(default_factory=dict)


class FileAnalyzeRequest(BaseModel):
    filename: str = Field(..., min_length=1, max_length=300)
    content_base64: str = Field(..., min_length=1)


class CaseCreateRequest(BaseModel):
    source_type: str = Field(default="manual")
    source_value: Optional[str] = None
    title: str = Field(..., min_length=3, max_length=240)
    severity: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    status: str = Field(default="new", pattern="^(new|triaged|escalated|closed)$")
    assigned_to: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    findings: Dict[str, Any] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)
    ioc_type: Optional[str] = None
    ioc_value: Optional[str] = None
    risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    scan_result: Dict[str, Any] = Field(default_factory=dict)
    notes: Optional[str] = None


class CaseFromAnalysisRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=240)
    text: str = Field(..., min_length=1)
    tags: List[str] = Field(default_factory=list)
    assigned_to: Optional[str] = None


class CaseUpdateRequest(BaseModel):
    title: Optional[str] = Field(default=None, min_length=3, max_length=240)
    severity: Optional[str] = Field(default=None, pattern="^(low|medium|high|critical)$")
    status: Optional[str] = Field(default=None, pattern="^(new|triaged|escalated|closed)$")
    assigned_to: Optional[str] = None
    tags: Optional[List[str]] = None
    recommendations: Optional[List[str]] = None
    notes: Optional[str] = None


class CommentCreateRequest(BaseModel):
    message: Optional[str] = Field(default=None, min_length=1, max_length=1200)
    body: Optional[str] = Field(default=None, min_length=1, max_length=1200)


class FeedConfigRequest(BaseModel):
    alienvault_otx: Optional[str] = None
    abuseipdb: Optional[str] = None
    virustotal: Optional[str] = None
    urlscan: Optional[str] = None


class AutoScheduleRequest(BaseModel):
    enabled: bool
    interval_hours: int = Field(default=6, ge=1, le=168)


class AutoAssetRequest(BaseModel):
    name: str
    type: str
    value: str
    scan_interval_hours: int = 6


class AriaChatRequest(BaseModel):
    message: Optional[str] = None
    conversation_history: List[Dict[str, str]] = Field(default_factory=list)
    messages: List[Dict[str, str]] = Field(default_factory=list)


class UnifiedScanRequest(BaseModel):
    target: str = Field(..., min_length=1)
    targetType: str = Field(default="auto")
    context: Optional[str] = None
    engines: Dict[str, bool] = Field(default_factory=dict)


class DeviceScheduleRequest(BaseModel):
    enabled: bool
    intervalMinutes: int = Field(default=360, ge=5, le=10080)


class DeviceKillRequest(BaseModel):
    pid: int
    sessionId: str = Field(..., min_length=1)


class DeviceBlockRequest(BaseModel):
    ip: str = Field(..., min_length=7, max_length=45)
    reason: str = Field(default="", max_length=500)


# ─────────────────────────────────────────────────────
# Application bootstrap
# ─────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DATA_DIR = str(Path(tempfile.gettempdir()) / "riskintel") if os.getenv("VERCEL") else str(BASE_DIR / "data")
DATA_DIR = Path(os.getenv("RISKINTEL_DATA_DIR", DEFAULT_DATA_DIR))
logger = logging.getLogger("riskintel")


def _load_dotenv(dotenv_path: Path) -> None:
    if not dotenv_path.exists():
        return
    try:
        for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and os.getenv(key) is None:
                os.environ[key] = value
    except OSError:
        pass


def _sync_feed_env_aliases() -> None:
    alias_pairs = {
        "OTX_API_KEY": "RISKINTEL_OTX_API_KEY",
        "ABUSEIPDB_API_KEY": "RISKINTEL_ABUSEIPDB_API_KEY",
        "VIRUSTOTAL_API_KEY": "RISKINTEL_VT_API_KEY",
        "URLSCAN_API_KEY": "RISKINTEL_URLSCAN_API_KEY",
    }
    for alias, canonical in alias_pairs.items():
        alias_value = os.getenv(alias, "").strip()
        canonical_value = os.getenv(canonical, "").strip()
        if alias_value and not canonical_value:
            os.environ[canonical] = alias_value
        elif canonical_value and not alias_value:
            os.environ[alias] = canonical_value


_load_dotenv(BASE_DIR.parent / ".env")
_sync_feed_env_aliases()

engine = RiskEngine()
fusion_engine = CyberFusionEngine(engine)
threat_intel_engine = ThreatIntelEngine()
auth_manager = AuthManager()
case_store = CaseStore(DATA_DIR / "riskintel.db")
scamcheck_cache = ScamCheckCacheStore(DATA_DIR / "riskintel.db")
scamcheck_service = ScamCheckService(threat_intel_engine, engine, scamcheck_cache)
automation_service = AutomationService(
    DATA_DIR / "riskintel.db",
    case_store=case_store,
    audit_writer=case_store.audit,
    risk_engine=engine,
    threat_intel_engine=threat_intel_engine,
    fusion_engine=fusion_engine,
)
scheduler_service = SchedulerService(
    automation_service.get_setting,
    automation_service.upsert_setting,
    lambda: automation_service.run_full_pipeline(),
)

from apscheduler.schedulers.asyncio import AsyncIOScheduler  # noqa: E402
from apscheduler.triggers.interval import IntervalTrigger  # noqa: E402

_device_scan_scheduler = AsyncIOScheduler()
_DEVICE_SCAN_JOB_ID = "crie_device_scan"


async def configure_device_scan_schedule(enabled: bool, interval_minutes: int) -> Dict[str, Any]:
    if not _device_scan_scheduler.running:
        _device_scan_scheduler.start()
    if _device_scan_scheduler.get_job(_DEVICE_SCAN_JOB_ID):
        _device_scan_scheduler.remove_job(_DEVICE_SCAN_JOB_ID)
    next_run = None
    if enabled:

        async def _fire_device_scan() -> None:
            await automation_service.start_device_scan("SYSTEM", "scheduled")

        _device_scan_scheduler.add_job(
            _fire_device_scan,
            IntervalTrigger(minutes=interval_minutes),
            id=_DEVICE_SCAN_JOB_ID,
            replace_existing=True,
        )
        job = _device_scan_scheduler.get_job(_DEVICE_SCAN_JOB_ID)
        next_run = job.next_run_time.isoformat() if job and job.next_run_time else None
    config = {"enabled": enabled, "intervalMinutes": interval_minutes, "next_run": next_run}
    await automation_service.upsert_setting("device_scan_schedule", config)
    return config


async def restore_device_scan_schedule() -> Dict[str, Any]:
    config = automation_service.get_setting("device_scan_schedule", {"enabled": False, "intervalMinutes": 360})
    return await configure_device_scan_schedule(bool(config.get("enabled")), int(config.get("intervalMinutes") or 360))


async def trigger_login_auto_scans(user_id: str) -> None:
    try:
        await asyncio.gather(
            automation_service.start_device_scan(user_id, "login_auto"),
            automation_service.start_system_scan(user_id),
            return_exceptions=True,
        )
    except Exception:
        logger.exception("Auto-scan failed for user %s", user_id)

app = FastAPI(
    title="Risk Intelligence System",
    version="3.0.0",
    description="Async hybrid fraud/threat detection - rules + NLP + live IOC feeds",
    docs_url="/docs",
    redoc_url="/redoc",
)

_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if (_DIST / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(_DIST / "assets")), name="assets")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.add_middleware(GZipMiddleware, minimum_size=1024)

@app.get("/")
async def root():
    index = _DIST / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return {"service": "risk-intelligence-system", "status": "ok", "docs": "/docs"}

AUTH_ENFORCED = os.getenv("RISKINTEL_ENFORCE_AUTH", "true").lower() == "true"
DEFAULT_API_KEY = os.getenv("RISKINTEL_DEFAULT_API_KEY", "").strip()
_feed_status_cache: Dict[str, Any] = {"feeds": [], "summary": {"configured": 0, "reachable": 0, "auth_valid": 0, "total": 0}}


def _feed_env(*names: str) -> str:
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            return value
    return ""


def _mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def _reload_feed_keys() -> None:
    threat_intel_engine.otx_key = _feed_env("OTX_API_KEY", "RISKINTEL_OTX_API_KEY")
    threat_intel_engine.abuseipdb_key = _feed_env("ABUSEIPDB_API_KEY", "RISKINTEL_ABUSEIPDB_API_KEY")
    threat_intel_engine.vt_key = _feed_env("VIRUSTOTAL_API_KEY", "RISKINTEL_VT_API_KEY")
    threat_intel_engine.urlscan_key = _feed_env("URLSCAN_API_KEY", "RISKINTEL_URLSCAN_API_KEY")


def _live_feeds_default() -> bool:
    return (
        os.getenv("RISKINTEL_USE_LIVE_FEEDS", "true").lower() == "true"
        and threat_intel_engine.live_feeds_available
    )


def _build_feed_configs() -> Dict[str, Dict[str, Any]]:
    return {
        "alienvault_otx": {"name": "AlienVault OTX", "api_key": threat_intel_engine.otx_key, "enabled": bool(threat_intel_engine.otx_key), "health_check_url": "https://otx.alienvault.com/api/v1/user/me"},
        "abuseipdb": {"name": "AbuseIPDB", "api_key": threat_intel_engine.abuseipdb_key, "enabled": bool(threat_intel_engine.abuseipdb_key), "health_check_url": "https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1&maxAgeInDays=30"},
        "virustotal": {"name": "VirusTotal", "api_key": threat_intel_engine.vt_key, "enabled": bool(threat_intel_engine.vt_key), "health_check_url": "https://www.virustotal.com/api/v3/users/current"},
        "urlscan": {"name": "URLScan.io", "api_key": threat_intel_engine.urlscan_key, "enabled": bool(threat_intel_engine.urlscan_key), "health_check_url": "https://urlscan.io/api/v1/user/quotas/"},
    }


def _build_auth_headers(feed_name: str, api_key: str) -> Dict[str, str]:
    if feed_name == "alienvault_otx":
        return {"X-OTX-API-KEY": api_key}
    if feed_name == "abuseipdb":
        return {"Key": api_key, "Accept": "application/json"}
    if feed_name == "virustotal":
        return {"x-apikey": api_key}
    if feed_name == "urlscan":
        return {"API-Key": api_key}
    return {}


async def _probe_feed(feed_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
    if not config.get("api_key") or not config.get("enabled") or not config.get("health_check_url"):
        return {"name": feed_name, "display_name": config.get("name", feed_name), "configured": False, "reachable": False, "auth_valid": False, "latency_ms": None, "http_status": None, "error": None, "last_checked": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    headers = _build_auth_headers(feed_name, config["api_key"])
    headers["User-Agent"] = "RiskIntel/3.0"
    logger.info("Feed probe %s url=%s headers=%s", feed_name, config["health_check_url"], {k: (_mask_secret(v) if "key" in k.lower() else v) for k, v in headers.items()})
    try:
        started = time.monotonic()
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(config["health_check_url"], headers=headers)
        latency_ms = int((time.monotonic() - started) * 1000)
        return {"name": feed_name, "display_name": config.get("name", feed_name), "configured": True, "reachable": response.status_code < 500, "auth_valid": response.status_code not in (401, 403), "latency_ms": latency_ms, "http_status": response.status_code, "error": None if response.status_code < 500 else f"HTTP {response.status_code}", "last_checked": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        return {"name": feed_name, "display_name": config.get("name", feed_name), "configured": True, "reachable": False, "auth_valid": False, "latency_ms": None, "http_status": None, "error": str(exc), "last_checked": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def _patched_intent_profile(self: RiskEngine, text: str) -> Dict[str, object]:
    templates = {
        "romance_fraud": ["i love you", "send money", "emergency abroad", "military deployment", "offshore account"],
        "lottery_fraud": ["you have won", "claim your prize", "lottery winner", "transfer fee required"],
        "phishing_credential_theft": ["verify your account", "click here to login", "your password has expired", "confirm your identity"],
        "advance_fee_fraud": ["million dollars", "inheritance", "need your help to transfer", "percentage commission"],
        "tech_support_scam": ["your computer is infected", "call microsoft", "remote access", "your ip was hacked"],
    }
    norm = self._normalize(text)
    if len(norm.strip()) < 10:
        return {"top_intents": [], "max_similarity": 0.0}
    query_vector = self._vectorize(norm)
    scores = []
    for intent, items in templates.items():
        sims = [self._cosine(query_vector, self._vectorize(self._normalize(item))) for item in items]
        best = max(sims) if sims else 0.0
        scores.append({"intent": intent, "similarity": round(best * 100, 1)})
    top = sorted(scores, key=lambda item: item["similarity"], reverse=True)[:4]
    return {"top_intents": top, "max_similarity": top[0]["similarity"] if top else 0.0}


def _patched_whois_domain_age_profile(self: RiskEngine, hostname: str) -> Dict[str, object]:
    host = (hostname or "").strip().lower()
    if not host:
        return {"score": 0.0, "flags": [], "age_days": None, "status": "unavailable"}

    cached = self._global_whois_cache.get(host)
    if cached is not None:
        return cached

    root = self._effective_domain(host)
    score = 0.0
    flags: List[str] = []
    age_days: Optional[int] = None
    creation_date: Optional[str] = None
    status = "unavailable"

    risk_engine_module = sys.modules.get("risk_engine") or sys.modules.get("app.risk_engine")
    python_whois = getattr(risk_engine_module, "python_whois", None) if risk_engine_module else None
    if python_whois is not None:
        try:
            record = python_whois.whois(root)
            created = getattr(record, "creation_date", None)
            if isinstance(created, list):
                created = created[0] if created else None
            if created:
                if getattr(created, "tzinfo", None) is not None:
                    created = created.replace(tzinfo=None)
                age_days = max(0, (datetime.utcnow() - created).days)
                creation_date = created.isoformat()
                status = "ok"
        except Exception as exc:
            logger.warning("WHOIS lookup failed for %s: %s", root, exc)

    if age_days is None:
        try:
            req = UrlRequest(
                f"https://rdap.org/domain/{root}",
                headers={"User-Agent": "RiskIntel/3.0", "Accept": "application/rdap+json"},
            )
            with urlopen(req, timeout=8.0) as response:
                payload = response.read(240000).decode("utf-8", errors="ignore")
            match = self._re_whois_date.search(payload)
            if match:
                year, month, day = int(match.group(1)), int(match.group(2)), int(match.group(3))
                created = datetime(year=year, month=max(1, min(month, 12)), day=max(1, min(day, 28)))
                age_days = max(0, (datetime.utcnow() - created).days)
                creation_date = created.isoformat()
                status = "ok"
        except Exception as exc:
            logger.warning("RDAP lookup failed for %s: %s", root, exc)

    if age_days is not None:
        if age_days < 30:
            score += 0.23; flags.append("Very new domain (<30 days)")
        elif age_days < 90:
            score += 0.16; flags.append("Recently registered (<90 days)")
        elif age_days < 180:
            score += 0.10; flags.append("Young domain (<180 days)")

    out = {
        "score": round(min(0.3, score), 3),
        "flags": flags,
        "age_days": age_days,
        "creation_date": creation_date,
        "status": status,
    }
    self._global_whois_cache.set(host, out)
    return out


def _patched_domain_reputation_profile(self: RiskEngine, hostname: str) -> Dict[str, object]:
    host = (hostname or "").strip().lower()
    base = {"score": 0.0, "flags": [], "category": "unknown", "reputation": "unknown", "sources": []}
    if not host:
        return base

    original = getattr(self, "_original_domain_reputation_profile", None)
    if callable(original):
        base.update(original(host))
    else:
        cached = self._global_domain_cache.get(host)
        if cached is not None:
            return cached

    sources: List[Dict[str, Any]] = []
    total_malicious = 0
    vt_key = _feed_env("VIRUSTOTAL_API_KEY", "RISKINTEL_VT_API_KEY")
    if vt_key:
        try:
            with httpx.Client(timeout=8.0, follow_redirects=True) as client:
                response = client.get(
                    f"https://www.virustotal.com/api/v3/domains/{host}",
                    headers={"x-apikey": vt_key, "User-Agent": "RiskIntel/3.0"},
                )
            if response.status_code == 200:
                vt_data = response.json()
                stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = int(stats.get("malicious", 0) or 0)
                suspicious = int(stats.get("suspicious", 0) or 0)
                total_malicious += malicious + suspicious
                sources.append({
                    "source": "virustotal",
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "http_status": response.status_code,
                })
            else:
                sources.append({"source": "virustotal", "malicious": 0, "http_status": response.status_code})
        except Exception as exc:
            logger.warning("VirusTotal domain reputation lookup failed for %s: %s", host, exc)

    if total_malicious <= 0:
        reputation = "clean" if sources else "unknown"
    elif total_malicious < 3:
        reputation = "suspicious"
    else:
        reputation = "malicious"

    base["sources"] = sources
    base["reputation"] = reputation
    base["total_malicious_hits"] = total_malicious
    if total_malicious > 0:
        base["score"] = round(min(1.0, float(base.get("score", 0.0)) + min(0.45, total_malicious * 0.08)), 3)
        flags = list(base.get("flags", []))
        flags.append(f"VirusTotal reports {total_malicious} malicious/suspicious detections")
        base["flags"] = flags[:8]
        base["category"] = "poor" if total_malicious >= 3 else "questionable"

    self._global_domain_cache.set(host, base)
    return base


RiskEngine._original_domain_reputation_profile = RiskEngine._domain_reputation_profile
RiskEngine._whois_domain_age_profile = _patched_whois_domain_age_profile
RiskEngine._domain_reputation_profile = _patched_domain_reputation_profile
RiskEngine._intent_profile = _patched_intent_profile
_reload_feed_keys()


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception for %s %s", request.method, request.url.path, exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "path": request.url.path},
    )


def _website_verdict_from_score(score: int) -> str:
    if score >= 70:
        return "DANGER"
    if score >= 30:
        return "CAUTION"
    return "SAFE"


def _website_summary(verdict: str, domain: str, feeds: Dict[str, Any]) -> str:
    vt = int((((feeds.get("virustotal") or {}).get("malicious")) or 0))
    abuse = int((((feeds.get("abuseipdb") or {}).get("abuseConfidence")) or 0))
    otx = int((((feeds.get("otx") or {}).get("pulseCount")) or 0))
    if verdict == "DANGER":
        if vt > 5:
            return f"Do not visit {domain}. VirusTotal flagged it across {vt} engines."
        if abuse > 50:
            return f"Proceeding is risky. Abuse intelligence is elevated for infrastructure linked to {domain}."
        return f"{domain} is tied to multiple threat-intelligence hits and should be avoided."
    if verdict == "CAUTION":
        if vt or abuse or otx:
            return f"Proceed with caution. {domain} has some suspicious reputation signals."
        return f"{domain} looks mostly clean, but there are a few signals worth double-checking."
    return f"No strong malicious signals were found for {domain}. Safe to visit with normal caution."


def _build_website_scan_result(input_url: str) -> Dict[str, Any]:
    normalized = input_url.strip()
    parsed = urlsplit(normalized if "://" in normalized else f"https://{normalized}")
    domain = (parsed.hostname or "").lower()
    if not domain or "." not in domain:
        raise ValueError(f"Invalid URL: {input_url}")
    ip = ""
    if domain:
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            ip = ""

    otx_raw = threat_intel_engine._lookup_otx("domain", domain) if domain else {"source": "otx", "pulse_count": 0}
    vt_raw = threat_intel_engine._lookup_virustotal("url", normalized)
    abuse_raw = threat_intel_engine._lookup_abuseipdb("ip", ip) if ip else {"source": "abuseipdb", "abuse_confidence": 0}

    vt_malicious = int(vt_raw.get("malicious_votes", 0) or 0)
    vt_suspicious = int(vt_raw.get("suspicious_votes", 0) or 0)
    abuse_confidence = int(abuse_raw.get("abuse_confidence", 0) or 0)
    otx_pulses = int(otx_raw.get("pulse_count", 0) or 0)

    risk_score = 0
    risk_score += 40 if vt_malicious > 5 else 20 if vt_malicious >= 1 else 0
    risk_score += 30 if abuse_confidence > 50 else 15 if abuse_confidence >= 10 else 0
    risk_score += 20 if otx_pulses > 2 else 10 if otx_pulses >= 1 else 0
    risk_score = min(100, risk_score)
    verdict = _website_verdict_from_score(risk_score)

    return {
        "type": "url",
        "input": normalized,
        "domain": domain,
        "ip": ip,
        "riskScore": risk_score,
        "verdict": verdict,
        "summary": _website_summary(
            verdict,
            domain or normalized,
            {
                "otx": {"pulseCount": otx_pulses},
                "abuseipdb": {"abuseConfidence": abuse_confidence},
                "virustotal": {"malicious": vt_malicious},
            },
        ),
        "feeds": {
            "otx": {
                "pulseCount": otx_pulses,
                "threatScore": min(100, otx_pulses * 20),
                "raw": otx_raw,
            },
            "abuseipdb": {
                "abuseConfidence": abuse_confidence,
                "totalReports": int(abuse_raw.get("total_reports", 0) or 0),
                "country": abuse_raw.get("country"),
                "isp": abuse_raw.get("isp"),
                "raw": abuse_raw,
            },
            "virustotal": {
                "malicious": vt_malicious,
                "suspicious": vt_suspicious,
                "total": vt_malicious + vt_suspicious,
                "raw": vt_raw,
            },
        },
        "scannedAt": datetime.utcnow().isoformat(),
    }


automation_service.website_scan_builder = _build_website_scan_result


async def refresh_feed_status_cache() -> Dict[str, Any]:
    global _feed_status_cache
    results = await automation_service.probe_live_feeds()
    normalized = [automation_service.normalize_feed_record(dict(feed)) for feed in results["feeds"]]
    _feed_status_cache = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "feeds": normalized,
        "summary": automation_service.feed_summary(),
    }
    return _feed_status_cache

# ─────────────────────────────────────────────────────
# In-memory response cache (TTL 60s)
# ─────────────────────────────────────────────────────
_response_cache: Dict[str, tuple] = {}
_RESPONSE_CACHE_TTL = 60.0


def _cache_key(*parts: str) -> str:
    return hashlib.md5(":".join(parts).encode()).hexdigest()


def _get_cached(key: str) -> Optional[Any]:
    entry = _response_cache.get(key)
    if entry and time.monotonic() - entry[1] < _RESPONSE_CACHE_TTL:
        return entry[0]
    return None


def _set_cached(key: str, value: Any) -> None:
    if len(_response_cache) > 2000:
        oldest = min(_response_cache.items(), key=lambda x: x[1][1])
        _response_cache.pop(oldest[0], None)
    _response_cache[key] = (value, time.monotonic())


# ─────────────────────────────────────────────────────
# Request timing middleware
# ─────────────────────────────────────────────────────
@app.middleware("http")
async def add_timing_header(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    response.headers["X-Process-Time-Ms"] = str(elapsed_ms)
    return response


# ─────────────────────────────────────────────────────
# Request counter middleware
# ─────────────────────────────────────────────────────
_request_counters: Dict[str, int] = {}


@app.middleware("http")
async def count_requests(request: Request, call_next):
    path = request.url.path
    _request_counters[path] = _request_counters.get(path, 0) + 1
    return await call_next(request)


# ─────────────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────────────
def get_current_user(x_api_key: Optional[str] = Header(default=None)) -> UserContext:
    provided_key = (x_api_key or "").strip()
    user = auth_manager.identify(provided_key or DEFAULT_API_KEY)
    if not user.authenticated and DEFAULT_API_KEY and provided_key and provided_key != DEFAULT_API_KEY:
        user = auth_manager.identify(DEFAULT_API_KEY)
    if AUTH_ENFORCED and auth_manager.key_count == 0:
        raise HTTPException(
            status_code=503,
            detail="Authentication is enabled but RISKINTEL_API_KEYS is not configured",
        )
    if AUTH_ENFORCED and not user.authenticated:
        raise HTTPException(status_code=401, detail="Valid X-API-Key is required")
    return user


def require_roles(*roles: str):
    allowed = set(roles)

    def _dep(user: UserContext = Depends(get_current_user)) -> UserContext:
        if not user.authenticated:
            raise HTTPException(status_code=401, detail="Valid X-API-Key is required")
        if user.role not in allowed:
            raise HTTPException(status_code=403, detail=f"Role '{user.role}' not allowed")
        return user

    return _dep


# ─────────────────────────────────────────────────────
# Static routes
# ─────────────────────────────────────────────────────
@app.get("/api/v1/health")
async def health() -> dict:
    return {
        "status": "ok",
        "service": "risk-intelligence-system",
        "version": "3.0.0",
        "auth_enforced": AUTH_ENFORCED,
        "configured_api_keys": auth_manager.key_count,
        "default_api_key_configured": bool(DEFAULT_API_KEY),
        "live_feeds_available": threat_intel_engine.live_feeds_available,
        "live_feeds_default": _live_feeds_default(),
        "data_dir": str(DATA_DIR),
        "live_feed_status": threat_intel_engine.live_feed_status,
        "engine_cache_sizes": {
            "link_cache": len(engine._global_link_cache),
            "domain_cache": len(engine._global_domain_cache),
            "whois_cache": len(engine._global_whois_cache),
        },
    }


@app.on_event("startup")
async def startup_diagnostics() -> None:
    logger.info("=== CRIE v3.0 STARTUP DIAGNOSTICS ===")
    for env_names in (
        ("OTX_API_KEY", "RISKINTEL_OTX_API_KEY"),
        ("ABUSEIPDB_API_KEY", "RISKINTEL_ABUSEIPDB_API_KEY"),
        ("VIRUSTOTAL_API_KEY", "RISKINTEL_VT_API_KEY"),
        ("URLSCAN_API_KEY", "RISKINTEL_URLSCAN_API_KEY"),
    ):
        env_key = env_names[0]
        value = _feed_env(*env_names)
        if value:
            logger.info("  %s: configured (%s chars)", env_key, len(value))
        else:
            logger.warning("  %s: missing", env_key)
    if os.getenv("VERCEL"):
        logger.info("Skipping startup feed probe on Vercel serverless runtime")
        logger.info("=====================================")
        return
    for attempt in range(1, 4):
        try:
            results = await refresh_feed_status_cache()
            for feed in results.get("feeds", []):
                state = "LIVE" if feed.get("auth_valid") else ("AUTH FAIL" if feed.get("reachable") else "OFFLINE")
                logger.info("  %s: %s", feed.get("name"), state)
            break
        except Exception as exc:
            logger.warning("Feed probe attempt %d/3 failed: %s", attempt, exc)
            if attempt < 3:
                await asyncio.sleep(5)
    await scheduler_service.restore()
    await restore_device_scan_schedule()
    logger.info("=====================================")


@app.get("/api/v1/live-feeds/status")
async def live_feeds_status(probe: bool = False) -> dict:
    if probe or not automation_service.get_feed_status():
        await refresh_feed_status_cache()
    return {"generated_at": datetime.utcnow().isoformat() + "Z", "feeds": automation_service.get_feed_status(), "summary": automation_service.feed_summary()}


@app.get("/api/v1/feeds/probe")
async def probe_all_feeds(user: UserContext = Depends(get_current_user)) -> dict:
    return await refresh_feed_status_cache()


@app.get("/api/v1/feeds/status/live")
async def feeds_live_status(
    background_tasks: BackgroundTasks,
    user: UserContext = Depends(get_current_user),
) -> dict:
    if not _feed_status_cache.get("feeds"):
        return await refresh_feed_status_cache()
    background_tasks.add_task(refresh_feed_status_cache)
    return _feed_status_cache


@app.websocket("/api/v1/ws/feeds/status")
async def feeds_status_ws(websocket: WebSocket) -> None:
    await automation_service.ws_hub.connect(websocket)
    try:
        if _feed_status_cache.get("feeds"):
            await websocket.send_json({"type": "feed_status", "timestamp": _feed_status_cache.get("timestamp"), "data": _feed_status_cache})
        latest = automation_service.last_pipeline_run()
        if latest:
            await websocket.send_json({"type": "pipeline_snapshot", "data": latest})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await automation_service.ws_hub.disconnect(websocket)


@app.post("/api/v1/feeds/configure", dependencies=[Depends(require_roles("admin"))])
async def configure_feeds(payload: FeedConfigRequest, user: UserContext = Depends(get_current_user)) -> dict:
    if os.getenv("VERCEL"):
        raise HTTPException(
            status_code=501,
            detail="Feed configuration writes to .env are disabled on Vercel. Configure environment variables in the Vercel dashboard.",
        )
    env_path = BASE_DIR.parent / ".env"
    existing = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
    key_map = {
        "alienvault_otx": "OTX_API_KEY",
        "abuseipdb": "ABUSEIPDB_API_KEY",
        "virustotal": "VIRUSTOTAL_API_KEY",
        "urlscan": "URLSCAN_API_KEY",
    }
    updates = {key_map[k]: v.strip() for k, v in payload.model_dump().items() if v and k in key_map}
    new_lines: List[str] = []
    updated: set[str] = set()
    for line in existing:
        if "=" not in line:
            new_lines.append(line)
            continue
        key = line.split("=", 1)[0].strip()
        if key in updates:
            new_lines.append(f"{key}={updates[key]}")
            updated.add(key)
        elif key.startswith("RISKINTEL_") and key.replace("RISKINTEL_", "", 1) in updates:
            actual = key.replace("RISKINTEL_", "", 1)
            new_lines.append(f"{key}={updates[actual]}")
            updated.add(actual)
        else:
            new_lines.append(line)
    for key, value in updates.items():
        if key not in updated:
            new_lines.append(f"{key}={value}")
    env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    for key, value in updates.items():
        os.environ[key] = value
        os.environ[f"RISKINTEL_{key}"] = value
    _reload_feed_keys()
    await refresh_feed_status_cache()
    case_store.audit(user.username, user.role, "configure_feeds", "feeds", meta={"updated": sorted(updates.keys())})
    return {"status": "ok", "updated": sorted(updates.keys())}


@app.get("/api/dashboard/stats")
async def dashboard_stats(user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))) -> dict:
    return automation_service.dashboard_stats(user.username)


@app.get("/api/dashboard/risk-trend")
async def dashboard_risk_trend(user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))) -> List[Dict[str, Any]]:
    trend = automation_service.intelligence_risk_trend(user.username, hours=24 * 7)
    return trend or automation_service.risk_trend(hours=24 * 7, limit=20)


@app.get("/api/feeds/status")
async def feeds_status_db(user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))) -> List[Dict[str, Any]]:
    if not automation_service.get_feed_status():
        await refresh_feed_status_cache()
    return automation_service.get_feed_status()


@app.post("/api/feeds/probe-all")
async def feeds_probe_all(user: UserContext = Depends(require_roles("admin", "analyst"))) -> dict:
    return await refresh_feed_status_cache()


@app.get("/api/v1/auth/whoami")
async def whoami(user: UserContext = Depends(get_current_user)) -> dict:
    scans_initiated: List[str] = []
    if user.authenticated:
        scans_initiated = ["device", "intelligence"]
        asyncio.create_task(trigger_login_auto_scans(user.username))
    return {
        "authenticated": user.authenticated,
        "username": user.username,
        "role": user.role,
        "api_key_hash": user.api_key_hash,
        "scansInitiated": scans_initiated,
    }


# ─────────────────────────────────────────────────────
# Core analysis endpoints
# ─────────────────────────────────────────────────────
@app.post("/api/v1/analyze")
async def analyze(
    payload: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    user: UserContext = Depends(get_current_user),
) -> dict:
    ck = _cache_key("analyze", payload.text[:500])
    cached = _get_cached(ck)
    if cached:
        return cached

    result, ioc_intel = await asyncio.gather(
        engine.analyze_async(payload.text),
        threat_intel_engine.scan_async(text=payload.text, live_feeds=_live_feeds_default()),
    )
    result["ioc_intelligence"] = ioc_intel
    _set_cached(ck, result)

    background_tasks.add_task(
        case_store.audit,
        actor=user.username, role=user.role, action="analyze_text", target_type="analysis",
        meta={"score": result.get("score"), "risk_level": result.get("risk_level"), "auth": user.authenticated},
    )
    return result


@app.post("/api/v1/analyze/batch")
async def analyze_batch(
    payload: BatchAnalyzeRequest,
    background_tasks: BackgroundTasks,
    user: UserContext = Depends(get_current_user),
) -> dict:
    results = await engine.analyze_batch_async(payload.texts)
    background_tasks.add_task(
        case_store.audit, actor=user.username, role=user.role, action="analyze_batch",
        target_type="analysis", meta={"count": len(results), "auth": user.authenticated},
    )
    return {"count": len(results), "results": results}


@app.post("/api/v1/threat-intel")
async def threat_intel(
    payload: ThreatIntelRequest,
    background_tasks: BackgroundTasks,
    user: UserContext = Depends(get_current_user),
) -> dict:
    live = _live_feeds_default() if payload.live_feeds is None else bool(payload.live_feeds)
    result = await threat_intel_engine.scan_async(
        text=payload.text, urls=payload.urls, domains=payload.domains,
        ips=payload.ips, hashes=payload.hashes, live_feeds=live,
    )
    background_tasks.add_task(
        case_store.audit, actor=user.username, role=user.role, action="threat_intel_scan",
        target_type="intel", meta={"ioc_count": result.get("ioc_count", 0), "overall_risk": result.get("overall_risk")},
    )
    return result


@app.post("/api/v1/scamcheck")
async def scamcheck(payload: ScamCheckRequest) -> dict:
    return await scamcheck_service.check_async(payload.input, payload.detectedType)


@app.post("/api/v1/website-intel")
async def website_intel(payload: WebsiteIntelRequest) -> dict:
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(engine._executor, lambda: _build_website_scan_result(payload.url))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/malware/analyze-file", response_model=FileAnalysisResult)
async def analyze_file(
    payload: FileAnalyzeRequest,
    background_tasks: BackgroundTasks,
    user: UserContext = Depends(get_current_user),
) -> FileAnalysisResult:
    try:
        blob = base64.b64decode(payload.content_base64, validate=True)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid base64 file payload") from exc

    size_bytes = len(blob)
    sha256 = hashlib.sha256(blob).hexdigest()
    lowered = blob[:200000].lower()
    flags: List[str] = []
    score = 0

    if payload.filename.lower().endswith((".exe", ".dll", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".hta")):
        score += 35; flags.append("Executable/script extension")
    if blob.startswith(b"MZ"):
        score += 28; flags.append("PE header (MZ magic bytes)")
    if b"powershell" in lowered or b"cmd.exe" in lowered:
        score += 18; flags.append("Command execution string")
    if b"autoopen" in lowered or b"document_open" in lowered:
        score += 22; flags.append("Macro auto-execution pattern")
    if b"http://" in lowered or b"https://" in lowered:
        score += 10; flags.append("Embedded URL/network indicator")
    if size_bytes > 8_000_000:
        score += 6; flags.append("Large file size anomaly")
    if b"createobject" in lowered:
        score += 15; flags.append("CreateObject COM call (possible script malware)")
    if b"wscript.shell" in lowered:
        score += 20; flags.append("WScript.Shell execution")

    score = min(100, max(0, score))
    level = "critical" if score >= 80 else ("high" if score >= 55 else ("medium" if score >= 30 else "low"))

    file_ioc = await threat_intel_engine.scan_async(hashes=[sha256], live_feeds=_live_feeds_default())

    background_tasks.add_task(
        case_store.audit, actor=user.username, role=user.role, action="malware_file_analysis",
        target_type="file", target_id=payload.filename, meta={"size": size_bytes, "risk_score": score, "risk_level": level},
    )
    return FileAnalysisResult(
        filename=payload.filename, size_bytes=size_bytes, sha256=sha256,
        risk_score=score, risk_level=level, suspicious_signals=flags[:8], ioc_intelligence=file_ioc,
    )


@app.post("/api/v1/trace-website")
async def trace_website(
    payload: WebsiteTraceRequest,
    background_tasks: BackgroundTasks,
    user: UserContext = Depends(get_current_user),
) -> dict:
    ck = _cache_key("trace_website", payload.url, str(payload.max_pages), str(payload.max_depth))
    cached = _get_cached(ck)
    if cached:
        return cached

    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            engine._executor,
            lambda: engine.trace_website(
                payload.url, max_pages=payload.max_pages, max_depth=payload.max_depth,
                include_external=payload.include_external, exhaustive=payload.exhaustive,
            ),
        )
        _set_cached(ck, result)
        background_tasks.add_task(
            case_store.audit, actor=user.username, role=user.role, action="trace_website",
            target_type="website", target_id=payload.url,
            meta={"site_verdict": result.get("site_verdict"), "pages_crawled": result.get("pages_crawled")},
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/fusion-scan")
async def fusion_scan(
    payload: FusionScanRequest,
    background_tasks: BackgroundTasks,
    user: UserContext = Depends(get_current_user),
) -> dict:
    if not (payload.text and payload.text.strip()) and not (payload.website_url and payload.website_url.strip()):
        raise HTTPException(status_code=400, detail="Provide at least one of: text, website_url")
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            engine._executor,
            lambda: fusion_engine.fusion_scan(
                text=payload.text, website_url=payload.website_url,
                max_pages=payload.max_pages, max_depth=payload.max_depth,
                include_external=payload.include_external, exhaustive=payload.exhaustive,
            ),
        )
        if payload.text and payload.text.strip() and isinstance(result.get("text_analysis"), dict):
            ioc = await threat_intel_engine.scan_async(text=payload.text, live_feeds=_live_feeds_default())
            result["text_analysis"]["ioc_intelligence"] = ioc
        if payload.website_url and payload.website_url.strip():
            website_intel = await loop.run_in_executor(
                engine._executor,
                lambda: _build_website_scan_result(payload.website_url or ""),
            )
            result["website_intelligence"] = website_intel

        background_tasks.add_task(
            case_store.audit, actor=user.username, role=user.role, action="fusion_scan",
            target_type="platform", target_id=payload.website_url or "text-only",
            meta={"posture_score": result.get("posture_score"), "posture_state": result.get("posture_state")},
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ─────────────────────────────────────────────────────
# Quick IOC lookup
# ─────────────────────────────────────────────────────
@app.get("/api/v1/ioc/{ioc_type}/{value}")
async def quick_ioc_lookup(
    ioc_type: str,
    value: str,
    live: bool = False,
    user: UserContext = Depends(get_current_user),
) -> dict:
    valid_types = {"domain", "ip", "url", "hash_md5", "hash_sha256", "hash_sha1"}
    if ioc_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"ioc_type must be one of: {sorted(valid_types)}")
    result = await threat_intel_engine.scan_async(**{f"{ioc_type}s" if ioc_type != "url" else "urls": [value], "live_feeds": live})
    return result


# ─────────────────────────────────────────────────────
# Cache management
# ─────────────────────────────────────────────────────
@app.post("/api/v1/cache/clear", dependencies=[Depends(require_roles("admin"))])
async def clear_caches() -> dict:
    engine._global_link_cache.clear()
    engine._global_whois_cache.clear()
    engine._global_domain_cache.clear()
    engine._global_cert_cache.clear()
    engine._global_sitemap_cache.clear()
    threat_intel_engine._cache.clear()
    _response_cache.clear()
    return {"status": "cleared", "message": "All engine and response caches cleared."}


@app.get("/api/v1/cache/stats", dependencies=[Depends(require_roles("admin", "analyst"))])
async def cache_stats() -> dict:
    return {
        "engine": {
            "link_cache": len(engine._global_link_cache),
            "domain_cache": len(engine._global_domain_cache),
            "whois_cache": len(engine._global_whois_cache),
            "cert_cache": len(engine._global_cert_cache),
            "sitemap_cache": len(engine._global_sitemap_cache),
        },
        "threat_intel_cache": len(getattr(threat_intel_engine._cache, "_store", {})),
        "response_cache": len(_response_cache),
    }


# ─────────────────────────────────────────────────────
# Metrics
# ─────────────────────────────────────────────────────
@app.get("/api/v1/metrics", dependencies=[Depends(require_roles("admin"))])
async def metrics() -> Response:
    lines = ["# HELP riskintel_requests_total Total requests per path",
             "# TYPE riskintel_requests_total counter"]
    for path, count in sorted(_request_counters.items()):
        safe_path = path.replace("/", "_").replace("-", "_").strip("_")
        lines.append(f'riskintel_requests_total{{path="{safe_path}"}} {count}')
    lines += [
        "",
        "# HELP riskintel_cache_size Cache sizes",
        "# TYPE riskintel_cache_size gauge",
        f'riskintel_cache_size{{name="link_cache"}} {len(engine._global_link_cache)}',
        f'riskintel_cache_size{{name="domain_cache"}} {len(engine._global_domain_cache)}',
        f'riskintel_cache_size{{name="threat_intel"}} {len(getattr(threat_intel_engine._cache, "_store", {}))}',
    ]
    return Response(content="\n".join(lines), media_type="text/plain")


# ─────────────────────────────────────────────────────
# Case management
# ─────────────────────────────────────────────────────
@app.post("/api/v1/cases", dependencies=[Depends(require_roles("admin", "analyst"))])
async def create_case(payload: CaseCreateRequest, user: UserContext = Depends(get_current_user)) -> dict:
    rec = case_store.create_case({
        "source_type": payload.source_type, "source_value": payload.source_value,
        "title": payload.title, "severity": payload.severity, "status": payload.status,
        "assigned_to": payload.assigned_to, "reporter": user.username,
        "findings": payload.findings, "tags": payload.tags, "recommendations": payload.recommendations,
        "ioc_type": payload.ioc_type, "ioc_value": payload.ioc_value, "risk_score": payload.risk_score,
        "scan_result": payload.scan_result, "notes": payload.notes,
    })
    case_store.audit(user.username, user.role, "create_case", "case", str(rec["id"]), {"severity": rec["severity"]})
    return rec


@app.post("/api/v1/cases/from-analysis", dependencies=[Depends(require_roles("admin", "analyst"))])
async def create_case_from_analysis(payload: CaseFromAnalysisRequest, user: UserContext = Depends(get_current_user)) -> dict:
    analysis = await engine.analyze_async(payload.text)
    rec = case_store.create_case({
        "source_type": "text", "source_value": payload.text[:300],
        "title": payload.title, "severity": analysis.get("risk_level", "medium"),
        "status": "new", "assigned_to": payload.assigned_to, "reporter": user.username,
        "findings": analysis, "tags": payload.tags, "recommendations": analysis.get("recommendations", []),
    })
    case_store.audit(user.username, user.role, "create_case_from_analysis", "case", str(rec["id"]),
                     {"risk_level": analysis.get("risk_level"), "score": analysis.get("score")})
    return rec


@app.get("/api/v1/cases")
async def list_cases(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assigned_to: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    user: UserContext = Depends(require_roles("admin", "analyst", "viewer")),
) -> dict:
    rows = case_store.list_cases(status=status, severity=severity, assigned_to=assigned_to, limit=limit, search=search)
    case_store.audit(user.username, user.role, "list_cases", "case", meta={"count": len(rows)})
    return {"count": len(rows), "results": rows}


@app.get("/api/v1/cases/{case_id}")
async def get_case(case_id: int, user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))) -> dict:
    try:
        rec = case_store.get_case(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    case_store.audit(user.username, user.role, "get_case", "case", str(case_id))
    return rec


@app.patch("/api/v1/cases/{case_id}", dependencies=[Depends(require_roles("admin", "analyst"))])
async def update_case(case_id: int, payload: CaseUpdateRequest, user: UserContext = Depends(get_current_user)) -> dict:
    try:
        rec = case_store.update_case(case_id, payload.model_dump())
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    case_store.audit(user.username, user.role, "update_case", "case", str(case_id), payload.model_dump())
    return rec


@app.delete("/api/v1/cases/{case_id}", dependencies=[Depends(require_roles("admin", "analyst"))], status_code=204)
async def delete_case(case_id: int, user: UserContext = Depends(get_current_user)) -> Response:
    try:
        case_store.delete_case(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    case_store.audit(user.username, user.role, "delete_case", "case", str(case_id))
    return Response(status_code=204)


@app.post("/api/v1/cases/{case_id}/comments", dependencies=[Depends(require_roles("admin", "analyst"))])
async def add_case_comment(case_id: int, payload: CommentCreateRequest, user: UserContext = Depends(get_current_user)) -> dict:
    comment_text = (payload.message or payload.body or "").strip()
    if not comment_text:
        raise HTTPException(status_code=400, detail="Comment body is required")
    try:
        comment = case_store.add_comment(case_id, user.username, comment_text)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    case_store.audit(user.username, user.role, "add_case_comment", "case", str(case_id))
    return comment


@app.get("/api/v1/audit", dependencies=[Depends(require_roles("admin"))])
async def list_audits(limit: int = 100, user: UserContext = Depends(get_current_user)) -> dict:
    rows = case_store.list_audits(limit=limit)
    case_store.audit(user.username, user.role, "list_audit_logs", "audit", meta={"count": len(rows)})
    return {"count": len(rows), "results": rows}

@app.on_event("shutdown")
async def _automation_shutdown():
    scheduler_service.shutdown()
    if _device_scan_scheduler.running:
        _device_scan_scheduler.shutdown(wait=False)


@app.post("/api/autopilot/run-all", status_code=202)
async def autopilot_run_all(user: UserContext = Depends(require_roles("admin", "analyst"))) -> dict:
    run_id = automation_service.create_pipeline_run()
    asyncio.create_task(automation_service.run_full_pipeline(run_id))
    return {"run_id": run_id}


@app.get("/api/autopilot/status/{run_id}")
async def autopilot_status(run_id: str, user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))) -> dict:
    payload = automation_service.pipeline_status(run_id)
    if not payload:
        raise HTTPException(404, "Pipeline run not found")
    return payload


@app.get("/api/autopilot/last-run")
async def autopilot_last_run(user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))) -> dict:
    payload = automation_service.last_pipeline_run()
    if not payload:
        raise HTTPException(404, "No pipeline runs yet")
    return payload


@app.post("/api/autopilot/run-task/{task_name}", status_code=202)
async def autopilot_run_task(task_name: str, user: UserContext = Depends(require_roles("admin", "analyst"))) -> dict:
    run_id = automation_service.create_pipeline_run(task_name)
    asyncio.create_task(automation_service.run_full_pipeline(run_id, single_task=task_name))
    return {"run_id": run_id}


@app.post("/api/autopilot/schedule")
async def autopilot_schedule(body: AutoScheduleRequest, user: UserContext = Depends(require_roles("admin", "analyst"))) -> dict:
    config = await scheduler_service.configure(body.enabled, body.interval_hours)
    return {"enabled": config["enabled"], "interval_hours": config["interval_hours"], "next_run": config["next_run"]}


@app.get("/api/autopilot/schedule")
async def autopilot_get_schedule(user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))) -> dict:
    config = scheduler_service.load()
    return config


@app.post("/api/intelligence/unified-scan")
async def intelligence_unified_scan(
    body: UnifiedScanRequest,
    user: UserContext = Depends(require_roles("admin", "analyst", "viewer")),
) -> dict:
    return await automation_service.unified_scan(
        body.target,
        body.targetType,
        context=body.context,
        user_id=user.username,
        engines=body.engines or None,
    )


@app.post("/api/intelligence/system-scan", status_code=202)
async def intelligence_system_scan(user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))) -> dict:
    session_id = await automation_service.start_system_scan(user.username)
    return {"session_id": session_id, "status": "running"}


@app.get("/api/intelligence/last-session")
async def intelligence_last_session(user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))) -> dict:
    session = automation_service.last_intelligence_session(user.username)
    if not session:
        raise HTTPException(404, "No intelligence session found")
    return session


@app.post("/api/device/scan", status_code=202)
async def device_scan_start(user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))) -> dict:
    session_id = await automation_service.start_device_scan(user.username, "manual")
    return {"sessionId": session_id, "status": "started", "message": "Device scan initiated"}


@app.get("/api/device/scan/latest")
async def device_scan_latest(user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))) -> dict:
    session = automation_service.last_device_session(user.username)
    if not session:
        raise HTTPException(404, "No device scan session found")
    sid = session["id"]
    return {
        **session,
        "connections": automation_service.device_list_connections(sid, page=1, limit=500)["items"],
        "processes": automation_service.device_list_processes(sid, page=1, limit=500)["items"],
        "ports": automation_service.device_list_ports(sid, page=1, limit=500)["items"],
        "software": automation_service.device_list_software(sid, page=1, limit=500)["items"],
        "startup": automation_service.device_list_startup(sid, page=1, limit=500)["items"],
    }


@app.get("/api/device/scan/history")
async def device_scan_history(user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))) -> List[Dict[str, Any]]:
    return automation_service.device_scan_history(30)


@app.get("/api/device/scan/{session_id}/connections")
async def device_scan_connections(
    session_id: str,
    page: int = 1,
    limit: int = 20,
    is_flagged: Optional[bool] = None,
    verdict: Optional[str] = None,
    process_name: Optional[str] = None,
    user: UserContext = Depends(require_roles("admin", "analyst", "viewer")),
) -> dict:
    filters: Dict[str, Any] = {}
    if is_flagged is not None:
        filters["is_flagged"] = is_flagged
    if verdict:
        filters["verdict"] = verdict
    if process_name:
        filters["process_name"] = process_name
    return automation_service.device_list_connections(session_id, page=page, limit=min(limit, 100), filters=filters)


@app.get("/api/device/scan/{session_id}/processes")
async def device_scan_processes(
    session_id: str,
    page: int = 1,
    limit: int = 20,
    is_flagged: Optional[bool] = None,
    verdict: Optional[str] = None,
    user: UserContext = Depends(require_roles("admin", "analyst", "viewer")),
) -> dict:
    filters: Dict[str, Any] = {}
    if is_flagged is not None:
        filters["is_flagged"] = is_flagged
    if verdict:
        filters["verdict"] = verdict
    return automation_service.device_list_processes(session_id, page=page, limit=min(limit, 100), filters=filters)


@app.get("/api/device/scan/{session_id}/ports")
async def device_scan_ports(
    session_id: str,
    page: int = 1,
    limit: int = 20,
    is_flagged: Optional[bool] = None,
    user: UserContext = Depends(require_roles("admin", "analyst", "viewer")),
) -> dict:
    filters: Dict[str, Any] = {}
    if is_flagged is not None:
        filters["is_flagged"] = is_flagged
    return automation_service.device_list_ports(session_id, page=page, limit=min(limit, 100), filters=filters)


@app.get("/api/device/scan/{session_id}/software")
async def device_scan_software(
    session_id: str,
    page: int = 1,
    limit: int = 20,
    user: UserContext = Depends(require_roles("admin", "analyst", "viewer")),
) -> dict:
    return automation_service.device_list_software(session_id, page=page, limit=min(limit, 100))


@app.get("/api/device/scan/{session_id}/startup")
async def device_scan_startup(
    session_id: str,
    page: int = 1,
    limit: int = 20,
    is_flagged: Optional[bool] = None,
    verdict: Optional[str] = None,
    user: UserContext = Depends(require_roles("admin", "analyst", "viewer")),
) -> dict:
    filters: Dict[str, Any] = {}
    if is_flagged is not None:
        filters["is_flagged"] = is_flagged
    if verdict:
        filters["verdict"] = verdict
    return automation_service.device_list_startup(session_id, page=page, limit=min(limit, 100), filters=filters)


@app.get("/api/device/test")
async def device_test(user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))) -> dict:
    """Sanity check: built-in OS facts without shell collectors."""
    from .device_scan_agent import get_builtin_system_info

    info = get_builtin_system_info()
    ram_gb = info.get("ram_total_gb")
    return {
        "hostname": info.get("hostname"),
        "platform": info.get("platform"),
        "user": info.get("current_user"),
        "ram": int(ram_gb * 1024**3) if ram_gb else None,
    }


@app.get("/api/device/sysinfo")
async def device_sysinfo(user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))) -> dict:
    return automation_service.device_sysinfo(user.username)


@app.post("/api/device/process/kill")
async def device_process_kill(body: DeviceKillRequest, user: UserContext = Depends(require_roles("admin"))) -> dict:
    from .device_scan_agent import run_exec, validate_kill_pid

    if not validate_kill_pid(body.pid):
        raise HTTPException(400, "pid must be a positive integer below 1000000")
    import sys

    if sys.platform == "win32":
        code, out, err = await asyncio.to_thread(run_exec, "taskkill", ["/PID", str(body.pid), "/F"])
    else:
        code, out, err = await asyncio.to_thread(run_exec, "kill", ["-9", str(body.pid)])
    case_store.audit(user.username, user.role, "kill_process", "host", str(body.pid), {"session_id": body.sessionId})
    if code != 0:
        raise HTTPException(500, err or out or "Failed to terminate process")
    return {"success": True, "message": f"Process {body.pid} terminated"}


@app.post("/api/device/ip/block")
async def device_ip_block(body: DeviceBlockRequest, user: UserContext = Depends(require_roles("admin"))) -> dict:
    from .device_scan_agent import run_exec, validate_ipv4_block

    if not validate_ipv4_block(body.ip):
        raise HTTPException(400, "ip must be a valid IPv4 address")
    import sys

    if sys.platform == "win32":
        rule = f"CRIE-Block-{body.ip.replace('.', '-')}"
        code, out, err = await asyncio.to_thread(
            run_exec,
            "netsh",
            ["advfirewall", "firewall", "add", "rule", f"name={rule}", "dir=out", "action=block", f"remoteip={body.ip}"],
        )
    else:
        code, out, err = await asyncio.to_thread(run_exec, "iptables", ["-A", "OUTPUT", "-d", body.ip, "-j", "DROP"])
    case_store.audit(user.username, user.role, "block_ip", "host", body.ip, {"reason": body.reason})
    if code != 0:
        raise HTTPException(500, err or out or "Failed to block IP")
    return {"success": True, "message": f"Outbound traffic to {body.ip} blocked"}


@app.post("/api/device/scan/schedule")
async def device_scan_schedule(body: DeviceScheduleRequest, user: UserContext = Depends(require_roles("admin", "analyst"))) -> dict:
    config = await configure_device_scan_schedule(body.enabled, body.intervalMinutes)
    case_store.audit(user.username, user.role, "device_scan_schedule", "settings", meta=config)
    return config


@app.get("/api/device/scan/schedule")
async def device_scan_schedule_get(user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))) -> dict:
    return automation_service.get_setting("device_scan_schedule", {"enabled": False, "intervalMinutes": 360, "next_run": None})


@app.post("/api/device/software/sync", status_code=202)
async def device_software_sync(user: UserContext = Depends(require_roles("admin", "analyst"))) -> dict:
    from .device_scan_agent import run_device_scan_software_only

    result = await run_device_scan_software_only(automation_service, user.username)
    return {"status": "complete", **result}


@app.get("/api/assets")
@app.get("/api/aria/assets")
async def aria_get_assets(user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))):
    return automation_service.list_assets()


@app.post("/api/assets")
@app.post("/api/aria/assets")
async def aria_add_asset(body: AutoAssetRequest, user: UserContext = Depends(require_roles("admin", "analyst"))):
    if body.type not in ("domain", "ip", "url", "email"):
        raise HTTPException(400, "type must be domain | ip | url | email")
    asset_id = automation_service.add_asset(body.name.strip() or body.value.strip(), body.type, body.value.strip())
    asset = automation_service.get_asset(asset_id)
    if asset:
        asyncio.create_task(automation_service.scan_asset(asset))
    return {"id": asset_id, "status": "added", "message": "Asset added - scanning now"}


@app.delete("/api/assets/{aid}")
@app.delete("/api/aria/assets/{aid}")
async def aria_delete_asset(aid: int, user: UserContext = Depends(require_roles("admin", "analyst"))):
    automation_service.delete_asset(aid)
    return {"status": "removed"}


@app.post("/api/aria/assets/{aid}/scan")
async def aria_scan_now(aid: int, user: UserContext = Depends(require_roles("admin", "analyst"))):
    asset = automation_service.get_asset(aid)
    if not asset:
        raise HTTPException(404, "Asset not found")
    asyncio.create_task(automation_service.scan_asset(asset))
    return {"status": "scanning", "message": "Scan started"}


@app.post("/api/aria/monitoring/run")
async def aria_run_monitoring_cycle(user: UserContext = Depends(require_roles("admin", "analyst"))):
    result = await automation_service.run_aria_monitoring_cycle(rescan_all=True)
    return {"status": "ok", **result, "triggered_at": datetime.utcnow().isoformat() + "Z"}


@app.get("/api/aria/assets/{aid}/history")
async def aria_asset_history(aid: int, user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))):
    return automation_service.asset_history(aid)


@app.get("/api/aria/assets/{aid}/summary")
async def aria_asset_summary(aid: int, user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))):
    asset = automation_service.get_asset(aid)
    if not asset:
        raise HTTPException(404, "Asset not found")
    history = automation_service.asset_history(aid, limit=5)
    return {"summary": f"{asset['label']} is currently {str(asset.get('risk_level', 'unscanned')).upper()} with score {asset['risk_score'] or 0}. {len(history)} snapshots recorded."}


@app.post("/api/alerts/generate-from-scan")
async def alerts_generate_from_scan(user: UserContext = Depends(require_roles("admin", "analyst"))):
    result = await automation_service.run_aria_monitoring_cycle(rescan_all=True)
    return {"generated": sum(1 for item in result["results"] if item.get("alert")), "details": result}


@app.get("/api/alerts")
@app.get("/api/aria/alerts")
async def aria_get_alerts(user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))):
    return automation_service.list_alerts()


@app.post("/api/aria/alerts/{aid}/seen")
async def aria_mark_seen(aid: int, user: UserContext = Depends(require_roles("admin", "analyst"))):
    automation_service.mark_alert_seen(aid)
    return {"status": "ok"}


@app.post("/api/aria/alerts/seen-all")
async def aria_mark_all_seen(user: UserContext = Depends(require_roles("admin", "analyst"))):
    automation_service.mark_all_alerts_seen()
    return {"status": "ok"}


@app.post("/api/cases/auto-create-from-alerts")
async def cases_auto_create(user: UserContext = Depends(require_roles("admin", "analyst"))):
    created = 0
    for alert in automation_service.list_alerts(500):
        if alert["severity"] in {"CRITICAL", "HIGH"} and not alert.get("case_id"):
            if automation_service.auto_create_case_for_alert(alert):
                created += 1
    return {"cases_created": created}


@app.get("/api/reports")
@app.get("/api/aria/reports")
async def aria_get_reports(user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))):
    return automation_service.list_reports()


@app.get("/api/reports/{rid}")
@app.get("/api/aria/reports/{rid}")
async def aria_get_report(rid: int, user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))):
    report = automation_service.get_report(rid)
    if not report:
        raise HTTPException(404, "Report not found")
    return report


@app.post("/api/reports/generate")
@app.post("/api/aria/reports/generate")
async def aria_generate_report(user: UserContext = Depends(require_roles("admin", "analyst"))):
    report = await automation_service.generate_daily_report()
    return {"id": report["report_id"], "status": "ok"}


@app.post("/api/analyze/text")
async def analyze_text_auto(payload: AnalyzeRequest, user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))):
    return await automation_service.analyze_text(payload.text, source="manual_text")


@app.post("/api/analyze/auto-scan-all")
async def analyze_auto_scan_all(user: UserContext = Depends(require_roles("admin", "analyst"))):
    return await automation_service.auto_scan_all_cases()


@app.post("/api/threat-intel/auto-pull")
async def threat_intel_auto_pull(user: UserContext = Depends(require_roles("admin", "analyst"))):
    return await automation_service.auto_pull_iocs()


@app.get("/api/threat-intel/iocs")
async def threat_intel_iocs(
    page: int = 1,
    limit: int = 50,
    type: Optional[str] = None,
    source: Optional[str] = None,
    min_confidence: float = 0,
    search: Optional[str] = None,
    user: UserContext = Depends(require_roles("admin", "analyst", "viewer")),
):
    return automation_service.list_iocs(page=page, limit=limit, ioc_type=type, source=source, min_confidence=min_confidence, search=search)


@app.get("/api/threat-intel/iocs/summary")
async def threat_intel_iocs_summary(user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))):
    return automation_service.ioc_summary()


@app.post("/api/website-intel/auto-scan")
async def website_intel_auto_scan(user: UserContext = Depends(require_roles("admin", "analyst"))):
    return await automation_service.auto_scan_domains()


@app.get("/api/website-intel/recent-scans")
async def website_intel_recent_scans(user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))):
    return automation_service.recent_website_scans()


@app.get("/api/malware/auto-check-ioc-hashes")
@app.post("/api/malware/auto-check-ioc-hashes")
async def malware_auto_check(user: UserContext = Depends(require_roles("admin", "analyst"))):
    return await automation_service.auto_check_hashes()


@app.get("/api/malware/recent-files")
async def malware_recent_files(user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))):
    return automation_service.recent_files()


@app.post("/api/fusion-scan/auto")
async def fusion_scan_auto(user: UserContext = Depends(require_roles("admin", "analyst"))):
    return await automation_service.auto_fusion()


@app.post("/api/aria/chat")
async def aria_chat(body: AriaChatRequest, user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))):
    stats = automation_service.aria_stats()
    assets = automation_service.list_assets()
    top_asset = max(assets, key=lambda item: item["risk_score"] or 0) if assets else None
    feed_summary = automation_service.feed_summary()
    device_session = automation_service.last_device_session(user.username)
    device_summary: Dict[str, Any] = {}
    flagged_connections: List[Dict[str, Any]] = []
    flagged_processes: List[Dict[str, Any]] = []
    if device_session:
        sid = device_session["id"]
        device_summary = {
            "risk_score": device_session.get("overall_risk_score"),
            "hostname": device_session.get("hostname"),
            "connections_flagged": device_session.get("connections_flagged"),
            "processes_flagged": device_session.get("processes_flagged"),
            "completed_at": device_session.get("completed_at"),
        }
        flagged_connections = automation_service.device_list_connections(
            sid, page=1, limit=10, filters={"is_flagged": True}
        )["items"]
        flagged_processes = automation_service.device_list_processes(
            sid, page=1, limit=10, filters={"is_flagged": True}
        )["items"]
    prompt = body.message or (body.messages[-1]["content"] if body.messages else "")
    reply = (
        f"Assets monitored: {stats['assets_monitored']}. "
        f"Unseen alerts: {stats['unseen_alerts']}. "
        f"Highest risk asset: {top_asset['label']} ({top_asset['risk_score']})"
        if top_asset
        else "No assets have been scored yet."
    )
    if device_summary:
        reply = (
            f"{reply} Device risk score: {device_summary.get('risk_score', 0)}/100 on "
            f"{device_summary.get('hostname') or 'this host'}. "
            f"Flagged connections: {device_summary.get('connections_flagged', 0)}, "
            f"flagged processes: {device_summary.get('processes_flagged', 0)}."
        )
    low = (prompt or "").lower()
    if "suspicious ip" in low or "connecting" in low:
        if flagged_connections:
            bits = [
                f"{row.get('process_name')} → {row.get('remote_ip')} ({row.get('verdict')})"
                for row in flagged_connections[:8]
            ]
            reply = f"Flagged connections: {'; '.join(bits)}"
        else:
            reply = "No flagged outbound connections in the latest device scan."
    elif "device safe" in low or "is my device" in low:
        score = int(device_summary.get("risk_score") or 0)
        verdict = "SECURE" if score < 30 else "AT RISK" if score < 70 else "COMPROMISED"
        reply = f"Latest device posture: {verdict} (risk {score}/100)."
    elif "high risk" in low and "score" in low:
        factors = []
        if device_summary.get("connections_flagged"):
            factors.append(f"{device_summary['connections_flagged']} flagged network connections")
        if device_summary.get("processes_flagged"):
            factors.append(f"{device_summary['processes_flagged']} suspicious processes")
        reply = f"Top risk drivers: {', '.join(factors) or 'no major flagged categories in the last scan'}."
    elif prompt:
        reply = f"{reply}. Analyst question: {prompt}. Feed health: {feed_summary['auth_valid']}/{feed_summary['total']} authenticated."
    return {
        "reply": reply,
        "response": reply,
        "device_context": {
            "summary": device_summary,
            "flagged_connections": flagged_connections,
            "flagged_processes": flagged_processes,
        },
    }


@app.get("/api/aria/stats")
async def aria_stats(user: UserContext = Depends(require_roles("admin", "analyst", "viewer"))):
    return automation_service.aria_stats()


@app.get("/api/admin/metrics")
async def admin_metrics(user: UserContext = Depends(require_roles("admin"))):
    return automation_service.admin_metrics()


@app.get("/analyze", include_in_schema=False)
@app.get("/threat-intel", include_in_schema=False)
@app.get("/website-intel", include_in_schema=False)
@app.get("/malware", include_in_schema=False)
@app.get("/fusion-scan", include_in_schema=False)
async def legacy_intelligence_redirect():
    return RedirectResponse(url="/intelligence", status_code=301)


@app.get("/{full_path:path}")
async def catch_all(full_path: str):
    # Let API and docs routes continue to resolve normally.
    if any(full_path.startswith(p) for p in ("api/", "docs", "redoc", "openapi")):
        raise HTTPException(status_code=404)
    index = _DIST / "index.html"
    if index.exists():
        return FileResponse(str(index))
    raise HTTPException(status_code=404)
