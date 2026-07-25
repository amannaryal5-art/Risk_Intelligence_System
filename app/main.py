from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import socket
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .cyber_fusion import CyberFusionEngine
from .risk_engine import RiskEngine
from .scamcheck import ScamCheckCacheStore, ScamCheckService
from .threat_intel import ThreatIntelEngine

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("RISKINTEL_DATA_DIR", BASE_DIR / "data" if not os.getenv("VERCEL") else Path(tempfile.gettempdir()) / "riskintel"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
logger = logging.getLogger("riskintel")


def load_env(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip("\"'") )


load_env(BASE_DIR.parent / ".env")
for legacy, canonical in {
    "OTX_API_KEY": "RISKINTEL_OTX_API_KEY",
    "ABUSEIPDB_API_KEY": "RISKINTEL_ABUSEIPDB_API_KEY",
    "VIRUSTOTAL_API_KEY": "RISKINTEL_VT_API_KEY",
    "URLSCAN_API_KEY": "RISKINTEL_URLSCAN_API_KEY",
}.items():
    if os.getenv(legacy) and not os.getenv(canonical):
        os.environ[canonical] = os.environ[legacy]

engine = RiskEngine()
intel = ThreatIntelEngine()
fusion = CyberFusionEngine(engine)
scamcheck = ScamCheckService(intel, engine, ScamCheckCacheStore(DATA_DIR / "riskintel_cache.db"))
API_KEY = os.getenv("RISKINTEL_API_KEY") or os.getenv("RISKINTEL_DEFAULT_API_KEY", "")
LIVE_FEEDS = os.getenv("RISKINTEL_USE_LIVE_FEEDS", "true").lower() == "true"

app = FastAPI(title="Risk Intelligence System", version="1.0.0", description="Analyze URLs, IPs, hashes, files, and suspicious text.")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled error on %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


class AnalyzeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20_000)


class ThreatIntelRequest(BaseModel):
    text: Optional[str] = None
    urls: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)
    live_feeds: Optional[bool] = None


class ScamCheckRequest(BaseModel):
    input: str = Field(min_length=1, max_length=8_000)
    detectedType: str = Field(default="text", max_length=24)


class WebsiteRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2_000)


class TraceRequest(WebsiteRequest):
    max_pages: int = Field(default=40, ge=1, le=100)
    max_depth: int = Field(default=2, ge=0, le=4)
    include_external: bool = False


class FusionRequest(BaseModel):
    text: Optional[str] = None
    website_url: Optional[str] = None
    max_pages: int = Field(default=40, ge=1, le=100)
    max_depth: int = Field(default=2, ge=0, le=4)


class FileRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=300)
    content_base64: str = Field(min_length=1)


def level(score: int) -> str:
    return "critical" if score >= 80 else "high" if score >= 55 else "medium" if score >= 30 else "low"


def website_result(url: str) -> dict[str, Any]:
    parsed = urlsplit(url if "://" in url else f"https://{url}")
    domain = (parsed.hostname or "").lower()
    if not domain or "." not in domain:
        raise ValueError("Provide a valid URL or domain")
    try:
        ip = socket.gethostbyname(domain)
    except OSError:
        ip = ""
    otx = intel._lookup_otx("domain", domain)
    vt = intel._lookup_virustotal("url", url)
    abuse = intel._lookup_abuseipdb("ip", ip) if ip else {}
    score = min(100, (40 if int(vt.get("malicious_votes", 0)) > 5 else 20 if int(vt.get("malicious_votes", 0)) else 0) + (30 if int(abuse.get("abuse_confidence", 0)) > 50 else 15 if int(abuse.get("abuse_confidence", 0)) >= 10 else 0) + (20 if int(otx.get("pulse_count", 0)) > 2 else 10 if int(otx.get("pulse_count", 0)) else 0))
    return {"input": url, "domain": domain, "ip": ip, "risk_score": score, "risk_level": level(score), "feeds": {"otx": otx, "virustotal": vt, "abuseipdb": abuse}, "scanned_at": datetime.now(timezone.utc).isoformat()}


@app.get("/")
async def root() -> dict[str, str]:
    return {"service": "risk-intelligence-system", "docs": "/docs"}


@app.get("/api/v1/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/analyze", dependencies=[Depends(require_api_key)])
async def analyze(payload: AnalyzeRequest) -> dict[str, Any]:
    local, ioc_intelligence = await asyncio.gather(engine.analyze_async(payload.text), intel.scan_async(text=payload.text, live_feeds=LIVE_FEEDS))
    local["ioc_intelligence"] = ioc_intelligence
    return local


@app.post("/api/v1/threat-intel", dependencies=[Depends(require_api_key)])
async def threat_intel(payload: ThreatIntelRequest) -> dict[str, Any]:
    return await intel.scan_async(text=payload.text, urls=payload.urls, domains=payload.domains, ips=payload.ips, hashes=payload.hashes, live_feeds=LIVE_FEEDS if payload.live_feeds is None else payload.live_feeds)


@app.post("/api/v1/scamcheck", dependencies=[Depends(require_api_key)])
async def check_scam(payload: ScamCheckRequest) -> dict[str, Any]:
    return await scamcheck.check_async(payload.input, payload.detectedType)


@app.post("/api/v1/website-intel", dependencies=[Depends(require_api_key)])
async def website_intel(payload: WebsiteRequest) -> dict[str, Any]:
    try:
        return await asyncio.get_running_loop().run_in_executor(engine._executor, lambda: website_result(payload.url))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/trace-website", dependencies=[Depends(require_api_key)])
async def trace_website(payload: TraceRequest) -> dict[str, Any]:
    try:
        return await asyncio.get_running_loop().run_in_executor(engine._executor, lambda: engine.trace_website(payload.url, max_pages=payload.max_pages, max_depth=payload.max_depth, include_external=payload.include_external, exhaustive=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/fusion-scan", dependencies=[Depends(require_api_key)])
async def fusion_scan(payload: FusionRequest) -> dict[str, Any]:
    if not (payload.text or payload.website_url):
        raise HTTPException(status_code=400, detail="Provide text or website_url")
    result = await fusion.fusion_scan_async(text=payload.text, website_url=payload.website_url, max_pages=payload.max_pages, max_depth=payload.max_depth)
    if payload.text:
        result["ioc_intelligence"] = await intel.scan_async(text=payload.text, live_feeds=LIVE_FEEDS)
    return result


@app.post("/api/v1/malware/analyze-file", dependencies=[Depends(require_api_key)])
async def analyze_file(payload: FileRequest) -> dict[str, Any]:
    try:
        blob = base64.b64decode(payload.content_base64, validate=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="content_base64 must be valid base64") from exc
    flags: list[str] = []
    sample = blob[:200_000].lower()
    score = 0
    for condition, points, description in [(payload.filename.lower().endswith((".exe", ".dll", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".hta")), 35, "Executable or script extension"), (blob.startswith(b"MZ"), 28, "PE executable header"), (b"powershell" in sample or b"cmd.exe" in sample, 18, "Command execution string"), (b"autoopen" in sample or b"document_open" in sample, 22, "Macro auto-execution pattern"), (b"createobject" in sample or b"wscript.shell" in sample, 20, "Script execution API")]:
        if condition:
            score += points; flags.append(description)
    sha256 = hashlib.sha256(blob).hexdigest()
    return {"filename": payload.filename, "size_bytes": len(blob), "sha256": sha256, "risk_score": min(score, 100), "risk_level": level(min(score, 100)), "suspicious_signals": flags, "ioc_intelligence": await intel.scan_async(hashes=[sha256], live_feeds=LIVE_FEEDS)}
