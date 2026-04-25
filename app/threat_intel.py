from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import threading
import httpx

logger = logging.getLogger("riskintel.threat_intel")


# ─────────────────────────────────────────────
# Thread-safe TTL cache (shared with risk engine)
# ─────────────────────────────────────────────
class TTLCache:
    def __init__(self, maxsize: int = 4096, ttl: float = 3600.0) -> None:
        self._store: Dict[str, tuple] = {}
        self._lock = threading.Lock()
        self._maxsize = maxsize
        self._ttl = ttl

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, ts = entry
            if time.monotonic() - ts > self._ttl:
                del self._store[key]
                return None
            return value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            if len(self._store) >= self._maxsize:
                oldest = sorted(self._store.items(), key=lambda x: x[1][1])[:self._maxsize // 10]
                for k, _ in oldest:
                    del self._store[k]
            self._store[key] = (value, time.monotonic())

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        return len(self._store)


@dataclass(frozen=True)
class IOC:
    ioc_type: str
    value: str


# ─────────────────────────────────────────────
# Rate limiter: prevent API key exhaustion
# ─────────────────────────────────────────────
class RateLimiter:
    """Simple token-bucket rate limiter per provider key."""

    def __init__(self, calls_per_minute: int = 60) -> None:
        self._calls_per_minute = calls_per_minute
        self._min_interval = 60.0 / max(calls_per_minute, 1)
        self._last_call: float = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            if elapsed < self._min_interval:
                time.sleep(self._min_interval - elapsed)
            self._last_call = time.monotonic()


class ThreatIntelEngine:
    """
    IOC enrichment engine with optional live feed lookups.
    v3: async-ready, parallel enrichment, rate limiting, extended IOC types.
    """

    def __init__(self) -> None:
        self.otx_key = os.getenv("RISKINTEL_OTX_API_KEY", "").strip()
        self.abuseipdb_key = os.getenv("RISKINTEL_ABUSEIPDB_API_KEY", "").strip()
        self.vt_key = os.getenv("RISKINTEL_VT_API_KEY", "").strip()
        self.shodan_key = os.getenv("RISKINTEL_SHODAN_API_KEY", "").strip()
        self.urlscan_key = os.getenv("RISKINTEL_URLSCAN_API_KEY", "").strip()

        # Per-provider rate limiters
        self._rl_otx = RateLimiter(calls_per_minute=60)
        self._rl_abuseipdb = RateLimiter(calls_per_minute=30)
        self._rl_vt = RateLimiter(calls_per_minute=4)   # VT free = 4 req/min
        self._rl_shodan = RateLimiter(calls_per_minute=18)
        self._rl_urlscan = RateLimiter(calls_per_minute=20)

        # Shared TTL cache: keyed by ioc_type:value:live
        self._cache = TTLCache(maxsize=8192, ttl=6 * 3600)

        # Thread pool for parallel provider calls
        self._executor = ThreadPoolExecutor(max_workers=12, thread_name_prefix="threat-intel")

        # Regex patterns
        self._re_url = re.compile(r"(?:(?:https?|ftp)://|www\.)[^\s<>'\"()]+", re.IGNORECASE)
        self._re_ip = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        self._re_ipv6 = re.compile(r"\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b")
        self._re_domain = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b")
        self._re_md5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
        self._re_sha1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
        self._re_sha256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
        self._re_email = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
        self._re_cve = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

        self.suspicious_tlds = {
            "zip", "mov", "top", "gq", "tk", "work", "click", "cam", "rest",
            "country", "stream", "xyz", "pw", "cc",
        }
        self._risk_url_terms = {"login", "verify", "secure", "update", "wallet", "payment", "signin", "confirm"}

    # ──────────────────────────────────────────
    # Provider availability
    # ──────────────────────────────────────────
    @property
    def live_feeds_available(self) -> bool:
        return bool(self.otx_key or self.abuseipdb_key or self.vt_key or self.shodan_key or self.urlscan_key)

    @property
    def live_feed_status(self) -> Dict[str, Dict[str, bool]]:
        status = self.build_live_feed_status(probe=False)
        return {k: {"configured": bool(v["configured"])} for k, v in status["providers"].items()}

    # ──────────────────────────────────────────
    # HTTP helper
    # ──────────────────────────────────────────
    @staticmethod
    def _probe_http(url: str, headers: Dict[str, str], timeout: float = 4.0) -> Dict[str, Any]:
        started = time.perf_counter()
        req = Request(url, headers=headers)
        try:
            with urlopen(req, timeout=timeout) as resp:
                _ = resp.read(256)
                code = int(getattr(resp, "status", 200) or 200)
            return {"reachable": True, "auth_valid": 200 <= code < 300, "latency_ms": int((time.perf_counter() - started) * 1000), "status_code": code}
        except HTTPError as exc:
            code = int(getattr(exc, "code", 0) or 0)
            return {"reachable": True, "auth_valid": code not in {401, 403}, "latency_ms": int((time.perf_counter() - started) * 1000), "status_code": code, "error": f"HTTP {code}"}
        except Exception as exc:
            return {"reachable": False, "auth_valid": None, "latency_ms": int((time.perf_counter() - started) * 1000), "status_code": None, "error": str(exc)[:220]}

    def build_live_feed_status(self, probe: bool = False) -> Dict[str, Any]:
        now = self._now_iso()
        providers: Dict[str, Dict[str, Any]] = {
            "otx": {"name": "AlienVault OTX", "configured": bool(self.otx_key), "reachable": None, "auth_valid": None, "latency_ms": None, "status_code": None, "error": None, "last_checked": now},
            "abuseipdb": {"name": "AbuseIPDB", "configured": bool(self.abuseipdb_key), "reachable": None, "auth_valid": None, "latency_ms": None, "status_code": None, "error": None, "last_checked": now},
            "virustotal": {"name": "VirusTotal", "configured": bool(self.vt_key), "reachable": None, "auth_valid": None, "latency_ms": None, "status_code": None, "error": None, "last_checked": now},
            "shodan": {"name": "Shodan", "configured": bool(self.shodan_key), "reachable": None, "auth_valid": None, "latency_ms": None, "status_code": None, "error": None, "last_checked": now},
            "urlscan": {"name": "URLScan.io", "configured": bool(self.urlscan_key), "reachable": None, "auth_valid": None, "latency_ms": None, "status_code": None, "error": None, "last_checked": now},
        }
        if probe:
            probe_map = {
                "otx": (bool(self.otx_key), "https://otx.alienvault.com/api/v1/user/me", {"X-OTX-API-KEY": self.otx_key, "User-Agent": "RiskIntel/3.0"}),
                "abuseipdb": (bool(self.abuseipdb_key), "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=30", {"Key": self.abuseipdb_key, "Accept": "application/json", "User-Agent": "RiskIntel/3.0"}),
                "virustotal": (bool(self.vt_key), "https://www.virustotal.com/api/v3/users/current", {"x-apikey": self.vt_key, "User-Agent": "RiskIntel/3.0"}),
                "shodan": (bool(self.shodan_key), f"https://api.shodan.io/api-info?key={self.shodan_key}", {"User-Agent": "RiskIntel/3.0"}),
                "urlscan": (bool(self.urlscan_key), "https://urlscan.io/user/", {"API-Key": self.urlscan_key, "User-Agent": "RiskIntel/3.0"}),
            }
            futures = {}
            with ThreadPoolExecutor(max_workers=5) as pool:
                for name, (configured, url, headers) in probe_map.items():
                    if configured:
                        futures[name] = pool.submit(self._probe_http, url, headers)
            for name, fut in futures.items():
                try:
                    providers[name].update(fut.result(timeout=8))
                except Exception:
                    pass

        configured = sum(1 for p in providers.values() if p["configured"])
        reachable = sum(1 for p in providers.values() if p["reachable"] is True)
        auth_valid = sum(1 for p in providers.values() if p["auth_valid"] is True)
        return {
            "generated_at": now,
            "probe_performed": bool(probe),
            "providers": providers,
            "summary": {"configured": configured, "reachable": reachable, "auth_valid": auth_valid, "total": len(providers)},
        }

    # ──────────────────────────────────────────
    # HTTP JSON fetch
    # ──────────────────────────────────────────
    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _http_json(self, url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 4.0) -> Dict[str, Any]:
        req = Request(url, headers=headers or {"User-Agent": "RiskIntel/3.0"})
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read(400000).decode("utf-8", errors="ignore"))

    def _cache_get(self, key: str) -> Optional[Dict[str, Any]]:
        return self._cache.get(key)

    def _cache_set(self, key: str, data: Dict[str, Any]) -> None:
        self._cache.set(key, data)

    # ──────────────────────────────────────────
    # IOC extraction (extended: CVE, SHA1, IPv6, email)
    # ──────────────────────────────────────────
    def _extract_iocs(self, text: str) -> List[IOC]:
        if not text.strip():
            return []
        found: List[IOC] = []
        seen: Set[str] = set()

        def add(ioc_type: str, value: str) -> None:
            key = f"{ioc_type}::{value.lower()}"
            if key not in seen:
                seen.add(key)
                found.append(IOC(ioc_type, value))

        for url in [x.strip(".,);]}>\"'") for x in self._re_url.findall(text)]:
            if not url:
                continue
            add("url", url)
            host = (urlsplit(url if "://" in url else f"http://{url}").hostname or "").lower()
            if host:
                add("domain", host)

        for ip in self._re_ip.findall(text):
            add("ip", ip)
        for ip6 in self._re_ipv6.findall(text):
            add("ipv6", ip6)
        for d in self._re_domain.findall(text):
            low = d.lower().lstrip("www.")
            add("domain", low)
        for h in self._re_sha256.findall(text):
            add("hash_sha256", h.lower())
        for h in self._re_sha1.findall(text):
            add("hash_sha1", h.lower())
        for h in self._re_md5.findall(text):
            add("hash_md5", h.lower())
        for email in self._re_email.findall(text):
            add("email", email.lower())
        for cve in self._re_cve.findall(text):
            add("cve", cve.upper())

        return found[:60]

    # ──────────────────────────────────────────
    # Heuristic scoring
    # ──────────────────────────────────────────
    def _heuristic_ioc_score(self, ioc_type: str, value: str) -> Dict[str, Any]:
        score = 8
        flags: List[str] = []

        if ioc_type == "domain":
            parts = value.lower().split(".")
            tld = parts[-1] if parts else ""
            label = parts[-2] if len(parts) >= 2 else value
            if tld in self.suspicious_tlds:
                score += 35; flags.append(f"Suspicious TLD .{tld}")
            if len(parts) >= 3:
                score += 8; flags.append("Deep subdomain pattern")
            if sum(ch.isdigit() for ch in label) >= 3:
                score += 12; flags.append("Numeric-heavy domain label")
            if "-" in label:
                score += 8; flags.append("Hyphenated label")

        elif ioc_type == "ip":
            try:
                ip_obj = ipaddress.ip_address(value)
                if ip_obj.is_private or ip_obj.is_loopback:
                    score += 15; flags.append("Private/local IP")
                else:
                    score += 10; flags.append("Public external IP")
            except ValueError:
                score += 20; flags.append("Malformed IP")

        elif ioc_type == "url":
            parsed = urlsplit(value if "://" in value else f"http://{value}")
            if parsed.scheme == "http":
                score += 18; flags.append("Unencrypted HTTP")
            for term in self._risk_url_terms:
                if term in value.lower():
                    score += 6; flags.append(f"Risk term: {term}")

        elif ioc_type.startswith("hash_"):
            score += 12; flags.append("File hash IOC")

        elif ioc_type == "email":
            score += 5; flags.append("Email address IOC")

        elif ioc_type == "cve":
            score += 20; flags.append("CVE identifier present")

        return {"score": min(95, max(0, score)), "flags": flags[:8],
                "reputation": ("malicious" if score >= 75 else ("suspicious" if score >= 45 else ("clean" if score >= 20 else "unknown")))}

    # ──────────────────────────────────────────
    # Live feed lookups (with rate limiting)
    # ──────────────────────────────────────────
    def _lookup_otx(self, ioc_type: str, value: str) -> Dict[str, Any]:
        if not self.otx_key:
            return {"enabled": False, "listed": False, "pulse_count": 0, "source": "otx"}
        otx_type_map = {"domain": "domain", "ip": "IPv4", "url": "url", "hash_md5": "file", "hash_sha256": "file"}
        otx_type = otx_type_map.get(ioc_type)
        if not otx_type:
            return {"enabled": True, "listed": False, "pulse_count": 0, "source": "otx"}
        try:
            self._rl_otx.acquire()
            url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{quote(value, safe='')}/general"
            data = self._http_json(url, {"X-OTX-API-KEY": self.otx_key, "User-Agent": "RiskIntel/3.0"})
            pulse_count = int((data.get("pulse_info") or {}).get("count", 0))
            tags = list((data.get("pulse_info") or {}).get("tags", []))[:5]
            return {"enabled": True, "listed": pulse_count > 0, "pulse_count": pulse_count, "tags": tags, "source": "otx"}
        except Exception:
            return {"enabled": True, "listed": False, "pulse_count": 0, "source": "otx", "error": True}

    def _lookup_abuseipdb(self, ioc_type: str, value: str) -> Dict[str, Any]:
        if ioc_type != "ip" or not self.abuseipdb_key:
            return {"enabled": bool(self.abuseipdb_key and ioc_type == "ip"), "listed": False, "abuse_confidence": 0, "source": "abuseipdb"}
        try:
            self._rl_abuseipdb.acquire()
            qs = urlencode({"ipAddress": value, "maxAgeInDays": 90, "verbose": ""})
            data = self._http_json(f"https://api.abuseipdb.com/api/v2/check?{qs}", {"Key": self.abuseipdb_key, "Accept": "application/json", "User-Agent": "RiskIntel/3.0"})
            rec = data.get("data") or {}
            confidence = int(rec.get("abuseConfidenceScore", 0))
            return {
                "enabled": True, "listed": confidence >= 40, "abuse_confidence": confidence,
                "total_reports": rec.get("totalReports", 0), "country": rec.get("countryCode"),
                "isp": rec.get("isp"), "usage_type": rec.get("usageType"), "source": "abuseipdb",
            }
        except Exception:
            return {"enabled": True, "listed": False, "abuse_confidence": 0, "source": "abuseipdb", "error": True}

    def _lookup_virustotal(self, ioc_type: str, value: str) -> Dict[str, Any]:
        if not self.vt_key:
            return {"enabled": False, "listed": False, "malicious_votes": 0, "source": "virustotal"}
        try:
            self._rl_vt.acquire()
            endpoint_map = {
                "domain": f"https://www.virustotal.com/api/v3/domains/{quote(value, safe='')}",
                "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{quote(value, safe='')}",
                "hash_md5": f"https://www.virustotal.com/api/v3/files/{quote(value, safe='')}",
                "hash_sha256": f"https://www.virustotal.com/api/v3/files/{quote(value, safe='')}",
                "hash_sha1": f"https://www.virustotal.com/api/v3/files/{quote(value, safe='')}",
            }
            if ioc_type == "url":
                url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
                endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            else:
                endpoint = endpoint_map.get(ioc_type)
            if not endpoint:
                return {"enabled": True, "listed": False, "malicious_votes": 0, "source": "virustotal"}
            data = self._http_json(endpoint, {"x-apikey": self.vt_key, "User-Agent": "RiskIntel/3.0"})
            stats = ((data.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            categories = ((data.get("data") or {}).get("attributes") or {}).get("categories") or {}
            return {
                "enabled": True, "listed": (malicious + suspicious) > 0,
                "malicious_votes": malicious, "suspicious_votes": suspicious,
                "categories": list(categories.values())[:5], "source": "virustotal",
            }
        except Exception:
            return {"enabled": True, "listed": False, "malicious_votes": 0, "source": "virustotal", "error": True}

    def _lookup_shodan(self, ioc_type: str, value: str) -> Dict[str, Any]:
        if ioc_type != "ip" or not self.shodan_key:
            return {"enabled": bool(self.shodan_key and ioc_type == "ip"), "listed": False, "source": "shodan"}
        try:
            self._rl_shodan.acquire()
            data = self._http_json(f"https://api.shodan.io/shodan/host/{quote(value)}?key={self.shodan_key}", {"User-Agent": "RiskIntel/3.0"})
            ports = data.get("ports", [])
            vulns = list((data.get("vulns") or {}).keys())[:10]
            org = data.get("org", "")
            return {
                "enabled": True, "listed": bool(vulns), "ports": ports[:20],
                "vulns": vulns, "org": org, "country": data.get("country_name"), "source": "shodan",
            }
        except Exception:
            return {"enabled": True, "listed": False, "source": "shodan", "error": True}

    def _lookup_urlscan(self, ioc_type: str, value: str) -> Dict[str, Any]:
        if ioc_type not in {"url", "domain"} or not self.urlscan_key:
            return {"enabled": bool(self.urlscan_key and ioc_type in {"url", "domain"}), "listed": False, "source": "urlscan"}
        try:
            self._rl_urlscan.acquire()
            query = quote(value)
            data = self._http_json(f"https://urlscan.io/api/v1/search/?q={query}&size=5", {"API-Key": self.urlscan_key, "User-Agent": "RiskIntel/3.0"})
            results = data.get("results", [])
            verdicts = [r.get("verdicts", {}).get("overall", {}) for r in results[:3]]
            malicious = sum(1 for v in verdicts if v.get("malicious"))
            return {
                "enabled": True, "listed": malicious > 0,
                "scan_count": len(results), "malicious_count": malicious, "source": "urlscan",
            }
        except Exception:
            return {"enabled": True, "listed": False, "source": "urlscan", "error": True}

    # ──────────────────────────────────────────
    # Parallel IOC enrichment
    # ──────────────────────────────────────────
    def _enrich_ioc(self, ioc: IOC, live: bool) -> Dict[str, Any]:
        cache_key = f"{ioc.ioc_type}:{ioc.value}:{int(live)}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        h = self._heuristic_ioc_score(ioc.ioc_type, ioc.value)
        feeds: List[Dict[str, Any]] = []
        listed = 0
        live_score_boost = 0

        if live:
            # Run all applicable providers in parallel
            lookup_fns = [
                (self._lookup_otx, ioc.ioc_type, ioc.value),
                (self._lookup_abuseipdb, ioc.ioc_type, ioc.value),
                (self._lookup_virustotal, ioc.ioc_type, ioc.value),
                (self._lookup_shodan, ioc.ioc_type, ioc.value),
                (self._lookup_urlscan, ioc.ioc_type, ioc.value),
            ]
            futures = {self._executor.submit(fn, t, v): fn.__name__ for fn, t, v in lookup_fns}
            for future in as_completed(futures, timeout=8):
                try:
                    feeds.append(future.result(timeout=6))
                except Exception:
                    pass

            for f in feeds:
                if f.get("enabled") and f.get("listed"):
                    listed += 1
            live_score_boost += min(40, listed * 12)
            live_score_boost += min(20, int((next((f.get("abuse_confidence", 0) for f in feeds if f.get("source") == "abuseipdb"), 0) or 0) / 10))
            live_score_boost += min(25, int(next((f.get("malicious_votes", 0) for f in feeds if f.get("source") == "virustotal"), 0) or 0))
            vuln_count = len(next((f.get("vulns", []) for f in feeds if f.get("source") == "shodan"), []))
            live_score_boost += min(20, vuln_count * 5)

        rep_score = min(100, int(h["score"]) + live_score_boost)
        reputation = ("malicious" if rep_score >= 80 else ("suspicious" if rep_score >= 55 else ("clean" if rep_score >= 30 else "unknown")))

        out = {
            "ioc_type": ioc.ioc_type,
            "value": ioc.value,
            "reputation_score": rep_score,
            "reputation": reputation,
            "listed_in": listed,
            "first_seen": self._now_iso(),
            "feeds": feeds,
            "flags": h["flags"],
        }
        self._cache_set(cache_key, out)
        return out

    # ──────────────────────────────────────────
    # Main scan entry point
    # ──────────────────────────────────────────
    def scan(
        self,
        text: Optional[str] = None,
        urls: Optional[List[str]] = None,
        domains: Optional[List[str]] = None,
        ips: Optional[List[str]] = None,
        hashes: Optional[List[str]] = None,
        live_feeds: bool = False,
    ) -> Dict[str, Any]:
        iocs: List[IOC] = []
        if text and text.strip():
            iocs.extend(self._extract_iocs(text))
        for url in urls or []:
            if url and url.strip():
                iocs.append(IOC("url", url.strip()))
        for d in domains or []:
            if d and d.strip():
                iocs.append(IOC("domain", d.strip().lower()))
        for ip in ips or []:
            if ip and ip.strip():
                iocs.append(IOC("ip", ip.strip()))
        for h in hashes or []:
            v = (h or "").strip().lower()
            if not v:
                continue
            if len(v) == 64 and re.fullmatch(r"[a-f0-9]{64}", v):
                iocs.append(IOC("hash_sha256", v))
            elif len(v) == 40 and re.fullmatch(r"[a-f0-9]{40}", v):
                iocs.append(IOC("hash_sha1", v))
            elif len(v) == 32 and re.fullmatch(r"[a-f0-9]{32}", v):
                iocs.append(IOC("hash_md5", v))

        dedup: Dict[str, IOC] = {}
        for ioc in iocs:
            key = f"{ioc.ioc_type}:{ioc.value.lower()}"
            if key not in dedup:
                dedup[key] = ioc
        items = list(dedup.values())[:60]

        # Parallel enrichment of all IOCs
        if live_feeds and items:
            futures = {self._executor.submit(self._enrich_ioc, ioc, live_feeds): ioc for ioc in items}
            results = []
            for future in as_completed(futures, timeout=15):
                try:
                    results.append(future.result(timeout=10))
                except Exception:
                    pass
        else:
            results = [self._enrich_ioc(ioc, live=False) for ioc in items]

        max_score = max((int(x.get("reputation_score", 0)) for x in results), default=0)
        overall = ("high" if max_score >= 80 else ("medium" if max_score >= 55 else ("low" if max_score >= 30 else "minimal")))

        # IOC type breakdown summary
        type_counts: Dict[str, int] = {}
        for r in results:
            t = r.get("ioc_type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "generated_at": self._now_iso(),
            "live_feeds": bool(live_feeds),
            "ioc_count": len(results),
            "overall_risk": overall,
            "max_ioc_score": max_score,
            "ioc_type_breakdown": type_counts,
            "results": sorted(results, key=lambda x: int(x.get("reputation_score", 0)), reverse=True),
        }

    # ──────────────────────────────────────────
    # Async wrapper
    # ──────────────────────────────────────────
    async def scan_async(
        self,
        text: Optional[str] = None,
        urls: Optional[List[str]] = None,
        domains: Optional[List[str]] = None,
        ips: Optional[List[str]] = None,
        hashes: Optional[List[str]] = None,
        live_feeds: bool = False,
    ) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            lambda: self.scan(text=text, urls=urls, domains=domains, ips=ips, hashes=hashes, live_feeds=live_feeds),
        )

# Runtime patch layer for the last ThreatIntelEngine definition in this file.
def _feed_env(*names: str) -> str:
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            return value
    return ""


def _mask_key(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def _ti_reload_config(self: ThreatIntelEngine) -> None:
    self.otx_key = _feed_env("OTX_API_KEY", "RISKINTEL_OTX_API_KEY")
    self.abuseipdb_key = _feed_env("ABUSEIPDB_API_KEY", "RISKINTEL_ABUSEIPDB_API_KEY")
    self.vt_key = _feed_env("VIRUSTOTAL_API_KEY", "RISKINTEL_VT_API_KEY")
    self.shodan_key = _feed_env("SHODAN_API_KEY", "RISKINTEL_SHODAN_API_KEY")
    self.urlscan_key = _feed_env("URLSCAN_API_KEY", "RISKINTEL_URLSCAN_API_KEY")


def _ti_init(self: ThreatIntelEngine) -> None:
    self._rl_otx = RateLimiter(calls_per_minute=60)
    self._rl_abuseipdb = RateLimiter(calls_per_minute=30)
    self._rl_vt = RateLimiter(calls_per_minute=4)
    self._rl_shodan = RateLimiter(calls_per_minute=18)
    self._rl_urlscan = RateLimiter(calls_per_minute=20)
    self._cache = TTLCache(maxsize=8192, ttl=6 * 3600)
    self._executor = ThreadPoolExecutor(max_workers=12, thread_name_prefix="threat-intel")
    self._re_url = re.compile(r"(?:(?:https?|ftp)://|www\.)[^\s<>'\"()]+", re.IGNORECASE)
    self._re_ip = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    self._re_ipv6 = re.compile(r"\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b")
    self._re_domain = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b")
    self._re_md5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
    self._re_sha1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
    self._re_sha256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
    self._re_email = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
    self._re_cve = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
    self.suspicious_tlds = {"zip", "mov", "top", "gq", "tk", "work", "click", "cam", "rest", "country", "stream", "xyz", "pw", "cc"}
    self._risk_url_terms = {"login", "verify", "secure", "update", "wallet", "payment", "signin", "confirm"}
    self.reload_config()


def _build_auth_headers(self: ThreatIntelEngine, feed_name: str, api_key: str) -> Dict[str, str]:
    if feed_name == "alienvault_otx":
        return {"X-OTX-API-KEY": api_key}
    if feed_name == "abuseipdb":
        return {"Key": api_key, "Accept": "application/json"}
    if feed_name == "virustotal":
        return {"x-apikey": api_key}
    if feed_name == "urlscan":
        return {"API-Key": api_key}
    return {}


def _feed_configs(self: ThreatIntelEngine) -> Dict[str, Dict[str, Any]]:
    return {
        "alienvault_otx": {"name": "AlienVault OTX", "api_key": self.otx_key, "enabled": bool(self.otx_key), "health_check_url": "https://otx.alienvault.com/api/v1/user/me"},
        "abuseipdb": {"name": "AbuseIPDB", "api_key": self.abuseipdb_key, "enabled": bool(self.abuseipdb_key), "health_check_url": "https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1&maxAgeInDays=30"},
        "virustotal": {"name": "VirusTotal", "api_key": self.vt_key, "enabled": bool(self.vt_key), "health_check_url": "https://www.virustotal.com/api/v3/users/current"},
        "shodan": {"name": "Shodan", "api_key": self.shodan_key, "enabled": bool(self.shodan_key), "health_check_url": f"https://api.shodan.io/api-info?key={self.shodan_key}" if self.shodan_key else ""},
        "urlscan": {"name": "URLScan.io", "api_key": self.urlscan_key, "enabled": bool(self.urlscan_key), "health_check_url": "https://urlscan.io/user/"},
    }


async def _probe_feed(self: ThreatIntelEngine, feed_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
    if not config.get("api_key") or not config.get("enabled") or not config.get("health_check_url"):
        return {"name": feed_name, "display_name": config.get("name", feed_name), "configured": False, "reachable": False, "auth_valid": False, "latency_ms": None, "http_status": None, "error": None, "last_checked": datetime.now(timezone.utc).isoformat()}
    headers = self.build_auth_headers(feed_name, config["api_key"])
    headers["User-Agent"] = "RiskIntel/3.0"
    logger.info("Feed probe %s url=%s headers=%s", feed_name, config["health_check_url"], {k: (_mask_key(v) if "key" in k.lower() or "auth" in k.lower() else v) for k, v in headers.items()})
    try:
        started = time.monotonic()
        async with httpx.AsyncClient(timeout=10.0, verify=True, follow_redirects=True) as client:
            response = await client.get(config["health_check_url"], headers=headers)
        latency_ms = int((time.monotonic() - started) * 1000)
        return {"name": feed_name, "display_name": config.get("name", feed_name), "configured": True, "reachable": response.status_code < 500, "auth_valid": response.status_code not in (401, 403), "latency_ms": latency_ms, "http_status": response.status_code, "error": None if response.status_code < 500 else f"HTTP {response.status_code}", "last_checked": datetime.now(timezone.utc).isoformat()}
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        return {"name": feed_name, "display_name": config.get("name", feed_name), "configured": True, "reachable": False, "auth_valid": False, "latency_ms": None, "http_status": None, "error": str(exc), "last_checked": datetime.now(timezone.utc).isoformat()}


async def _probe_all_feeds_async(self: ThreatIntelEngine) -> Dict[str, Any]:
    configs = self.get_feed_configs()
    results = await asyncio.gather(*[self.probe_feed(name, cfg) for name, cfg in configs.items()])
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "feeds": results, "summary": {"configured": sum(1 for item in results if item.get("configured")), "reachable": sum(1 for item in results if item.get("reachable")), "auth_valid": sum(1 for item in results if item.get("auth_valid")), "total": len(results)}}


def _build_live_feed_status(self: ThreatIntelEngine, probe: bool = False) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    configs = self.get_feed_configs()
    providers = {key: {"name": cfg.get("name", key), "configured": bool(cfg.get("enabled")), "reachable": None, "auth_valid": None, "latency_ms": None, "status_code": None, "http_status": None, "error": None, "last_checked": now} for key, cfg in configs.items()}
    if probe:
        loop = asyncio.new_event_loop()
        try:
            payload = loop.run_until_complete(self.probe_all_feeds_async())
        finally:
            loop.close()
        for feed in payload.get("feeds", []):
            if feed["name"] in providers:
                providers[feed["name"]].update(feed)
                providers[feed["name"]]["status_code"] = feed.get("http_status")
        return {"generated_at": payload.get("timestamp", now), "probe_performed": True, "providers": providers, "summary": payload.get("summary", {})}
    configured = sum(1 for item in providers.values() if item.get("configured"))
    return {"generated_at": now, "probe_performed": False, "providers": providers, "summary": {"configured": configured, "reachable": 0, "auth_valid": 0, "total": len(providers)}}


ThreatIntelEngine.__init__ = _ti_init
ThreatIntelEngine.reload_config = _ti_reload_config
ThreatIntelEngine.build_auth_headers = _build_auth_headers
ThreatIntelEngine.get_feed_configs = _feed_configs
ThreatIntelEngine.probe_feed = _probe_feed
ThreatIntelEngine.probe_all_feeds_async = _probe_all_feeds_async
ThreatIntelEngine.build_live_feed_status = _build_live_feed_status


def _feed_env(*names: str) -> str:
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            return value
    return ""


def _mask_key(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def _ti_reload_config(self: ThreatIntelEngine) -> None:
    self.otx_key = _feed_env("OTX_API_KEY", "RISKINTEL_OTX_API_KEY")
    self.abuseipdb_key = _feed_env("ABUSEIPDB_API_KEY", "RISKINTEL_ABUSEIPDB_API_KEY")
    self.vt_key = _feed_env("VIRUSTOTAL_API_KEY", "RISKINTEL_VT_API_KEY")
    self.shodan_key = _feed_env("SHODAN_API_KEY", "RISKINTEL_SHODAN_API_KEY")
    self.urlscan_key = _feed_env("URLSCAN_API_KEY", "RISKINTEL_URLSCAN_API_KEY")


def _ti_init(self: ThreatIntelEngine) -> None:
    self._rl_otx = RateLimiter(calls_per_minute=60)
    self._rl_abuseipdb = RateLimiter(calls_per_minute=30)
    self._rl_vt = RateLimiter(calls_per_minute=4)
    self._rl_shodan = RateLimiter(calls_per_minute=18)
    self._rl_urlscan = RateLimiter(calls_per_minute=20)
    self._cache = TTLCache(maxsize=8192, ttl=6 * 3600)
    self._executor = ThreadPoolExecutor(max_workers=12, thread_name_prefix="threat-intel")
    self._re_url = re.compile(r"(?:(?:https?|ftp)://|www\.)[^\s<>'\"()]+", re.IGNORECASE)
    self._re_ip = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    self._re_ipv6 = re.compile(r"\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b")
    self._re_domain = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b")
    self._re_md5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
    self._re_sha1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
    self._re_sha256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
    self._re_email = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
    self._re_cve = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
    self.suspicious_tlds = {"zip", "mov", "top", "gq", "tk", "work", "click", "cam", "rest", "country", "stream", "xyz", "pw", "cc"}
    self._risk_url_terms = {"login", "verify", "secure", "update", "wallet", "payment", "signin", "confirm"}
    self.reload_config()


def _build_auth_headers(self: ThreatIntelEngine, feed_name: str, api_key: str) -> Dict[str, str]:
    if feed_name == "alienvault_otx":
        return {"X-OTX-API-KEY": api_key}
    if feed_name == "abuseipdb":
        return {"Key": api_key, "Accept": "application/json"}
    if feed_name == "virustotal":
        return {"x-apikey": api_key}
    if feed_name == "urlscan":
        return {"API-Key": api_key}
    return {}


def _feed_configs(self: ThreatIntelEngine) -> Dict[str, Dict[str, Any]]:
    return {
        "alienvault_otx": {"name": "AlienVault OTX", "api_key": self.otx_key, "enabled": bool(self.otx_key), "health_check_url": "https://otx.alienvault.com/api/v1/user/me"},
        "abuseipdb": {"name": "AbuseIPDB", "api_key": self.abuseipdb_key, "enabled": bool(self.abuseipdb_key), "health_check_url": "https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1&maxAgeInDays=30"},
        "virustotal": {"name": "VirusTotal", "api_key": self.vt_key, "enabled": bool(self.vt_key), "health_check_url": "https://www.virustotal.com/api/v3/users/current"},
        "shodan": {"name": "Shodan", "api_key": self.shodan_key, "enabled": bool(self.shodan_key), "health_check_url": f"https://api.shodan.io/api-info?key={self.shodan_key}" if self.shodan_key else ""},
        "urlscan": {"name": "URLScan.io", "api_key": self.urlscan_key, "enabled": bool(self.urlscan_key), "health_check_url": "https://urlscan.io/user/"},
    }


async def _probe_feed(self: ThreatIntelEngine, feed_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
    if not config.get("api_key") or not config.get("enabled") or not config.get("health_check_url"):
        return {"name": feed_name, "display_name": config.get("name", feed_name), "configured": False, "reachable": False, "auth_valid": False, "latency_ms": None, "http_status": None, "error": None, "last_checked": datetime.now(timezone.utc).isoformat()}
    headers = self.build_auth_headers(feed_name, config["api_key"])
    headers["User-Agent"] = "RiskIntel/3.0"
    logger.info("Feed probe %s url=%s headers=%s", feed_name, config["health_check_url"], {k: (_mask_key(v) if "key" in k.lower() or "auth" in k.lower() else v) for k, v in headers.items()})
    try:
        started = time.monotonic()
        async with httpx.AsyncClient(timeout=10.0, verify=True, follow_redirects=True) as client:
            response = await client.get(config["health_check_url"], headers=headers)
        latency_ms = int((time.monotonic() - started) * 1000)
        return {"name": feed_name, "display_name": config.get("name", feed_name), "configured": True, "reachable": response.status_code < 500, "auth_valid": response.status_code not in (401, 403), "latency_ms": latency_ms, "http_status": response.status_code, "error": None if response.status_code < 500 else f"HTTP {response.status_code}", "last_checked": datetime.now(timezone.utc).isoformat()}
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        return {"name": feed_name, "display_name": config.get("name", feed_name), "configured": True, "reachable": False, "auth_valid": False, "latency_ms": None, "http_status": None, "error": str(exc), "last_checked": datetime.now(timezone.utc).isoformat()}


async def _probe_all_feeds_async(self: ThreatIntelEngine) -> Dict[str, Any]:
    configs = self.get_feed_configs()
    results = await asyncio.gather(*[self.probe_feed(name, cfg) for name, cfg in configs.items()])
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "feeds": results, "summary": {"configured": sum(1 for item in results if item.get("configured")), "reachable": sum(1 for item in results if item.get("reachable")), "auth_valid": sum(1 for item in results if item.get("auth_valid")), "total": len(results)}}


def _build_live_feed_status(self: ThreatIntelEngine, probe: bool = False) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    configs = self.get_feed_configs()
    providers = {key: {"name": cfg.get("name", key), "configured": bool(cfg.get("enabled")), "reachable": None, "auth_valid": None, "latency_ms": None, "status_code": None, "http_status": None, "error": None, "last_checked": now} for key, cfg in configs.items()}
    if probe:
        loop = asyncio.new_event_loop()
        try:
            payload = loop.run_until_complete(self.probe_all_feeds_async())
        finally:
            loop.close()
        for feed in payload.get("feeds", []):
            if feed["name"] in providers:
                providers[feed["name"]].update(feed)
                providers[feed["name"]]["status_code"] = feed.get("http_status")
        return {"generated_at": payload.get("timestamp", now), "probe_performed": True, "providers": providers, "summary": payload.get("summary", {})}
    configured = sum(1 for item in providers.values() if item.get("configured"))
    return {"generated_at": now, "probe_performed": False, "providers": providers, "summary": {"configured": configured, "reachable": 0, "auth_valid": 0, "total": len(providers)}}


ThreatIntelEngine.__init__ = _ti_init
ThreatIntelEngine.reload_config = _ti_reload_config
ThreatIntelEngine.build_auth_headers = _build_auth_headers
ThreatIntelEngine.get_feed_configs = _feed_configs
ThreatIntelEngine.probe_feed = _probe_feed
ThreatIntelEngine.probe_all_feeds_async = _probe_all_feeds_async
ThreatIntelEngine.build_live_feed_status = _build_live_feed_status


def _feed_env(*names: str) -> str:
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            return value
    return ""


def _mask_key(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def _ti_reload_config(self: ThreatIntelEngine) -> None:
    self.otx_key = _feed_env("OTX_API_KEY", "RISKINTEL_OTX_API_KEY")
    self.abuseipdb_key = _feed_env("ABUSEIPDB_API_KEY", "RISKINTEL_ABUSEIPDB_API_KEY")
    self.vt_key = _feed_env("VIRUSTOTAL_API_KEY", "RISKINTEL_VT_API_KEY")
    self.shodan_key = _feed_env("SHODAN_API_KEY", "RISKINTEL_SHODAN_API_KEY")
    self.urlscan_key = _feed_env("URLSCAN_API_KEY", "RISKINTEL_URLSCAN_API_KEY")


def _ti_init(self: ThreatIntelEngine) -> None:
    self._rl_otx = RateLimiter(calls_per_minute=60)
    self._rl_abuseipdb = RateLimiter(calls_per_minute=30)
    self._rl_vt = RateLimiter(calls_per_minute=4)
    self._rl_shodan = RateLimiter(calls_per_minute=18)
    self._rl_urlscan = RateLimiter(calls_per_minute=20)
    self._cache = TTLCache(maxsize=8192, ttl=6 * 3600)
    self._executor = ThreadPoolExecutor(max_workers=12, thread_name_prefix="threat-intel")
    self._re_url = re.compile(r"(?:(?:https?|ftp)://|www\.)[^\s<>'\"()]+", re.IGNORECASE)
    self._re_ip = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    self._re_ipv6 = re.compile(r"\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b")
    self._re_domain = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b")
    self._re_md5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
    self._re_sha1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
    self._re_sha256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
    self._re_email = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
    self._re_cve = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
    self.suspicious_tlds = {"zip", "mov", "top", "gq", "tk", "work", "click", "cam", "rest", "country", "stream", "xyz", "pw", "cc"}
    self._risk_url_terms = {"login", "verify", "secure", "update", "wallet", "payment", "signin", "confirm"}
    self.reload_config()


def _build_auth_headers(self: ThreatIntelEngine, feed_name: str, api_key: str) -> Dict[str, str]:
    if feed_name == "alienvault_otx":
        return {"X-OTX-API-KEY": api_key}
    if feed_name == "abuseipdb":
        return {"Key": api_key, "Accept": "application/json"}
    if feed_name == "virustotal":
        return {"x-apikey": api_key}
    if feed_name == "shodan":
        return {}
    if feed_name == "urlscan":
        return {"API-Key": api_key}
    return {}


def _feed_configs(self: ThreatIntelEngine) -> Dict[str, Dict[str, Any]]:
    return {
        "alienvault_otx": {
            "name": "AlienVault OTX",
            "api_key": self.otx_key,
            "enabled": bool(self.otx_key),
            "health_check_url": "https://otx.alienvault.com/api/v1/user/me",
        },
        "abuseipdb": {
            "name": "AbuseIPDB",
            "api_key": self.abuseipdb_key,
            "enabled": bool(self.abuseipdb_key),
            "health_check_url": "https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1&maxAgeInDays=30",
        },
        "virustotal": {
            "name": "VirusTotal",
            "api_key": self.vt_key,
            "enabled": bool(self.vt_key),
            "health_check_url": "https://www.virustotal.com/api/v3/users/current",
        },
        "shodan": {
            "name": "Shodan",
            "api_key": self.shodan_key,
            "enabled": bool(self.shodan_key),
            "health_check_url": f"https://api.shodan.io/api-info?key={self.shodan_key}" if self.shodan_key else "",
        },
        "urlscan": {
            "name": "URLScan.io",
            "api_key": self.urlscan_key,
            "enabled": bool(self.urlscan_key),
            "health_check_url": "https://urlscan.io/user/",
        },
    }


async def _probe_feed(self: ThreatIntelEngine, feed_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
    if not config.get("api_key") or not config.get("enabled") or not config.get("health_check_url"):
        return {
            "name": feed_name,
            "display_name": config.get("name", feed_name),
            "configured": False,
            "reachable": False,
            "auth_valid": False,
            "latency_ms": None,
            "http_status": None,
            "error": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
        }
    headers = self.build_auth_headers(feed_name, config["api_key"])
    headers["User-Agent"] = "RiskIntel/3.0"
    safe_headers = {k: (_mask_key(v) if "key" in k.lower() or "auth" in k.lower() else v) for k, v in headers.items()}
    logger.info("Feed probe %s url=%s headers=%s", feed_name, config["health_check_url"], safe_headers)
    try:
        started = time.monotonic()
        async with httpx.AsyncClient(timeout=10.0, verify=True, follow_redirects=True) as client:
            response = await client.get(config["health_check_url"], headers=headers)
        latency_ms = int((time.monotonic() - started) * 1000)
        logger.info("Feed probe %s status=%s latency_ms=%s", feed_name, response.status_code, latency_ms)
        return {
            "name": feed_name,
            "display_name": config.get("name", feed_name),
            "configured": True,
            "reachable": response.status_code < 500,
            "auth_valid": response.status_code not in (401, 403),
            "latency_ms": latency_ms,
            "http_status": response.status_code,
            "error": None if response.status_code < 500 else f"HTTP {response.status_code}",
            "last_checked": datetime.now(timezone.utc).isoformat(),
        }
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        logger.warning("Feed probe %s connection failure: %s", feed_name, exc)
        return {
            "name": feed_name,
            "display_name": config.get("name", feed_name),
            "configured": True,
            "reachable": False,
            "auth_valid": False,
            "latency_ms": None,
            "http_status": None,
            "error": str(exc),
            "last_checked": datetime.now(timezone.utc).isoformat(),
        }


async def _probe_all_feeds_async(self: ThreatIntelEngine) -> Dict[str, Any]:
    configs = self.get_feed_configs()
    results = await asyncio.gather(*[self.probe_feed(name, cfg) for name, cfg in configs.items()])
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "feeds": results,
        "summary": {
            "configured": sum(1 for item in results if item.get("configured")),
            "reachable": sum(1 for item in results if item.get("reachable")),
            "auth_valid": sum(1 for item in results if item.get("auth_valid")),
            "total": len(results),
        },
    }


def _build_live_feed_status(self: ThreatIntelEngine, probe: bool = False) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    configs = self.get_feed_configs()
    providers: Dict[str, Dict[str, Any]] = {}
    for key, cfg in configs.items():
        providers[key] = {
            "name": cfg.get("name", key),
            "configured": bool(cfg.get("enabled")),
            "reachable": None,
            "auth_valid": None,
            "latency_ms": None,
            "status_code": None,
            "http_status": None,
            "error": None,
            "last_checked": now,
        }
    if probe:
        try:
            payload = asyncio.run(self.probe_all_feeds_async())
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                payload = loop.run_until_complete(self.probe_all_feeds_async())
            finally:
                loop.close()
        for feed in payload.get("feeds", []):
            key = feed["name"]
            if key in providers:
                providers[key].update(feed)
                providers[key]["status_code"] = feed.get("http_status")
        return {
            "generated_at": payload.get("timestamp", now),
            "probe_performed": True,
            "providers": providers,
            "summary": payload.get("summary", {}),
        }
    configured = sum(1 for item in providers.values() if item.get("configured"))
    return {
        "generated_at": now,
        "probe_performed": False,
        "providers": providers,
        "summary": {"configured": configured, "reachable": 0, "auth_valid": 0, "total": len(providers)},
    }


ThreatIntelEngine.__init__ = _ti_init
ThreatIntelEngine.reload_config = _ti_reload_config
ThreatIntelEngine.build_auth_headers = _build_auth_headers
ThreatIntelEngine.get_feed_configs = _feed_configs
ThreatIntelEngine.probe_feed = _probe_feed
ThreatIntelEngine.probe_all_feeds_async = _probe_all_feeds_async
ThreatIntelEngine.build_live_feed_status = _build_live_feed_status

import asyncio
import base64
import ipaddress
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import threading


# ─────────────────────────────────────────────
# Thread-safe TTL cache (shared with risk engine)
# ─────────────────────────────────────────────
class TTLCache:
    def __init__(self, maxsize: int = 4096, ttl: float = 3600.0) -> None:
        self._store: Dict[str, tuple] = {}
        self._lock = threading.Lock()
        self._maxsize = maxsize
        self._ttl = ttl

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, ts = entry
            if time.monotonic() - ts > self._ttl:
                del self._store[key]
                return None
            return value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            if len(self._store) >= self._maxsize:
                oldest = sorted(self._store.items(), key=lambda x: x[1][1])[:self._maxsize // 10]
                for k, _ in oldest:
                    del self._store[k]
            self._store[key] = (value, time.monotonic())

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


@dataclass(frozen=True)
class IOC:
    ioc_type: str
    value: str


# ─────────────────────────────────────────────
# Rate limiter: prevent API key exhaustion
# ─────────────────────────────────────────────
class RateLimiter:
    """Simple token-bucket rate limiter per provider key."""

    def __init__(self, calls_per_minute: int = 60) -> None:
        self._calls_per_minute = calls_per_minute
        self._min_interval = 60.0 / max(calls_per_minute, 1)
        self._last_call: float = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            if elapsed < self._min_interval:
                time.sleep(self._min_interval - elapsed)
            self._last_call = time.monotonic()


class ThreatIntelEngine:
    """
    IOC enrichment engine with optional live feed lookups.
    v3: async-ready, parallel enrichment, rate limiting, extended IOC types.
    """

    def __init__(self) -> None:
        self.otx_key = os.getenv("RISKINTEL_OTX_API_KEY", "").strip()
        self.abuseipdb_key = os.getenv("RISKINTEL_ABUSEIPDB_API_KEY", "").strip()
        self.vt_key = os.getenv("RISKINTEL_VT_API_KEY", "").strip()
        self.shodan_key = os.getenv("RISKINTEL_SHODAN_API_KEY", "").strip()
        self.urlscan_key = os.getenv("RISKINTEL_URLSCAN_API_KEY", "").strip()

        # Per-provider rate limiters
        self._rl_otx = RateLimiter(calls_per_minute=60)
        self._rl_abuseipdb = RateLimiter(calls_per_minute=30)
        self._rl_vt = RateLimiter(calls_per_minute=4)   # VT free = 4 req/min
        self._rl_shodan = RateLimiter(calls_per_minute=18)
        self._rl_urlscan = RateLimiter(calls_per_minute=20)

        # Shared TTL cache: keyed by ioc_type:value:live
        self._cache = TTLCache(maxsize=8192, ttl=6 * 3600)

        # Thread pool for parallel provider calls
        self._executor = ThreadPoolExecutor(max_workers=12, thread_name_prefix="threat-intel")

        # Regex patterns
        self._re_url = re.compile(r"(?:(?:https?|ftp)://|www\.)[^\s<>'\"()]+", re.IGNORECASE)
        self._re_ip = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        self._re_ipv6 = re.compile(r"\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b")
        self._re_domain = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b")
        self._re_md5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
        self._re_sha1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
        self._re_sha256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
        self._re_email = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
        self._re_cve = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

        self.suspicious_tlds = {
            "zip", "mov", "top", "gq", "tk", "work", "click", "cam", "rest",
            "country", "stream", "xyz", "pw", "cc",
        }
        self._risk_url_terms = {"login", "verify", "secure", "update", "wallet", "payment", "signin", "confirm"}

    # ──────────────────────────────────────────
    # Provider availability
    # ──────────────────────────────────────────
    @property
    def live_feeds_available(self) -> bool:
        return bool(self.otx_key or self.abuseipdb_key or self.vt_key or self.shodan_key or self.urlscan_key)

    @property
    def live_feed_status(self) -> Dict[str, Dict[str, bool]]:
        status = self.build_live_feed_status(probe=False)
        return {k: {"configured": bool(v["configured"])} for k, v in status["providers"].items()}

    # ──────────────────────────────────────────
    # HTTP helper
    # ──────────────────────────────────────────
    @staticmethod
    def _probe_http(url: str, headers: Dict[str, str], timeout: float = 4.0) -> Dict[str, Any]:
        started = time.perf_counter()
        req = Request(url, headers=headers)
        try:
            with urlopen(req, timeout=timeout) as resp:
                _ = resp.read(256)
                code = int(getattr(resp, "status", 200) or 200)
            return {"reachable": True, "auth_valid": 200 <= code < 300, "latency_ms": int((time.perf_counter() - started) * 1000), "status_code": code}
        except HTTPError as exc:
            code = int(getattr(exc, "code", 0) or 0)
            return {"reachable": True, "auth_valid": code not in {401, 403}, "latency_ms": int((time.perf_counter() - started) * 1000), "status_code": code, "error": f"HTTP {code}"}
        except Exception as exc:
            return {"reachable": False, "auth_valid": None, "latency_ms": int((time.perf_counter() - started) * 1000), "status_code": None, "error": str(exc)[:220]}

    def build_live_feed_status(self, probe: bool = False) -> Dict[str, Any]:
        now = self._now_iso()
        providers: Dict[str, Dict[str, Any]] = {
            "otx": {"name": "AlienVault OTX", "configured": bool(self.otx_key), "reachable": None, "auth_valid": None, "latency_ms": None, "status_code": None, "error": None, "last_checked": now},
            "abuseipdb": {"name": "AbuseIPDB", "configured": bool(self.abuseipdb_key), "reachable": None, "auth_valid": None, "latency_ms": None, "status_code": None, "error": None, "last_checked": now},
            "virustotal": {"name": "VirusTotal", "configured": bool(self.vt_key), "reachable": None, "auth_valid": None, "latency_ms": None, "status_code": None, "error": None, "last_checked": now},
            "shodan": {"name": "Shodan", "configured": bool(self.shodan_key), "reachable": None, "auth_valid": None, "latency_ms": None, "status_code": None, "error": None, "last_checked": now},
            "urlscan": {"name": "URLScan.io", "configured": bool(self.urlscan_key), "reachable": None, "auth_valid": None, "latency_ms": None, "status_code": None, "error": None, "last_checked": now},
        }
        if probe:
            probe_map = {
                "otx": (bool(self.otx_key), "https://otx.alienvault.com/api/v1/user/me", {"X-OTX-API-KEY": self.otx_key, "User-Agent": "RiskIntel/3.0"}),
                "abuseipdb": (bool(self.abuseipdb_key), "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=30", {"Key": self.abuseipdb_key, "Accept": "application/json", "User-Agent": "RiskIntel/3.0"}),
                "virustotal": (bool(self.vt_key), "https://www.virustotal.com/api/v3/users/current", {"x-apikey": self.vt_key, "User-Agent": "RiskIntel/3.0"}),
                "shodan": (bool(self.shodan_key), f"https://api.shodan.io/api-info?key={self.shodan_key}", {"User-Agent": "RiskIntel/3.0"}),
                "urlscan": (bool(self.urlscan_key), "https://urlscan.io/user/", {"API-Key": self.urlscan_key, "User-Agent": "RiskIntel/3.0"}),
            }
            futures = {}
            with ThreadPoolExecutor(max_workers=5) as pool:
                for name, (configured, url, headers) in probe_map.items():
                    if configured:
                        futures[name] = pool.submit(self._probe_http, url, headers)
            for name, fut in futures.items():
                try:
                    providers[name].update(fut.result(timeout=8))
                except Exception:
                    pass

        configured = sum(1 for p in providers.values() if p["configured"])
        reachable = sum(1 for p in providers.values() if p["reachable"] is True)
        auth_valid = sum(1 for p in providers.values() if p["auth_valid"] is True)
        return {
            "generated_at": now,
            "probe_performed": bool(probe),
            "providers": providers,
            "summary": {"configured": configured, "reachable": reachable, "auth_valid": auth_valid, "total": len(providers)},
        }

    # ──────────────────────────────────────────
    # HTTP JSON fetch
    # ──────────────────────────────────────────
    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _http_json(self, url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 4.0) -> Dict[str, Any]:
        req = Request(url, headers=headers or {"User-Agent": "RiskIntel/3.0"})
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read(400000).decode("utf-8", errors="ignore"))

    def _cache_get(self, key: str) -> Optional[Dict[str, Any]]:
        return self._cache.get(key)

    def _cache_set(self, key: str, data: Dict[str, Any]) -> None:
        self._cache.set(key, data)

    # ──────────────────────────────────────────
    # IOC extraction (extended: CVE, SHA1, IPv6, email)
    # ──────────────────────────────────────────
    def _extract_iocs(self, text: str) -> List[IOC]:
        if not text.strip():
            return []
        found: List[IOC] = []
        seen: Set[str] = set()

        def add(ioc_type: str, value: str) -> None:
            key = f"{ioc_type}::{value.lower()}"
            if key not in seen:
                seen.add(key)
                found.append(IOC(ioc_type, value))

        for url in [x.strip(".,);]}>\"'") for x in self._re_url.findall(text)]:
            if not url:
                continue
            add("url", url)
            host = (urlsplit(url if "://" in url else f"http://{url}").hostname or "").lower()
            if host:
                add("domain", host)

        for ip in self._re_ip.findall(text):
            add("ip", ip)
        for ip6 in self._re_ipv6.findall(text):
            add("ipv6", ip6)
        for d in self._re_domain.findall(text):
            low = d.lower().lstrip("www.")
            add("domain", low)
        for h in self._re_sha256.findall(text):
            add("hash_sha256", h.lower())
        for h in self._re_sha1.findall(text):
            add("hash_sha1", h.lower())
        for h in self._re_md5.findall(text):
            add("hash_md5", h.lower())
        for email in self._re_email.findall(text):
            add("email", email.lower())
        for cve in self._re_cve.findall(text):
            add("cve", cve.upper())

        return found[:60]

    # ──────────────────────────────────────────
    # Heuristic scoring
    # ──────────────────────────────────────────
    def _heuristic_ioc_score(self, ioc_type: str, value: str) -> Dict[str, Any]:
        score = 8
        flags: List[str] = []

        if ioc_type == "domain":
            parts = value.lower().split(".")
            tld = parts[-1] if parts else ""
            label = parts[-2] if len(parts) >= 2 else value
            if tld in self.suspicious_tlds:
                score += 35; flags.append(f"Suspicious TLD .{tld}")
            if len(parts) >= 3:
                score += 8; flags.append("Deep subdomain pattern")
            if sum(ch.isdigit() for ch in label) >= 3:
                score += 12; flags.append("Numeric-heavy domain label")
            if "-" in label:
                score += 8; flags.append("Hyphenated label")

        elif ioc_type == "ip":
            try:
                ip_obj = ipaddress.ip_address(value)
                if ip_obj.is_private or ip_obj.is_loopback:
                    score += 15; flags.append("Private/local IP")
                else:
                    score += 10; flags.append("Public external IP")
            except ValueError:
                score += 20; flags.append("Malformed IP")

        elif ioc_type == "url":
            parsed = urlsplit(value if "://" in value else f"http://{value}")
            if parsed.scheme == "http":
                score += 18; flags.append("Unencrypted HTTP")
            for term in self._risk_url_terms:
                if term in value.lower():
                    score += 6; flags.append(f"Risk term: {term}")

        elif ioc_type.startswith("hash_"):
            score += 12; flags.append("File hash IOC")

        elif ioc_type == "email":
            score += 5; flags.append("Email address IOC")

        elif ioc_type == "cve":
            score += 20; flags.append("CVE identifier present")

        return {"score": min(95, max(0, score)), "flags": flags[:8],
                "reputation": ("malicious" if score >= 75 else ("suspicious" if score >= 45 else ("clean" if score >= 20 else "unknown")))}

    # ──────────────────────────────────────────
    # Live feed lookups (with rate limiting)
    # ──────────────────────────────────────────
    def _lookup_otx(self, ioc_type: str, value: str) -> Dict[str, Any]:
        if not self.otx_key:
            return {"enabled": False, "listed": False, "pulse_count": 0, "source": "otx"}
        otx_type_map = {"domain": "domain", "ip": "IPv4", "url": "url", "hash_md5": "file", "hash_sha256": "file"}
        otx_type = otx_type_map.get(ioc_type)
        if not otx_type:
            return {"enabled": True, "listed": False, "pulse_count": 0, "source": "otx"}
        try:
            self._rl_otx.acquire()
            url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{quote(value, safe='')}/general"
            data = self._http_json(url, {"X-OTX-API-KEY": self.otx_key, "User-Agent": "RiskIntel/3.0"})
            pulse_count = int((data.get("pulse_info") or {}).get("count", 0))
            tags = list((data.get("pulse_info") or {}).get("tags", []))[:5]
            return {"enabled": True, "listed": pulse_count > 0, "pulse_count": pulse_count, "tags": tags, "source": "otx"}
        except Exception:
            return {"enabled": True, "listed": False, "pulse_count": 0, "source": "otx", "error": True}

    def _lookup_abuseipdb(self, ioc_type: str, value: str) -> Dict[str, Any]:
        if ioc_type != "ip" or not self.abuseipdb_key:
            return {"enabled": bool(self.abuseipdb_key and ioc_type == "ip"), "listed": False, "abuse_confidence": 0, "source": "abuseipdb"}
        try:
            self._rl_abuseipdb.acquire()
            qs = urlencode({"ipAddress": value, "maxAgeInDays": 90, "verbose": ""})
            data = self._http_json(f"https://api.abuseipdb.com/api/v2/check?{qs}", {"Key": self.abuseipdb_key, "Accept": "application/json", "User-Agent": "RiskIntel/3.0"})
            rec = data.get("data") or {}
            confidence = int(rec.get("abuseConfidenceScore", 0))
            return {
                "enabled": True, "listed": confidence >= 40, "abuse_confidence": confidence,
                "total_reports": rec.get("totalReports", 0), "country": rec.get("countryCode"),
                "isp": rec.get("isp"), "usage_type": rec.get("usageType"), "source": "abuseipdb",
            }
        except Exception:
            return {"enabled": True, "listed": False, "abuse_confidence": 0, "source": "abuseipdb", "error": True}

    def _lookup_virustotal(self, ioc_type: str, value: str) -> Dict[str, Any]:
        if not self.vt_key:
            return {"enabled": False, "listed": False, "malicious_votes": 0, "source": "virustotal"}
        try:
            self._rl_vt.acquire()
            endpoint_map = {
                "domain": f"https://www.virustotal.com/api/v3/domains/{quote(value, safe='')}",
                "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{quote(value, safe='')}",
                "hash_md5": f"https://www.virustotal.com/api/v3/files/{quote(value, safe='')}",
                "hash_sha256": f"https://www.virustotal.com/api/v3/files/{quote(value, safe='')}",
                "hash_sha1": f"https://www.virustotal.com/api/v3/files/{quote(value, safe='')}",
            }
            if ioc_type == "url":
                url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
                endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            else:
                endpoint = endpoint_map.get(ioc_type)
            if not endpoint:
                return {"enabled": True, "listed": False, "malicious_votes": 0, "source": "virustotal"}
            data = self._http_json(endpoint, {"x-apikey": self.vt_key, "User-Agent": "RiskIntel/3.0"})
            stats = ((data.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            categories = ((data.get("data") or {}).get("attributes") or {}).get("categories") or {}
            return {
                "enabled": True, "listed": (malicious + suspicious) > 0,
                "malicious_votes": malicious, "suspicious_votes": suspicious,
                "categories": list(categories.values())[:5], "source": "virustotal",
            }
        except Exception:
            return {"enabled": True, "listed": False, "malicious_votes": 0, "source": "virustotal", "error": True}

    def _lookup_shodan(self, ioc_type: str, value: str) -> Dict[str, Any]:
        if ioc_type != "ip" or not self.shodan_key:
            return {"enabled": bool(self.shodan_key and ioc_type == "ip"), "listed": False, "source": "shodan"}
        try:
            self._rl_shodan.acquire()
            data = self._http_json(f"https://api.shodan.io/shodan/host/{quote(value)}?key={self.shodan_key}", {"User-Agent": "RiskIntel/3.0"})
            ports = data.get("ports", [])
            vulns = list((data.get("vulns") or {}).keys())[:10]
            org = data.get("org", "")
            return {
                "enabled": True, "listed": bool(vulns), "ports": ports[:20],
                "vulns": vulns, "org": org, "country": data.get("country_name"), "source": "shodan",
            }
        except Exception:
            return {"enabled": True, "listed": False, "source": "shodan", "error": True}

    def _lookup_urlscan(self, ioc_type: str, value: str) -> Dict[str, Any]:
        if ioc_type not in {"url", "domain"} or not self.urlscan_key:
            return {"enabled": bool(self.urlscan_key and ioc_type in {"url", "domain"}), "listed": False, "source": "urlscan"}
        try:
            self._rl_urlscan.acquire()
            query = quote(value)
            data = self._http_json(f"https://urlscan.io/api/v1/search/?q={query}&size=5", {"API-Key": self.urlscan_key, "User-Agent": "RiskIntel/3.0"})
            results = data.get("results", [])
            verdicts = [r.get("verdicts", {}).get("overall", {}) for r in results[:3]]
            malicious = sum(1 for v in verdicts if v.get("malicious"))
            return {
                "enabled": True, "listed": malicious > 0,
                "scan_count": len(results), "malicious_count": malicious, "source": "urlscan",
            }
        except Exception:
            return {"enabled": True, "listed": False, "source": "urlscan", "error": True}

    # ──────────────────────────────────────────
    # Parallel IOC enrichment
    # ──────────────────────────────────────────
    def _enrich_ioc(self, ioc: IOC, live: bool) -> Dict[str, Any]:
        cache_key = f"{ioc.ioc_type}:{ioc.value}:{int(live)}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        h = self._heuristic_ioc_score(ioc.ioc_type, ioc.value)
        feeds: List[Dict[str, Any]] = []
        listed = 0
        live_score_boost = 0

        if live:
            # Run all applicable providers in parallel
            lookup_fns = [
                (self._lookup_otx, ioc.ioc_type, ioc.value),
                (self._lookup_abuseipdb, ioc.ioc_type, ioc.value),
                (self._lookup_virustotal, ioc.ioc_type, ioc.value),
                (self._lookup_shodan, ioc.ioc_type, ioc.value),
                (self._lookup_urlscan, ioc.ioc_type, ioc.value),
            ]
            futures = {self._executor.submit(fn, t, v): fn.__name__ for fn, t, v in lookup_fns}
            for future in as_completed(futures, timeout=8):
                try:
                    feeds.append(future.result(timeout=6))
                except Exception:
                    pass

            for f in feeds:
                if f.get("enabled") and f.get("listed"):
                    listed += 1
            live_score_boost += min(40, listed * 12)
            live_score_boost += min(20, int((next((f.get("abuse_confidence", 0) for f in feeds if f.get("source") == "abuseipdb"), 0) or 0) / 10))
            live_score_boost += min(25, int(next((f.get("malicious_votes", 0) for f in feeds if f.get("source") == "virustotal"), 0) or 0))
            vuln_count = len(next((f.get("vulns", []) for f in feeds if f.get("source") == "shodan"), []))
            live_score_boost += min(20, vuln_count * 5)

        rep_score = min(100, int(h["score"]) + live_score_boost)
        reputation = ("malicious" if rep_score >= 80 else ("suspicious" if rep_score >= 55 else ("clean" if rep_score >= 30 else "unknown")))

        out = {
            "ioc_type": ioc.ioc_type,
            "value": ioc.value,
            "reputation_score": rep_score,
            "reputation": reputation,
            "listed_in": listed,
            "first_seen": self._now_iso(),
            "feeds": feeds,
            "flags": h["flags"],
        }
        self._cache_set(cache_key, out)
        return out

    # ──────────────────────────────────────────
    # Main scan entry point
    # ──────────────────────────────────────────
    def scan(
        self,
        text: Optional[str] = None,
        urls: Optional[List[str]] = None,
        domains: Optional[List[str]] = None,
        ips: Optional[List[str]] = None,
        hashes: Optional[List[str]] = None,
        live_feeds: bool = False,
    ) -> Dict[str, Any]:
        iocs: List[IOC] = []
        if text and text.strip():
            iocs.extend(self._extract_iocs(text))
        for url in urls or []:
            if url and url.strip():
                iocs.append(IOC("url", url.strip()))
        for d in domains or []:
            if d and d.strip():
                iocs.append(IOC("domain", d.strip().lower()))
        for ip in ips or []:
            if ip and ip.strip():
                iocs.append(IOC("ip", ip.strip()))
        for h in hashes or []:
            v = (h or "").strip().lower()
            if not v:
                continue
            if len(v) == 64 and re.fullmatch(r"[a-f0-9]{64}", v):
                iocs.append(IOC("hash_sha256", v))
            elif len(v) == 40 and re.fullmatch(r"[a-f0-9]{40}", v):
                iocs.append(IOC("hash_sha1", v))
            elif len(v) == 32 and re.fullmatch(r"[a-f0-9]{32}", v):
                iocs.append(IOC("hash_md5", v))

        dedup: Dict[str, IOC] = {}
        for ioc in iocs:
            key = f"{ioc.ioc_type}:{ioc.value.lower()}"
            if key not in dedup:
                dedup[key] = ioc
        items = list(dedup.values())[:60]

        # Parallel enrichment of all IOCs
        if live_feeds and items:
            futures = {self._executor.submit(self._enrich_ioc, ioc, live_feeds): ioc for ioc in items}
            results = []
            for future in as_completed(futures, timeout=15):
                try:
                    results.append(future.result(timeout=10))
                except Exception:
                    pass
        else:
            results = [self._enrich_ioc(ioc, live=False) for ioc in items]

        max_score = max((int(x.get("reputation_score", 0)) for x in results), default=0)
        overall = ("high" if max_score >= 80 else ("medium" if max_score >= 55 else ("low" if max_score >= 30 else "minimal")))

        # IOC type breakdown summary
        type_counts: Dict[str, int] = {}
        for r in results:
            t = r.get("ioc_type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "generated_at": self._now_iso(),
            "live_feeds": bool(live_feeds),
            "ioc_count": len(results),
            "overall_risk": overall,
            "max_ioc_score": max_score,
            "ioc_type_breakdown": type_counts,
            "results": sorted(results, key=lambda x: int(x.get("reputation_score", 0)), reverse=True),
        }

    # ──────────────────────────────────────────
    # Async wrapper
    # ──────────────────────────────────────────
    async def scan_async(
        self,
        text: Optional[str] = None,
        urls: Optional[List[str]] = None,
        domains: Optional[List[str]] = None,
        ips: Optional[List[str]] = None,
        hashes: Optional[List[str]] = None,
        live_feeds: bool = False,
    ) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            lambda: self.scan(text=text, urls=urls, domains=domains, ips=ips, hashes=hashes, live_feeds=live_feeds),
        )
