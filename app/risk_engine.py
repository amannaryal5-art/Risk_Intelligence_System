from __future__ import annotations

import asyncio
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen


class RiskEngine:
    """Local, explainable risk scoring for suspicious text and web pages."""

    _url = re.compile(r"(?:https?://|www\.)[^\s<>'\"]+", re.I)
    _ip = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _email = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
    _hash = re.compile(r"\b[a-fA-F0-9]{32}(?:[a-fA-F0-9]{8})?(?:[a-fA-F0-9]{24})?\b")
    _link = re.compile(r"href=[\"']([^\"'#]+)", re.I)
    _terms = {
        "credential_theft": ("password", "login", "verify your account", "sign in", "otp"),
        "financial_fraud": ("wire transfer", "upi", "gift card", "crypto", "bank account", "payment"),
        "social_engineering": ("urgent", "immediately", "suspended", "confirm now", "act now"),
        "malware": ("download", "attachment", "powershell", "cmd.exe", "macro", "invoice.exe"),
    }

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=6, thread_name_prefix="risk")

    @staticmethod
    def _level(score: int) -> str:
        return "critical" if score >= 80 else "high" if score >= 55 else "medium" if score >= 30 else "low"

    def analyze(self, text: str) -> dict[str, Any]:
        value = text.strip()
        lowered = value.lower()
        signals: list[dict[str, Any]] = []
        dimensions: dict[str, int] = {}
        score = 0
        for name, terms in self._terms.items():
            hits = [term for term in terms if term in lowered]
            dimension = min(100, len(hits) * 28)
            dimensions[name] = dimension
            if hits:
                points = min(35, len(hits) * 12)
                score += points
                signals.append({"name": name, "score": points / 100, "detail": f"Matched: {', '.join(hits)}"})
        urls = [item.rstrip(".,;:)") for item in self._url.findall(value)]
        insecure = [item for item in urls if item.lower().startswith("http://")]
        if insecure:
            score += min(20, 8 * len(insecure))
            signals.append({"name": "insecure_link", "score": 0.12, "detail": "Contains unencrypted HTTP link"})
        suspicious_links = [item for item in urls if any(term in item.lower() for term in ("login", "verify", "secure", "account", "update"))]
        if suspicious_links:
            score += min(20, 10 * len(suspicious_links))
            signals.append({"name": "suspicious_link", "score": 0.18, "detail": "Link contains credential or account language"})
        score = min(100, score)
        entities = {"urls": urls[:20], "ips": self._ip.findall(value)[:20], "emails": self._email.findall(value)[:20], "hashes": self._hash.findall(value)[:20]}
        entities["counts"] = {key: len(items) for key, items in entities.items() if isinstance(items, list)}
        return {"input": value, "score": score, "risk_level": self._level(score), "confidence": min(100, 25 + len(signals) * 18 + len(urls) * 4), "signals": signals, "dimensions": dimensions, "entities": entities, "link_analysis": {"total_links": len(urls), "high_risk_links": len(suspicious_links), "insecure_links": len(insecure)}, "analyzed_at": datetime.now(timezone.utc).isoformat()}

    async def analyze_async(self, text: str) -> dict[str, Any]:
        return await asyncio.get_running_loop().run_in_executor(self._executor, self.analyze, text)

    async def analyze_batch_async(self, texts: list[str]) -> list[dict[str, Any]]:
        return await asyncio.gather(*(self.analyze_async(text) for text in texts))

    def _whois_domain_age_profile(self, hostname: str) -> dict[str, object]:
        """WHOIS is deliberately not queried: it is unreliable and often rate limited."""
        return {"hostname": hostname, "available": False, "reason": "WHOIS lookup is not part of the local scoring pipeline"}

    def trace_website(self, url: str, max_pages: int = 40, max_depth: int = 2, include_external: bool = False, exhaustive: bool = True) -> dict[str, Any]:
        normalized = url if "://" in url else f"https://{url}"
        parsed = urlsplit(normalized)
        if not parsed.hostname:
            raise ValueError("Provide a valid URL or domain")
        pages: list[dict[str, Any]] = []
        seen = {normalized}
        pending = [(normalized, 0)]
        while pending and len(pages) < max_pages:
            current, depth = pending.pop(0)
            try:
                request = Request(current, headers={"User-Agent": "RiskIntel/1.0"})
                with urlopen(request, timeout=6) as response:
                    body = response.read(300_000).decode("utf-8", errors="ignore")
                analysis = self.analyze(body)
                pages.append({"url": current, "score": analysis["score"], "risk_level": analysis["risk_level"]})
                if depth < max_depth:
                    for href in self._link.findall(body):
                        candidate = urljoin(current, href)
                        host = urlsplit(candidate).hostname
                        if host and candidate not in seen and (include_external or host == parsed.hostname):
                            seen.add(candidate); pending.append((candidate, depth + 1))
            except Exception as exc:
                pages.append({"url": current, "score": 0, "risk_level": "unknown", "error": str(exc)[:120]})
        scores = [int(page["score"]) for page in pages]
        highest = max(scores, default=0)
        return {"input": normalized, "pages_crawled": len(pages), "highest_score": highest, "site_verdict": "DANGER" if highest >= 70 else "CAUTION" if highest >= 30 else "SAFE", "scam_likelihood": highest, "malware_likelihood": max((int(page["score"]) for page in pages if page.get("risk_level") in {"high", "critical"}), default=0), "coverage_percent": 100 if pages else 0, "certificate_hosts_ok": 0, "malware_likely_pages": sum(1 for page in pages if int(page["score"]) >= 80), "malware_suspicious_pages": sum(1 for page in pages if int(page["score"]) >= 55), "discovered_host_count": len({urlsplit(page["url"]).hostname for page in pages}), "top_risky_pages": sorted(pages, key=lambda page: int(page["score"]), reverse=True)[:10], "pages": pages[:max_pages]}
