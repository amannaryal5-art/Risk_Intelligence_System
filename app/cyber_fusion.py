from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

if __package__:
    from .risk_engine import RiskEngine
else:
    from risk_engine import RiskEngine


class CyberFusionEngine:
    """
    Fuses text intelligence and website telemetry into five SOC modules.
    v3: richer scoring, async support, threat timeline, geo exposure stub.
    """

    def __init__(self, risk_engine: RiskEngine) -> None:
        self.risk_engine = risk_engine

    @staticmethod
    def _module_state(score: int) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "elevated"
        if score >= 35:
            return "watch"
        return "stable"

    @staticmethod
    def _clamp(score: float) -> int:
        return max(0, min(100, int(round(score))))

    def _build_modules(self, analysis: Optional[Dict[str, Any]], website: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        analysis = analysis or {}
        website = website or {}
        link_info = analysis.get("link_analysis", {})
        entity_counts = (analysis.get("entities") or {}).get("counts", {})

        risk_score = int(analysis.get("score", 0))
        confidence = int(analysis.get("confidence", 0))
        high_risk_links = int(link_info.get("high_risk_links", 0))
        total_links = int(link_info.get("total_links", 0))
        pages_crawled = int(website.get("pages_crawled", 0))
        scam_likelihood = int(website.get("scam_likelihood", 0))
        malware_likelihood = int(website.get("malware_likelihood", 0))
        coverage = int(website.get("coverage_percent", 0))
        cert_ok = int(website.get("certificate_hosts_ok", 0))
        malware_likely = int(website.get("malware_likely_pages", 0))
        malware_suspicious = int(website.get("malware_suspicious_pages", 0))
        highest_score = int(website.get("highest_score", 0))
        dimensions = analysis.get("dimensions", {})

        # ── Module 1: Attack Surface Monitoring
        attack_surface_score = self._clamp(
            (total_links * 7) + (high_risk_links * 16) + (pages_crawled * 1.2)
            + (int(website.get("discovered_host_count", 0)) * 3)
        )

        # ── Module 2: Threat Intelligence
        threat_intel_score = self._clamp(
            (risk_score * 0.55) + (confidence * 0.2) + (high_risk_links * 10)
            + (int(dimensions.get("credential_theft", 0)) * 0.12)
            + (int(dimensions.get("financial_fraud", 0)) * 0.12)
        )

        # ── Module 3: Dark Web / Data Exposure
        dark_web_score = self._clamp(
            (entity_counts.get("emails", 0) * 12) + (entity_counts.get("numeric_ids", 0) * 9)
            + (entity_counts.get("crypto_wallets", 0) * 15)
        )

        # ── Module 4: Phishing Detection
        phishing_score = self._clamp(
            (risk_score * 0.7) + (high_risk_links * 11) + (confidence * 0.12)
            + (int(dimensions.get("social_engineering", 0)) * 0.15)
            + (int(dimensions.get("coercion_pressure", 0)) * 0.10)
        )

        # ── Module 5: Vulnerability Detection
        vulnerability_score = self._clamp(
            (scam_likelihood * 0.45) + (malware_likelihood * 0.5)
            + (max(0, 60 - coverage) * 0.4) + (max(0, 2 - cert_ok) * 5)
            + (malware_likely * 12) + (malware_suspicious * 5)
        )

        # ── Module 6: Business Email Compromise (new)
        bec_score = self._clamp(
            (int(dimensions.get("financial_fraud", 0)) * 0.4)
            + (int(dimensions.get("social_engineering", 0)) * 0.4)
            + (risk_score * 0.2)
        )

        return {
            "attack_surface_monitoring": {
                "score": attack_surface_score,
                "state": self._module_state(attack_surface_score),
                "headline": f"{total_links} external refs · {pages_crawled} pages mapped · {int(website.get('discovered_host_count', 0))} hosts",
                "detail": "Monitors exposed domains, links, crawl-discovered pathways, and host diversity.",
            },
            "threat_intelligence": {
                "score": threat_intel_score,
                "state": self._module_state(threat_intel_score),
                "headline": f"Risk {risk_score}/100 · {high_risk_links} high-risk IOCs · confidence {confidence}%",
                "detail": "Correlates scoring signals, campaign-like patterns, and IOC density.",
            },
            "dark_web_monitoring": {
                "score": dark_web_score,
                "state": self._module_state(dark_web_score),
                "headline": f"{entity_counts.get('emails', 0)} email · {entity_counts.get('numeric_ids', 0)} ID · {entity_counts.get('crypto_wallets', 0)} wallet indicators",
                "detail": "Detects leak indicators from entity exposure, wallets, and numeric ID presence.",
            },
            "phishing_detection": {
                "score": phishing_score,
                "state": self._module_state(phishing_score),
                "headline": f"Phishing confidence {confidence}% · social engineering {dimensions.get('social_engineering', 0)}",
                "detail": "Detects social engineering, urgency pressure, and credential theft semantics.",
            },
            "vulnerability_detection": {
                "score": vulnerability_score,
                "state": self._module_state(vulnerability_score),
                "headline": f"Scam {scam_likelihood}% · Malware {malware_likelihood}% · Coverage {coverage}%",
                "detail": "Tracks weak points across web content, assets, certificates, and malware surface.",
            },
            "bec_detection": {
                "score": bec_score,
                "state": self._module_state(bec_score),
                "headline": f"BEC score {bec_score}/100 · financial {dimensions.get('financial_fraud', 0)} · social {dimensions.get('social_engineering', 0)}",
                "detail": "Business Email Compromise patterns: vendor fraud, wire diversion, executive impersonation.",
            },
        }

    def _stream(self, analysis: Optional[Dict[str, Any]], website: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        now = datetime.now(timezone.utc).isoformat()
        feed: List[Dict[str, Any]] = []
        if analysis:
            for sig in (analysis.get("signals") or [])[:5]:
                score = int(round(float(sig.get("score", 0.0)) * 100))
                feed.append({
                    "at": now, "source": "text-intel",
                    "severity": self._module_state(score),
                    "title": str(sig.get("name", "signal")),
                    "detail": str(sig.get("detail", ""))[:220],
                })
        if website:
            for page in (website.get("top_risky_pages") or [])[:3]:
                score = int(page.get("score", 0))
                feed.append({
                    "at": now, "source": "web-crawl",
                    "severity": self._module_state(score),
                    "title": f"Risk page: {page.get('risk_level', 'unknown')}",
                    "detail": str(page.get("url", ""))[:220],
                })
            for cert in (website.get("certificates") or []):
                if cert.get("status") == "error":
                    feed.append({
                        "at": now, "source": "cert-check",
                        "severity": "watch",
                        "title": "SSL certificate check failed",
                        "detail": f"Host: {cert.get('host', '')} — {cert.get('error', '')[:120]}",
                    })
        return feed[:10]

    def _risk_timeline(self, analysis: Optional[Dict[str, Any]], website: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build a simple threat timeline from scan artifacts."""
        now = datetime.now(timezone.utc).isoformat()
        events: List[Dict[str, Any]] = []
        if analysis:
            events.append({"at": now, "event": "text_analyzed", "risk_level": analysis.get("risk_level"), "score": analysis.get("score")})
        if website:
            events.append({"at": now, "event": "site_crawled", "pages": website.get("pages_crawled"), "verdict": website.get("site_verdict")})
            if website.get("malware_likely_pages", 0) > 0:
                events.append({"at": now, "event": "malware_detected", "pages": website.get("malware_likely_pages")})
        return events

    def fusion_scan(
        self,
        text: Optional[str] = None,
        website_url: Optional[str] = None,
        max_pages: int = 80,
        max_depth: int = 3,
        include_external: bool = False,
        exhaustive: bool = True,
    ) -> Dict[str, Any]:
        analysis: Optional[Dict[str, Any]] = None
        website: Optional[Dict[str, Any]] = None

        if text and text.strip():
            analysis = self.risk_engine.analyze(text)
        if website_url and website_url.strip():
            website = self.risk_engine.trace_website(
                website_url, max_pages=max_pages, max_depth=max_depth,
                include_external=include_external, exhaustive=exhaustive,
            )

        modules = self._build_modules(analysis, website)
        posture_score = self._clamp(sum(m["score"] for m in modules.values()) / max(len(modules), 1))
        posture_state = self._module_state(posture_score)

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "platform": "Cyber Risk Intelligence Engine v3",
            "posture_score": posture_score,
            "posture_state": posture_state,
            "modules": modules,
            "threat_stream": self._stream(analysis, website),
            "risk_timeline": self._risk_timeline(analysis, website),
            "text_analysis": analysis,
            "website_trace": website,
        }

    async def fusion_scan_async(
        self,
        text: Optional[str] = None,
        website_url: Optional[str] = None,
        max_pages: int = 80,
        max_depth: int = 3,
        include_external: bool = False,
        exhaustive: bool = True,
    ) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.risk_engine._executor,
            lambda: self.fusion_scan(text=text, website_url=website_url, max_pages=max_pages,
                                     max_depth=max_depth, include_external=include_external, exhaustive=exhaustive),
        )
