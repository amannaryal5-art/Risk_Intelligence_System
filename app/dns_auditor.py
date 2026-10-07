"""
Domain, Email Spoofing, and Certificate Transparency (CT) Auditor.
Audits SPF, DMARC, MX records, and enumerates subdomains via CT logs.
"""

from __future__ import annotations

import json
import logging
import socket
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote

logger = logging.getLogger("riskintel.dns_auditor")


class DnsAuditor:
    """Audits domain DNS, email impersonation protection (SPF/DMARC), and subdomains."""

    def __init__(self, timeout: float = 4.0) -> None:
        self.timeout = timeout

    def _doh_query(self, name: str, rtype: str = "TXT") -> List[str]:
        """Queries DNS-over-HTTPS (DoH) via Google DNS and Cloudflare."""
        endpoints = [
            f"https://dns.google/resolve?name={quote(name)}&type={quote(rtype)}",
            f"https://cloudflare-dns.com/dns-query?name={quote(name)}&type={quote(rtype)}",
        ]
        for url in endpoints:
            try:
                req = urllib.request.Request(
                    url,
                    headers={"Accept": "application/dns-json", "User-Agent": "RiskIntel-Auditor/1.0"},
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    answers = data.get("Answer", [])
                    records = []
                    for a in answers:
                        val = a.get("data", "").strip('"')
                        if val:
                            records.append(val)
                    if records:
                        return records
            except Exception as exc:
                logger.debug("DoH query failed on %s: %s", url, exc)
        return []

    def get_subdomains_crtsh(self, domain: str, limit: int = 25) -> List[str]:
        """Queries public Certificate Transparency logs via crt.sh to discover subdomains."""
        clean = domain.strip().lower()
        url = f"https://crt.sh/?q=%.{quote(clean)}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "RiskIntel/1.0"})
        subdomains: set[str] = set()
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                for entry in data[:100]:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.splitlines():
                        sub = sub.strip().lower()
                        if sub.endswith(clean) and not sub.startswith("*"):
                            subdomains.add(sub)
        except Exception:
            pass
        return sorted(list(subdomains))[:limit]

    def audit_domain(self, domain: str) -> Dict[str, Any]:
        """Performs full email spoofing and DNS security posture audit."""
        clean = domain.strip().lower().lstrip("https://").lstrip("http://").split("/")[0]

        # 1. Resolve IP
        try:
            ip = socket.gethostbyname(clean)
        except OSError:
            ip = ""

        # 2. Query MX, SPF, DMARC
        mx_records = self._doh_query(clean, "MX")
        txt_records = self._doh_query(clean, "TXT")
        dmarc_records = self._doh_query(f"_dmarc.{clean}", "TXT")

        # Parse SPF
        spf_record = next((r for r in txt_records if r.startswith("v=spf1")), None)
        spf_policy = "unknown"
        spf_vulnerable = False
        if spf_record:
            if "+all" in spf_record:
                spf_policy = "allow_all (+all)"
                spf_vulnerable = True
            elif "~all" in spf_record:
                spf_policy = "softfail (~all)"
            elif "-all" in spf_record:
                spf_policy = "hardfail (-all)"
            elif "?all" in spf_record:
                spf_policy = "neutral (?all)"
                spf_vulnerable = True
        else:
            spf_policy = "missing"
            spf_vulnerable = True

        # Parse DMARC
        dmarc_record = next((r for r in dmarc_records if r.startswith("v=DMARC1")), None)
        dmarc_policy = "missing"
        dmarc_vulnerable = False
        if dmarc_record:
            for part in dmarc_record.split(";"):
                part = part.strip()
                if part.startswith("p="):
                    dmarc_policy = part.split("=")[1].lower()
                    if dmarc_policy == "none":
                        dmarc_vulnerable = True
        else:
            dmarc_vulnerable = True

        # Calculate Spoofing Risk Score
        risk_score = 0
        findings: List[Dict[str, Any]] = []

        if dmarc_policy == "missing":
            risk_score += 45
            findings.append({"status": "CRITICAL", "message": "No DMARC record found. Anyone can forge emails from this domain."})
        elif dmarc_policy == "none":
            risk_score += 30
            findings.append({"status": "WARNING", "message": "DMARC policy is set to 'p=none' (monitoring only). Spoofed emails are not blocked."})
        else:
            findings.append({"status": "PASS", "message": f"DMARC enforcement active (p={dmarc_policy})."})

        if spf_policy == "missing":
            risk_score += 35
            findings.append({"status": "HIGH", "message": "No SPF record found. Email senders are not authenticated."})
        elif spf_vulnerable:
            risk_score += 30
            findings.append({"status": "HIGH", "message": f"SPF policy '{spf_policy}' is overly permissive."})
        else:
            findings.append({"status": "PASS", "message": f"SPF configured correctly ({spf_policy})."})

        if not mx_records:
            findings.append({"status": "INFO", "message": "No MX records found. Domain may not receive inbound email."})

        subdomains = self.get_subdomains_crtsh(clean)

        verdict = "HIGH VULNERABILITY" if risk_score >= 60 else "MODERATE VULNERABILITY" if risk_score >= 30 else "PROTECTED"

        return {
            "domain": clean,
            "ip": ip,
            "email_spoof_risk_score": min(100, risk_score),
            "verdict": verdict,
            "dmarc": {
                "record": dmarc_record,
                "policy": dmarc_policy,
                "vulnerable": dmarc_vulnerable,
            },
            "spf": {
                "record": spf_record,
                "policy": spf_policy,
                "vulnerable": spf_vulnerable,
            },
            "mx_records": mx_records[:8],
            "findings": findings,
            "subdomains_discovered": subdomains,
            "subdomain_count": len(subdomains),
            "audited_at": datetime.now(timezone.utc).isoformat(),
        }
