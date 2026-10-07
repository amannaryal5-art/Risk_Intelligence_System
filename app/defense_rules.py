"""
SOAR Defense & Mitigation Generator.
Transforms indicators (IPs, Domains, URLs, Hashes) into ready-to-deploy firewall rules,
Suricata/Snort NIDS signatures, and DNS sinkhole entries.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlsplit


class DefenseRuleGenerator:
    """Generates firewall, NIDS (Snort/Suricata), and DNS mitigation playbooks."""

    @staticmethod
    def generate_playbook(
        ips: List[str] | None = None,
        domains: List[str] | None = None,
        urls: List[str] | None = None,
        hashes: List[str] | None = None,
        title: str = "CRIE Autonomous Defense Playbook",
    ) -> Dict[str, Any]:
        ips = [ip.strip() for ip in (ips or []) if ip.strip()]
        domains = [d.strip().lower() for d in (domains or []) if d.strip()]
        urls = [u.strip() for u in (urls or []) if u.strip()]
        hashes = [h.strip().lower() for h in (hashes or []) if h.strip()]

        sid_start = 9100000

        # 1. Linux iptables & UFW
        iptables_lines: List[str] = ["# --- Linux iptables ---"]
        ufw_lines: List[str] = ["# --- Linux UFW ---"]
        win_firewall: List[str] = ["# --- Windows Defender Firewall (PowerShell) ---"]

        for ip in ips:
            iptables_lines.append(f"iptables -A INPUT -s {ip} -j DROP")
            iptables_lines.append(f"iptables -A OUTPUT -d {ip} -j DROP")
            ufw_lines.append(f"ufw deny from {ip} to any")
            win_firewall.append(f'New-NetFirewallRule -DisplayName "CRIE-Block-{ip}" -Direction Outbound -RemoteAddress {ip} -Action Block')

        # 2. Cisco ASA ACLs
        cisco_lines: List[str] = ["! --- Cisco ASA Access List ---"]
        for ip in ips:
            cisco_lines.append(f"access-list CRIE_BLOCK extended deny ip any host {ip}")

        # 3. Suricata / Snort NIDS Signatures
        suricata_lines: List[str] = ["# --- Suricata / Snort 3 Rules ---"]
        for ip in ips:
            sid_start += 1
            suricata_lines.append(
                f'drop ip $HOME_NET any -> {ip} any (msg:"CRIE_THREAT: Connection to Malicious IP {ip}"; classtype:trojan-activity; sid:{sid_start}; rev:1;)'
            )

        for d in domains:
            sid_start += 1
            suricata_lines.append(
                f'drop dns $HOME_NET any -> any 53 (msg:"CRIE_THREAT: Query to Flagged Domain {d}"; dns.query; content:"{d}"; nocase; sid:{sid_start}; rev:1;)'
            )

        for u in urls:
            parsed = urlsplit(u if "://" in u else f"http://{u}")
            path = parsed.path or "/"
            sid_start += 1
            suricata_lines.append(
                f'drop http $HOME_NET any -> $EXTERNAL_NET any (msg:"CRIE_THREAT: Request to Malicious URL Path {path[:40]}"; http.uri; content:"{path}"; nocase; sid:{sid_start}; rev:1;)'
            )

        # 4. DNS Sinkhole / Pi-hole / Hosts
        sinkhole_lines: List[str] = ["# --- Pi-hole / /etc/hosts Format ---"]
        for d in domains:
            sinkhole_lines.append(f"0.0.0.0 {d}")
            sinkhole_lines.append(f"0.0.0.0 www.{d}")

        # 5. YARA Rule for Hashes
        yara_lines: List[str] = [
            '/* --- YARA IOC Rule --- */',
            f'rule CRIE_Blocked_Hashes_{datetime.now(timezone.utc).strftime("%Y%m%d")}',
            '{',
            '    meta:',
            f'        description = "{title}"',
            f'        created_at = "{datetime.now(timezone.utc).isoformat()}"',
            '    condition:',
        ]
        if hashes:
            hash_checks = [f'hash.sha256(0, filesize) == "{h}"' for h in hashes]
            yara_lines.append('        ' + ' or\n        '.join(hash_checks))
        else:
            yara_lines.append('        false')
        yara_lines.append('}')

        return {
            "title": title,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "indicator_counts": {
                "ips": len(ips),
                "domains": len(domains),
                "urls": len(urls),
                "hashes": len(hashes),
            },
            "rules": {
                "iptables": "\n".join(iptables_lines),
                "ufw": "\n".join(ufw_lines),
                "windows_firewall": "\n".join(win_firewall),
                "cisco_asa": "\n".join(cisco_lines),
                "suricata": "\n".join(suricata_lines),
                "dns_sinkhole": "\n".join(sinkhole_lines),
                "yara": "\n".join(yara_lines),
            },
        }

