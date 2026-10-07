"""
Threat Graph & IOC Correlation Service.
Builds node-link relationship graphs between URLs, Domains, IPs, Hashes, and MITRE ATT&CK tactics.
"""

from __future__ import annotations

import socket
from typing import Any, Dict, List
from urllib.parse import urlsplit


class ThreatGraphBuilder:
    """Builds interactive graph topology for indicators and related entities."""

    @staticmethod
    def build_graph(
        target: str,
        kind: str,
        scan_data: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        seen_nodes: set[str] = set()

        def add_node(node_id: str, label: str, node_type: str, risk: str = "medium", meta: Any = None) -> None:
            if node_id not in seen_nodes:
                seen_nodes.add(node_id)
                nodes.append({
                    "id": node_id,
                    "label": label,
                    "type": node_type,
                    "risk": risk,
                    "meta": meta or {},
                })

        def add_edge(src: str, dst: str, relation: str) -> None:
            edge_id = f"{src}->{dst}:{relation}"
            edges.append({
                "id": edge_id,
                "source": src,
                "target": dst,
                "label": relation,
            })

        scan_data = scan_data or {}
        overall_risk = str(scan_data.get("risk_level", scan_data.get("overall_risk", "medium"))).lower()

        # Root target node
        root_id = f"target:{target}"
        add_node(root_id, target, kind, risk=overall_risk, meta={"is_root": True})

        if kind in {"url", "domain"}:
            host = urlsplit(target if "://" in target else f"http://{target}").hostname or target
            host_id = f"domain:{host}"
            if host_id != root_id:
                add_node(host_id, host, "domain", risk=overall_risk)
                add_edge(root_id, host_id, "references_host")

            # Try resolving IP
            resolved_ip = scan_data.get("ip")
            if not resolved_ip:
                try:
                    resolved_ip = socket.gethostbyname(host)
                except OSError:
                    resolved_ip = ""

            if resolved_ip:
                ip_id = f"ip:{resolved_ip}"
                add_node(ip_id, resolved_ip, "ip", risk=overall_risk)
                add_edge(host_id, ip_id, "resolves_to")

                # ASN stub / Infrastructure
                asn_id = f"asn:AS_{resolved_ip.replace('.', '_')[:8]}"
                add_node(asn_id, f"Routing Network / ASN", "asn", risk="low")
                add_edge(ip_id, asn_id, "routed_by")

        elif kind == "ip":
            # Reverse PTR or Routing
            asn_id = f"asn:AS_Network"
            add_node(asn_id, "Public Autonomous System", "asn", risk="low")
            add_edge(root_id, asn_id, "originated_from")

        elif kind == "file" or kind == "hash":
            sha256 = scan_data.get("sha256", target)
            hash_id = f"hash:{sha256[:16]}"
            add_node(hash_id, f"SHA256: {sha256[:12]}...", "hash", risk=overall_risk)
            if root_id != hash_id:
                add_edge(root_id, hash_id, "payload_hash")

            # Add MITRE tactic
            mitre_id = "mitre:T1204_User_Execution"
            add_node(mitre_id, "MITRE T1204: User Execution", "mitre_tactic", risk="high")
            add_edge(root_id, mitre_id, "exhibits_behavior")

        # Map Feeds from scan_data
        feeds = scan_data.get("feeds", {})
        if isinstance(feeds, dict):
            for provider, pdata in feeds.items():
                if isinstance(pdata, dict) and pdata.get("listed"):
                    prov_id = f"intel:{provider}"
                    add_node(prov_id, f"{provider.upper()} Pulse", "threat_pulse", risk="critical", meta=pdata)
                    add_edge(root_id, prov_id, "flagged_by")

        # Fallback MITRE nodes for high risk
        if overall_risk in {"high", "critical"}:
            m1 = "mitre:T1566_Phishing"
            add_node(m1, "MITRE T1566: Phishing / Ingress", "mitre_tactic", risk="critical")
            add_edge(root_id, m1, "tactical_alignment")

        return {
            "target": target,
            "kind": kind,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": nodes,
            "edges": edges,
        }

