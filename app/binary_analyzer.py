"""
Advanced Static Binary & File Analyzer.
Performs PE header parsing, section entropy calculation, suspicious API extraction,
and automated YARA rule generation.
"""

from __future__ import annotations

import hashlib
import math
import re
import struct
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


def calculate_entropy(data: bytes) -> float:
    """Calculates the Shannon entropy of a byte sequence (range: 0.0 - 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


class BinaryAnalyzer:
    """Deep static analysis engine for executables, scripts, and documents."""

    SUSPICIOUS_APIS = {
        "process_injection": [
            "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "QueueUserAPC", "SetThreadContext", "NtQueueApcThread", "RtlCreateUserThread",
        ],
        "evasion_anti_debug": [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString",
            "VirtualProtect", "VirtualProtectEx", "NtQueryInformationProcess",
        ],
        "persistence_execution": [
            "RegSetValueEx", "RegCreateKeyEx", "CreateService", "ShellExecute",
            "WinExec", "CreateProcess", "CreateProcessW", "WScript.Shell",
        ],
        "network_c2": [
            "InternetOpen", "HttpOpenRequest", "InternetConnect", "URLDownloadToFile",
            "WSAStartup", "connect", "send", "recv", "WinHttpOpen",
        ],
        "credential_access": [
            "CryptUnprotectData", "LsaEnumerateLogonSessions", "MiniDumpWriteDump",
            "SamIConnect", "SamrQueryInformationUser",
        ],
    }

    SCRIPT_PATTERNS = [
        (re.compile(rb"(?:powershell|pwsh)(?:\.exe)?", re.I), "PowerShell invocation"),
        (re.compile(rb"-enc(?:odedcommand)?\s+[a-z0-9+/=]{12,}", re.I), "Encoded PowerShell command"),
        (re.compile(rb"invoke-expression|iex\b", re.I), "Dynamic code execution (IEX)"),
        (re.compile(rb"downloadstring|downloadfile", re.I), "Remote payload download"),
        (re.compile(rb"bypass\s+-nop", re.I), "Execution policy bypass flags"),
        (re.compile(rb"(?:wscript|cscript)(?:\.exe)?", re.I), "Windows Script Host invocation"),
        (re.compile(rb"vba_project|autoopen|document_open|workbook_open", re.I), "Office Macro auto-execution"),
        (re.compile(rb"/JavaScript|/JS\b|/Launch\b|/OpenAction\b", re.I), "Suspicious PDF active element"),
    ]

    @staticmethod
    def _parse_pe(data: bytes) -> Dict[str, Any]:
        """Parses DOS, COFF, Optional headers and Section Table of a PE file."""
        if len(data) < 64 or not data.startswith(b"MZ"):
            return {"is_pe": False}

        try:
            (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
            if e_lfanew + 24 > len(data):
                return {"is_pe": False, "corrupt": True}

            pe_sig = data[e_lfanew : e_lfanew + 4]
            if pe_sig != b"PE\x00\x00":
                return {"is_pe": False}

            # COFF Header (20 bytes)
            coff_offset = e_lfanew + 4
            machine, num_sections, timedatestamp, _, _, opt_hdr_size, characteristics = struct.unpack_from(
                "<HHIIIHH", data, coff_offset
            )

            machine_map = {0x014C: "x86 (32-bit)", 0x8664: "x64 (64-bit)", 0x0200: "Itanium", 0xAA64: "ARM64"}
            machine_str = machine_map.get(machine, f"Unknown (0x{machine:04x})")

            # Section headers
            sec_offset = coff_offset + 20 + opt_hdr_size
            sections: List[Dict[str, Any]] = []
            is_packed = False

            for i in range(min(num_sections, 32)):
                if sec_offset + 40 > len(data):
                    break
                sec_bytes = data[sec_offset : sec_offset + 40]
                name_raw = sec_bytes[:8].split(b"\x00", 1)[0].decode("ascii", errors="ignore").strip()
                vsize, vaddr, raw_size, raw_offset = struct.unpack_from("<IIII", sec_bytes, 8)

                sec_data = data[raw_offset : raw_offset + raw_size] if raw_offset + raw_size <= len(data) else b""
                entropy = calculate_entropy(sec_data) if sec_data else 0.0

                if entropy >= 7.2 or name_raw.lower() in {".upx0", ".upx1", ".aspack", ".vmp0", ".themida"}:
                    is_packed = True

                sections.append({
                    "index": i + 1,
                    "name": name_raw or f"sec_{i+1}",
                    "virtual_size": vsize,
                    "raw_size": raw_size,
                    "entropy": entropy,
                    "suspicious_entropy": entropy >= 7.0,
                })
                sec_offset += 40

            return {
                "is_pe": True,
                "machine": machine_str,
                "num_sections": num_sections,
                "is_dll": bool(characteristics & 0x2000),
                "is_packed": is_packed,
                "timestamp_utc": datetime.fromtimestamp(timedatestamp, tz=timezone.utc).isoformat() if timedatestamp > 0 else "Unknown",
                "sections": sections,
            }
        except Exception as exc:
            return {"is_pe": True, "parse_error": str(exc)}

    def analyze_file(self, filename: str, data: bytes) -> Dict[str, Any]:
        """Full static analysis of raw file bytes."""
        size = len(data)
        sha256 = hashlib.sha256(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()

        overall_entropy = calculate_entropy(data)
        pe_info = self._parse_pe(data)

        # Scan for suspicious APIs
        sample_text = data.decode("latin-1", errors="ignore")
        detected_apis: Dict[str, List[str]] = {}
        total_apis = 0

        for category, api_list in self.SUSPICIOUS_APIS.items():
            hits = [api for api in api_list if api in sample_text]
            if hits:
                detected_apis[category] = hits
                total_apis += len(hits)

        # Scan for script and execution patterns
        detected_script_signals: List[str] = []
        for pattern, desc in self.SCRIPT_PATTERNS:
            if pattern.search(data):
                detected_script_signals.append(desc)

        # Compute risk score
        risk_score = 0
        signals: List[Dict[str, Any]] = []

        if pe_info.get("is_pe"):
            signals.append({"signal": "PE Header Detected", "severity": "info", "points": 10})
            if pe_info.get("is_packed"):
                risk_score += 35
                signals.append({"signal": "High Section Entropy / Known Packer", "severity": "high", "points": 35})
        elif overall_entropy > 7.3:
            risk_score += 25
            signals.append({"signal": f"High Overall Entropy ({overall_entropy:.2f}/8.0 - Packed/Encrypted)", "severity": "medium", "points": 25})

        if detected_script_signals:
            pts = min(40, len(detected_script_signals) * 15)
            risk_score += pts
            signals.append({"signal": f"Script/Macro Execution Patterns: {', '.join(detected_script_signals)}", "severity": "critical" if pts > 25 else "high", "points": pts})

        if total_apis > 0:
            pts = min(45, total_apis * 8)
            risk_score += pts
            signals.append({"signal": f"Suspicious Windows APIs ({total_apis} calls across {len(detected_apis)} categories)", "severity": "high", "points": pts})

        # Risky extensions
        lower_name = filename.lower()
        if lower_name.endswith((".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".hta", ".iso")):
            risk_score += 20
            signals.append({"signal": f"Executable or Script Extension: {lower_name.split('.')[-1]}", "severity": "medium", "points": 20})

        final_score = min(100, risk_score)
        level = "critical" if final_score >= 80 else "high" if final_score >= 55 else "medium" if final_score >= 30 else "low"

        # Generate YARA rule
        yara_rule = self._generate_yara(filename, sha256, detected_apis, detected_script_signals, pe_info)

        return {
            "filename": filename,
            "size_bytes": size,
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "entropy": overall_entropy,
            "entropy_assessment": "High (Likely packed, encrypted, or compressed)" if overall_entropy >= 7.0 else "Normal (Uncompressed plaintext / code)",
            "risk_score": final_score,
            "risk_level": level,
            "pe_metadata": pe_info,
            "detected_apis": detected_apis,
            "detected_script_signals": detected_script_signals,
            "signals": signals,
            "yara_rule": yara_rule,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }

    def _generate_yara(
        self,
        filename: str,
        sha256: str,
        apis: Dict[str, List[str]],
        script_signals: List[str],
        pe_info: Dict[str, Any],
    ) -> str:
        """Generates a deployable YARA rule for incident response teams."""
        safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", filename.rsplit(".", 1)[0]) or "Suspicious_Sample"
        rule_name = f"Detect_{safe_name}"

        strings_block: List[str] = []
        idx = 1
        for cat, api_list in apis.items():
            for api in api_list[:4]:
                strings_block.append(f'        $api_{idx} = "{api}" ascii wide')
                idx += 1

        for sig in script_signals[:3]:
            safe_sig = sig.split(" ")[0]
            strings_block.append(f'        $sig_{idx} = "{safe_sig}" ascii wide nocase')
            idx += 1

        if not strings_block:
            strings_block.append('        $s1 = "powershell" ascii wide nocase')
            strings_block.append('        $s2 = "cmd.exe" ascii wide nocase')

        strings_str = "\n".join(strings_block)

        condition = "uint16(0) == 0x5A4D and " if pe_info.get("is_pe") else ""
        condition += f"2 of ($*)" if len(strings_block) >= 2 else "1 of ($*)"

        return f"""rule {rule_name}
{{
    meta:
        description = "Auto-generated rule for {filename}"
        reference_sha256 = "{sha256}"
        author = "CRIE Autonomous Threat Hunting"
        generated_at = "{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"

    strings:
{strings_str}

    condition:
        {condition}
}}"""

