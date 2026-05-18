"""
Host device EDR scan agent — collectors for network, processes, ports, software, DNS, startup, system info.

Uses subprocess with argument lists only (no shell). All OS probes are isolated so one failure
does not stop the scan.
"""

from __future__ import annotations

import asyncio
import getpass
import hashlib
import ipaddress
import json
import logging
import os
import platform
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger("riskintel.device_scan")

ALLOWED_EXECUTABLES = frozenset(
    {
        "netstat",
        "ss",
        "ps",
        "powershell",
        "pwsh",
        "ipconfig",
        "schtasks",
        "systemctl",
        "dpkg",
        "rpm",
        "launchctl",
        "taskkill",
        "kill",
        "netsh",
        "iptables",
        "uname",
        "uptime",
        "dscacheutil",
        "sw_vers",
        "system_profiler",
        "resolvectl",
    }
)

KNOWN_SAFE_PORTS = {80, 443, 3000, 5173, 5432, 8080, 8443, 22, 3306}
CMD_TIMEOUT = 30
MAX_FILE_HASH_BYTES = 500 * 1024 * 1024
VT_BATCH_SIZE = 4
VT_BATCH_SLEEP_SEC = 15.0
ABUSE_CONCURRENCY = 8

_DOUBLE_EXT = re.compile(r"\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|zip|txt)\.(exe|bat|cmd|scr|pif)$", re.I)
RAT_PORTS = {4444, 1337, 31337, 8888, 9999, 1234}
SAFE_PORTS = {22, 53, 80, 443, 3000, 3001, 3306, 5173, 5432, 5433, 5434, 6379, 8080, 8443, 27017}


def _memory_stats() -> Tuple[Optional[float], Optional[float]]:
    """Return (total_gb, free_gb) without external dependencies."""
    try:
        if sys.platform == "win32":
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                return round(stat.ullTotalPhys / 1024**3, 1), round(stat.ullAvailPhys / 1024**3, 1)
        elif sys.platform == "linux":
            meminfo = Path("/proc/meminfo").read_text(encoding="utf-8", errors="replace")
            total = free = None
            for line in meminfo.splitlines():
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1]) / 1024 / 1024
                if line.startswith("MemAvailable:"):
                    free = int(line.split()[1]) / 1024 / 1024
            if total is not None:
                return round(total, 1), round(free or 0, 1)
    except OSError:
        pass
    return None, None


def _uptime_seconds() -> Optional[int]:
    try:
        if sys.platform == "linux":
            raw = Path("/proc/uptime").read_text(encoding="utf-8", errors="replace").split()
            return int(float(raw[0])) if raw else None
        if sys.platform == "darwin":
            proc = subprocess.run(["sysctl", "-n", "kern.boottime"], capture_output=True, text=True, timeout=5)
            if proc.returncode == 0 and "sec" in proc.stdout:
                sec = int(proc.stdout.split("=")[-1].strip().split()[0])
                return max(0, int(time.time()) - sec)
        if sys.platform == "win32":
            proc = subprocess.run(
                [
                    "powershell",
                    "-NonInteractive",
                    "-Command",
                    "[int]((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalSeconds",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if proc.returncode == 0 and proc.stdout.strip().isdigit():
                return int(proc.stdout.strip())
    except OSError:
        pass
    return None


def get_builtin_system_info() -> Dict[str, Any]:
    """Host facts from Python/stdlib — no dependency on a completed scan session."""
    ram_total, ram_free = _memory_stats()
    cpus = os.cpu_count() or 1
    cpu_model = platform.processor() or ""
    if not cpu_model.strip():
        cpu_model = f"{cpus} logical CPU(s)"
    try:
        user = getpass.getuser()
    except Exception:
        user = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
    plat = sys.platform
    os_name = "Windows" if plat == "win32" else "macOS" if plat == "darwin" else "Linux"
    return {
        "hostname": socket.gethostname(),
        "platform": plat,
        "os_name": os_name,
        "os_version": f"{os_name} {platform.release()}".strip(),
        "os_build": platform.version(),
        "cpu_model": cpu_model,
        "cpu_cores": cpus,
        "ram_total_gb": ram_total,
        "ram_free_gb": ram_free,
        "ram_gb": ram_total,
        "uptime_seconds": _uptime_seconds(),
        "current_user": user,
        "arch": platform.machine(),
        "network_interfaces": [],
        "firewall_status": "unknown",
        "av_status": "unknown",
    }


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=True)


def is_private_ip(addr: str) -> bool:
    if not addr or addr in {"*", "0.0.0.0", "::", "::0"}:
        return True
    a = addr.strip().lower()
    if a in {"127.0.0.1", "localhost", "::1"}:
        return True
    try:
        ip = ipaddress.ip_address(a.split("%")[0])
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except ValueError:
        return True


def validate_ipv4_block(ip: str) -> bool:
    m = re.fullmatch(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", (ip or "").strip())
    if not m:
        return False
    parts = [int(m.group(i)) for i in range(1, 5)]
    return all(0 <= p <= 255 for p in parts)


def validate_kill_pid(pid: int) -> bool:
    return 0 < pid < 1_000_000


def suspicious_process_path(path: str, plat: str) -> Tuple[bool, str]:
    if not path or not str(path).strip():
        return True, "empty_or_missing_path"
    p = path.replace("/", "\\").lower() if plat == "win32" else path.lower()
    if _DOUBLE_EXT.search(path):
        return True, "double_extension_executable"
    if plat == "win32":
        checks = [
            (r"\\temp\\", "temp_directory"),
            (r"\\appdata\\roaming\\", "roaming_directory"),
            (r"\\downloads\\", "downloads_directory"),
        ]
        for pat, reason in checks:
            if pat in p and p.endswith(".exe"):
                return True, reason
    else:
        if "/tmp/" in p or "/var/tmp/" in p:
            return True, "temp_directory"
        if "downloads" in p and (p.endswith(".exe") or ".exe" in p):
            return True, "downloads_executable"
    return False, ""


def resolve_executable(name: str) -> str:
    base = os.path.basename(name).lower()
    if base not in ALLOWED_EXECUTABLES and name.lower() not in {e.lower() for e in ALLOWED_EXECUTABLES}:
        raise ValueError(f"Executable not allowlisted: {name}")
    resolved = shutil.which(name) if os.path.dirname(name) == "" else name
    if not resolved or not os.path.isfile(resolved):
        raise FileNotFoundError(f"Executable not found: {name}")
    rb = os.path.basename(resolved).lower()
    if rb not in ALLOWED_EXECUTABLES:
        raise ValueError(f"Resolved executable not allowlisted: {resolved}")
    return resolved


def run_exec(
    exe_name: str,
    args: Sequence[str],
    *,
    audit: Optional[Callable[..., Any]] = None,
    triggered_by: str = "device_scan",
) -> Tuple[int, str, str]:
    """Run allowlisted executable with fixed timeout. Returns (returncode, stdout, stderr)."""
    started = time.perf_counter()
    exe = resolve_executable(exe_name)
    full = [exe, *args]
    ok = False
    code = -1
    out = ""
    err = ""
    try:
        proc = subprocess.run(
            full,
            capture_output=True,
            text=True,
            timeout=CMD_TIMEOUT,
            shell=False,
            encoding="utf-8",
            errors="replace",
        )
        code = proc.returncode
        out = proc.stdout or ""
        err = proc.stderr or ""
        ok = code == 0
    except Exception as exc:
        err = str(exc)
        logger.warning("run_exec failed %s %s: %s", exe_name, args[:3], exc)
    duration_ms = int((time.perf_counter() - started) * 1000)
    if audit:
        try:
            audit(
                {
                    "command": exe_name,
                    "args_redacted": "[REDACTED]",
                    "success": ok,
                    "duration_ms": duration_ms,
                    "triggered_by": triggered_by,
                    "returncode": code,
                }
            )
        except Exception:
            pass
    return code, out, err


def sha256_file_stream(path: str) -> Optional[str]:
    try:
        st = os.stat(path)
        if st.st_size > MAX_FILE_HASH_BYTES or not os.path.isfile(path):
            return None
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


@dataclass
class CollectorResult:
    name: str
    ok: bool
    summary: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class DeviceScanAgent:
    """Runs parallel collectors and persists rows for a device_scan_sessions row."""

    def __init__(self, automation: Any, user_id: str, session_id: str, triggered_by: str) -> None:
        self.auto = automation
        self.user_id = user_id
        self.session_id = session_id
        self.triggered_by = triggered_by
        self.platform = sys.platform
        self.feed = automation.feed_client
        self._vt_lock = asyncio.Lock()
        self._vt_queue: asyncio.Queue[str] = asyncio.Queue()
        self._vt_results: Dict[str, Dict[str, Any]] = {}

    def _audit_cmd(self, meta: Dict[str, Any]) -> None:
        if self.auto.case_store:
            try:
                self.auto.case_store.audit(
                    "SYSTEM",
                    "system",
                    "device_os_command",
                    "host",
                    self.session_id,
                    meta,
                )
            except Exception:
                pass

    async def _emit(self, payload: Dict[str, Any]) -> None:
        await self.auto.ws_hub.broadcast(payload)

    def _ioc_cache_get(self, ioc_value: str, ioc_type: str, source: str) -> Optional[Dict[str, Any]]:
        if getattr(self.auto, "ioc_cache", None):
            return self.auto.ioc_cache.get_cached(ioc_value, ioc_type, source)
        return self.auto.device_ioc_cache_get(ioc_value, ioc_type, source)

    def _ioc_cache_set(self, ioc_value: str, ioc_type: str, source: str, result: Dict[str, Any]) -> None:
        if getattr(self.auto, "ioc_cache", None):
            score = int(result.get("score") or result.get("malicious") or 0) if isinstance(result, dict) else 0
            verdict = result.get("verdict") if isinstance(result, dict) else None
            if not verdict:
                verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean"
            self.auto.ioc_cache.set_cached(
                ioc_value,
                ioc_type,
                source,
                result,
                is_flagged=verdict != "clean",
                verdict=verdict,
                score=score or None,
            )
            return
        self.auto.device_ioc_cache_set(ioc_value, ioc_type, source, result)

    def _queue_ioc_check(self, value: str, ioc_type: str) -> None:
        if getattr(self.auto, "ioc_cache", None):
            self.auto.ioc_cache.queue_check(value, ioc_type)

    def _local_ioc_match(self, ioc_type: str, value: str) -> bool:
        return self.auto.device_local_ioc_exists(ioc_type, value)

    async def _lookup_abuseipdb(self, ip: str) -> Dict[str, Any]:
        cached = self._ioc_cache_get(ip, "ip", "abuseipdb")
        if cached is not None:
            return cached
        resp = await self.feed.request(
            "abuseipdb",
            "GET",
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
        )
        body = {"raw": resp, "score": 0, "categories": []}
        if resp.get("ok") and isinstance(resp.get("data"), dict):
            d = resp["data"]
            data = d.get("data") if isinstance(d.get("data"), dict) else d
            score = int(data.get("abuseConfidenceScore") or 0)
            cats = data.get("reports") or []
            body = {"raw": resp, "score": score, "categories": cats[:5] if isinstance(cats, list) else []}
        self._ioc_cache_set(ip, "ip", "abuseipdb", body)
        return body

    async def _lookup_otx_ip(self, ip: str) -> Dict[str, Any]:
        cached = self._ioc_cache_get(ip, "ip", "otx")
        if cached is not None:
            return cached
        resp = await self.feed.request("otx", "GET", f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general")
        pulse = 0
        tags: List[str] = []
        if resp.get("ok") and isinstance(resp.get("data"), dict):
            d = resp["data"]
            pulse = int(d.get("pulse_info", {}).get("count", 0) or 0)
            tags = (d.get("pulse_info", {}) or {}).get("related", [])[:5]
            if isinstance(tags, list) and tags and isinstance(tags[0], dict):
                tags = [str(t.get("name", "")) for t in tags][:5]
        body = {"raw": resp, "pulse_count": pulse, "tags": tags if isinstance(tags, list) else []}
        self._ioc_cache_set(ip, "ip", "otx", body)
        return body

    async def _virustotal_file(self, file_hash: str) -> Dict[str, Any]:
        cached = self._ioc_cache_get(file_hash.lower(), "hash", "virustotal")
        if cached is not None:
            return cached
        async with self._vt_lock:
            resp = await self.feed.request(
                "virustotal",
                "GET",
                f"https://www.virustotal.com/api/v3/files/{file_hash.lower()}",
            )
            malicious = 0
            total = 0
            if resp.get("ok") and isinstance(resp.get("data"), dict):
                stats = (((resp["data"].get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {})
                malicious = int(stats.get("malicious") or 0) + int(stats.get("suspicious") or 0)
                total = sum(int(stats.get(k) or 0) for k in ("harmless", "malicious", "suspicious", "undetected"))
            body = {"malicious": malicious, "total": total or 87, "raw_ok": bool(resp.get("ok"))}
            self._ioc_cache_set(file_hash.lower(), "hash", "virustotal", body)
            await asyncio.sleep(0)
        return body

    async def _vt_process_queue(self, hashes: List[str]) -> None:
        uniq = list(dict.fromkeys(h for h in hashes if h))
        batches = [uniq[i : i + VT_BATCH_SIZE] for i in range(0, len(uniq), VT_BATCH_SIZE)]
        for batch in batches:
            await asyncio.gather(*[self._virustotal_file(h) for h in batch])
            if batches.index(batch) < len(batches) - 1:
                await asyncio.sleep(VT_BATCH_SLEEP_SEC)

    async def collect_system_info(self) -> CollectorResult:
        full: Dict[str, Any] = dict(get_builtin_system_info())
        try:
            if self.platform == "win32":
                ps = (
                    "$d = Get-ComputerInfo | Select-Object CsName,OsName,OsVersion,OsArchitecture,"
                    "CsProcessors,CsTotalPhysicalMemory,CsUserName | ConvertTo-Json -Compress;"
                    "$mp = try { Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled | ConvertTo-Json -Compress } catch { '{}' };"
                    "$fw = try { netsh advfirewall show allprofiles state } catch { '' };"
                    "$d, $mp, $fw | Write-Output"
                )
                code, out, err = await asyncio.to_thread(run_exec, "powershell", ["-NoProfile", "-Command", ps], audit=self._audit_cmd, triggered_by=self.triggered_by)
                parts = [p.strip() for p in out.split("\n") if p.strip()]
                try:
                    comp = json.loads(parts[0]) if parts else {}
                except json.JSONDecodeError:
                    comp = {}
                av = {}
                try:
                    av = json.loads(parts[1]) if len(parts) > 1 else {}
                except json.JSONDecodeError:
                    av = {}
                fw_text = parts[2] if len(parts) > 2 else ""
                fw_on = "ON" in fw_text.upper() or "ENABLE" in fw_text.upper()
                ram_gb = round(int(comp.get("CsTotalPhysicalMemory") or 0) / (1024**3), 2) if comp.get("CsTotalPhysicalMemory") else None
                procs = comp.get("CsProcessors") or []
                cpu_model = procs[0].get("Name") if isinstance(procs, list) and procs and isinstance(procs[0], dict) else str(procs)
                full.update(
                    {
                        "hostname": comp.get("CsName") or full.get("hostname"),
                        "os_name": comp.get("OsName") or full.get("os_name"),
                        "os_version": f"{comp.get('OsName','')} {comp.get('OsVersion','')}".strip() or full.get("os_version"),
                        "cpu_model": cpu_model or full.get("cpu_model"),
                        "ram_total_gb": ram_gb or full.get("ram_total_gb"),
                        "ram_gb": ram_gb or full.get("ram_gb"),
                        "current_user": comp.get("CsUserName") or full.get("current_user"),
                        "firewall_status": "active" if fw_on else "disabled",
                        "av_status": "detected" if av.get("AntivirusEnabled") else "not_found",
                    }
                )
            elif self.platform == "darwin":
                code, out, _ = await asyncio.to_thread(run_exec, "sw_vers", [], audit=self._audit_cmd, triggered_by=self.triggered_by)
                lines = [x for x in out.splitlines() if ":" in x]
                ver = {k.strip(): v.strip() for k, v in (ln.split(":", 1) for ln in lines)}
                _, up_out, _ = await asyncio.to_thread(run_exec, "uptime", [], audit=self._audit_cmd, triggered_by=self.triggered_by)
                full.update(
                    {
                        "hostname": platform.node() or full.get("hostname"),
                        "os_name": ver.get("ProductName", "macOS"),
                        "os_version": f"{ver.get('ProductName','')} {ver.get('ProductVersion','')}".strip(),
                        "uptime_raw": up_out.strip(),
                    }
                )
            else:
                os_release = ""
                try:
                    os_release = Path("/etc/os-release").read_text(encoding="utf-8", errors="replace")
                except OSError:
                    pass
                _, uname_out, _ = await asyncio.to_thread(run_exec, "uname", ["-a"], audit=self._audit_cmd, triggered_by=self.triggered_by)
                _, up_out, _ = await asyncio.to_thread(run_exec, "uptime", [], audit=self._audit_cmd, triggered_by=self.triggered_by)
                full.update(
                    {
                        "hostname": platform.node() or full.get("hostname"),
                        "os_version": uname_out.strip() or full.get("os_version"),
                        "uptime_raw": up_out.strip(),
                        "os_release": os_release[:800],
                    }
                )
            if full.get("uptime_seconds") is None and full.get("uptime_raw"):
                full["uptime_seconds"] = _uptime_seconds()
            summary = {"hostname": full.get("hostname"), "platform": self.platform}
            self.auto.device_session_update_fields(
                self.session_id,
                {
                    "os_platform": self.platform,
                    "hostname": full.get("hostname") or "",
                },
            )
            self.auto.device_merge_full_results(self.session_id, {"system": full})
            return CollectorResult("sysinfo", True, summary)
        except Exception as exc:
            logger.exception("collect_system_info")
            return CollectorResult("sysinfo", False, {}, str(exc))

    async def collect_network(self) -> CollectorResult:
        rows: List[Dict[str, Any]] = []
        flagged_items: List[Dict[str, Any]] = []
        try:
            if self.platform == "win32":
                ps = (
                    "Get-NetTCPConnection -State Established,Listen | "
                    "Select-Object -First 500 LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | "
                    "ConvertTo-Json -Compress -Depth 4"
                )
                _, out, _ = await asyncio.to_thread(run_exec, "powershell", ["-NoProfile", "-Command", ps], audit=self._audit_cmd, triggered_by=self.triggered_by)
                try:
                    data = json.loads(out or "[]")
                    if isinstance(data, dict):
                        data = [data]
                except json.JSONDecodeError:
                    data = []
                pid_map = await self._windows_pid_map()
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    lip = str(item.get("LocalAddress") or "")
                    rip = str(item.get("RemoteAddress") or "")
                    pid = int(item.get("OwningProcess") or 0)
                    proc = pid_map.get(pid, ("", ""))
                    rows.append(
                        {
                            "local_ip": lip,
                            "local_port": int(item.get("LocalPort") or 0),
                            "remote_ip": rip,
                            "remote_port": int(item.get("RemotePort") or 0),
                            "protocol": "tcp",
                            "state": str(item.get("State") or ""),
                            "pid": pid,
                            "process_name": proc[0],
                            "process_path": proc[1],
                        }
                    )
            else:
                exe = "ss" if shutil.which("ss") else "netstat"
                args = ["-tunap"] if exe == "ss" else ["-tunap"]
                _, out, _ = await asyncio.to_thread(run_exec, exe, args, audit=self._audit_cmd, triggered_by=self.triggered_by)
                rows = self._parse_ss_output(out)
            public_ips: List[str] = []
            for r in rows:
                rip = r.get("remote_ip") or ""
                if rip and not is_private_ip(rip) and rip not in public_ips:
                    public_ips.append(rip)
            ip_intel: Dict[str, Dict[str, Any]] = {}
            for ip in public_ips[:200]:
                cached = self._ioc_cache_get(ip, "ip", "abuseipdb")
                if cached:
                    score = int(cached.get("score") or 0)
                    ip_intel[ip] = {"abuse": {"score": score, "categories": cached.get("categories", [])}}
                else:
                    self._queue_ioc_check(ip, "ip")
                    ip_intel[ip] = {"abuse": {"score": 0, "categories": []}}

            now = utc_now_iso()
            flagged = 0
            malicious = 0
            db_rows = []
            for r in rows:
                rip = r.get("remote_ip") or ""
                intel = ip_intel.get(rip, {})
                abuse = intel.get("abuse") or {}
                score = int(abuse.get("score") or 0) if isinstance(abuse, dict) else 0
                local_hit = self._local_ioc_match("ip", rip) if rip else False
                verdict = "clean"
                threat_type = None
                threat_source = None
                conf = 0
                is_flagged = False
                if local_hit or score >= 75:
                    verdict = "malicious" if score >= 90 or local_hit else "suspicious"
                    is_flagged = True
                    conf = max(score, 90 if local_hit else 0)
                    threat_type = "malicious_ip" if verdict == "malicious" else "suspicious_ip"
                    threat_source = "abuseipdb" if score else "local_ioc"
                    if local_hit:
                        threat_source = "local_ioc"
                elif score >= 25:
                    verdict = "suspicious"
                    is_flagged = True
                    conf = score
                    threat_type = "elevated_abuse_score"
                    threat_source = "abuseipdb"
                if verdict == "malicious":
                    malicious += 1
                if is_flagged:
                    flagged += 1
                    flagged_items.append({"remote_ip": rip, "process": r.get("process_name"), "verdict": verdict})
                db_rows.append(
                    {
                        "timestamp": now,
                        "local_ip": r.get("local_ip"),
                        "local_port": r.get("local_port"),
                        "remote_ip": rip,
                        "remote_port": r.get("remote_port"),
                        "protocol": r.get("protocol") or "tcp",
                        "state": r.get("state"),
                        "pid": r.get("pid"),
                        "process_name": r.get("process_name"),
                        "process_path": r.get("process_path"),
                        "is_flagged": is_flagged,
                        "ioc_confidence": conf,
                        "threat_type": threat_type,
                        "threat_source": threat_source,
                        "verdict": verdict,
                    }
                )
            self.auto.device_insert_connections(self.session_id, db_rows)
            return CollectorResult(
                "network",
                True,
                {
                    "found": len(db_rows),
                    "flagged": flagged,
                    "malicious": malicious,
                    "flaggedItems": flagged_items[:50],
                },
            )
        except Exception as exc:
            logger.exception("collect_network")
            return CollectorResult("network", False, {"found": 0, "flagged": 0, "flaggedItems": []}, str(exc))

    async def _windows_pid_map(self) -> Dict[int, Tuple[str, str]]:
        ps = "Get-Process | Select-Object Id,ProcessName,Path | ConvertTo-Json -Compress"
        _, out, _ = await asyncio.to_thread(run_exec, "powershell", ["-NoProfile", "-Command", ps], audit=self._audit_cmd, triggered_by=self.triggered_by)
        out_map: Dict[int, Tuple[str, str]] = {}
        try:
            data = json.loads(out or "[]")
            if isinstance(data, dict):
                data = [data]
            for item in data:
                if not isinstance(item, dict):
                    continue
                pid = int(item.get("Id") or 0)
                out_map[pid] = (str(item.get("ProcessName") or ""), str(item.get("Path") or ""))
        except json.JSONDecodeError:
            pass
        return out_map

    def _parse_ss_output(self, text: str) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("Netid") or line.startswith("State"):
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0].lower()
            state = parts[1] if len(parts) > 1 else ""
            local = parts[3] if len(parts) > 3 else parts[2]
            peer = parts[4] if len(parts) > 4 else ""
            pid = 0
            pname = ""
            ppath = ""
            if "users:" in line:
                m = re.search(r"users:\(\(\"([^\"]+)\"", line)
                if m:
                    pname = m.group(1)
                m2 = re.search(r"pid=(\d+)", line)
                if m2:
                    pid = int(m2.group(1))

            def split_addr(s: str) -> Tuple[str, int]:
                if "]:" in s:
                    host, port = s.rsplit(":", 1)
                    host = host.strip("[]")
                    try:
                        return host, int(port)
                    except ValueError:
                        return host, 0
                if s.count(":") > 1:
                    return s, 0
                if ":" in s:
                    h, p = s.rsplit(":", 1)
                    try:
                        return h, int(p)
                    except ValueError:
                        return h, 0
                return s, 0

            lip, lp = split_addr(local)
            rip, rp = split_addr(peer)
            rows.append(
                {
                    "local_ip": lip,
                    "local_port": lp,
                    "remote_ip": rip,
                    "remote_port": rp,
                    "protocol": proto,
                    "state": state,
                    "pid": pid,
                    "process_name": pname,
                    "process_path": ppath,
                }
            )
        return rows

    async def collect_processes(self) -> CollectorResult:
        rows_out: List[Dict[str, Any]] = []
        hashes: List[str] = []
        flagged_items: List[Dict[str, Any]] = []
        malicious = 0
        try:
            if self.platform == "win32":
                ps = "Get-Process | Select-Object Name,Id,CPU,WorkingSet,Path | ConvertTo-Json -Compress"
                _, out, _ = await asyncio.to_thread(run_exec, "powershell", ["-NoProfile", "-Command", ps], audit=self._audit_cmd, triggered_by=self.triggered_by)
                try:
                    data = json.loads(out or "[]")
                    if isinstance(data, dict):
                        data = [data]
                except json.JSONDecodeError:
                    data = []
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    pid = int(item.get("Id") or 0)
                    name = str(item.get("Name") or "")
                    path = str(item.get("Path") or "")
                    cpu = float(item.get("CPU") or 0)
                    mem = float(item.get("WorkingSet") or 0) / (1024 * 1024)
                    flag, reason = suspicious_process_path(path, "win32")
                    h = sha256_file_stream(path) if path else None
                    if h:
                        hashes.append(h)
                    rows_out.append(
                        {
                            "pid": pid,
                            "name": name,
                            "path": path,
                            "cpu_percent": cpu,
                            "memory_mb": mem,
                            "sha256_hash": h,
                            "is_flagged": flag,
                            "suspicious_path_reason": reason or None,
                            "verdict": "suspicious" if flag else "clean",
                        }
                    )
            else:
                _, out, _ = await asyncio.to_thread(run_exec, "ps", ["aux"], audit=self._audit_cmd, triggered_by=self.triggered_by)
                for line in out.splitlines()[1:400]:
                    parts = line.split(None, 10)
                    if len(parts) < 11:
                        continue
                    user, pid_s, cpu_s, mem_s, vsz, rss, tty, stat, start, time_el, cmd = parts[:11]
                    pid = int(pid_s)
                    cpu = float(cpu_s)
                    mem = float(rss) / 1024.0 if rss.isdigit() else 0.0
                    path = cmd.split(" ", 1)[0] if cmd else ""
                    flag, reason = suspicious_process_path(cmd, "linux")
                    h = sha256_file_stream(path) if path.startswith("/") else None
                    if h:
                        hashes.append(h)
                    rows_out.append(
                        {
                            "pid": pid,
                            "name": cmd[:80],
                            "path": cmd,
                            "cpu_percent": cpu,
                            "memory_mb": mem,
                            "sha256_hash": h,
                            "is_flagged": flag,
                            "suspicious_path_reason": reason or None,
                            "verdict": "suspicious" if flag else "clean",
                        }
                    )
            for h in hashes:
                if h and not self._ioc_cache_get(h.lower(), "hash", "virustotal"):
                    self._queue_ioc_check(h.lower(), "hash")
            now = utc_now_iso()
            db_rows = []
            flagged = 0
            for r in rows_out:
                h = r.get("sha256_hash")
                vt_p = vt_t = None
                verdict = r.get("verdict") or "clean"
                if h:
                    vt = self._ioc_cache_get(h.lower(), "hash", "virustotal") or {}
                    vt_p = int(vt.get("malicious") or 0)
                    vt_t = int(vt.get("total") or 0)
                    if vt_p > 0:
                        verdict = "malicious"
                        r["is_flagged"] = True
                if r.get("is_flagged") or verdict == "malicious":
                    flagged += 1
                    if verdict == "malicious":
                        malicious += 1
                        flagged_items.append({"name": r.get("name"), "path": r.get("path"), "vt": vt_p})
                db_rows.append(
                    {
                        "timestamp": now,
                        "pid": r.get("pid"),
                        "name": r.get("name"),
                        "path": r.get("path"),
                        "cpu_percent": r.get("cpu_percent"),
                        "memory_mb": r.get("memory_mb"),
                        "sha256_hash": h,
                        "is_flagged": bool(r.get("is_flagged") or verdict != "clean"),
                        "vt_positives": vt_p,
                        "vt_total": vt_t,
                        "suspicious_path_reason": r.get("suspicious_path_reason"),
                        "verdict": verdict,
                    }
                )
            self.auto.device_insert_processes(self.session_id, db_rows)
            malicious_n = sum(1 for row in db_rows if row.get("verdict") == "malicious")
            return CollectorResult(
                "processes",
                True,
                {
                    "found": len(db_rows),
                    "flagged": flagged,
                    "malicious": malicious_n,
                    "flaggedItems": flagged_items[:40],
                },
            )
        except Exception as exc:
            logger.exception("collect_processes")
            return CollectorResult("processes", False, {"found": 0, "flagged": 0, "flaggedItems": []}, str(exc))

    async def collect_ports(self) -> CollectorResult:
        rows: List[Dict[str, Any]] = []
        try:
            if self.platform == "win32":
                _, out, _ = await asyncio.to_thread(run_exec, "netstat", ["-ano", "-p", "tcp"], audit=self._audit_cmd, triggered_by=self.triggered_by)
                rows = self._parse_netstat_windows(out)
            else:
                exe = "ss" if shutil.which("ss") else "netstat"
                args = ["-tlnp"] if exe == "ss" else ["-tlnp"]
                _, out, _ = await asyncio.to_thread(run_exec, exe, args, audit=self._audit_cmd, triggered_by=self.triggered_by)
                rows = self._parse_ss_listen(out)
            open_n = 0
            susp = 0
            db_rows = []
            for r in rows:
                if r.get("state") and str(r.get("state")).upper() not in {"LISTEN", "LISTENING"}:
                    continue
                open_n += 1
                bound = r.get("bound_address") or ""
                port = int(r.get("port") or 0)
                flag = False
                reason = ""
                if bound in {"0.0.0.0", "*", "::"}:
                    flag = True
                    reason = "bound_all_interfaces"
                if port and port not in KNOWN_SAFE_PORTS:
                    flag = True
                    reason = (reason + ";non_standard_port").strip(";")
                if flag:
                    susp += 1
                db_rows.append(
                    {
                        "port": port,
                        "protocol": r.get("protocol") or "tcp",
                        "bound_address": bound,
                        "pid": r.get("pid"),
                        "process_name": r.get("process_name") or "",
                        "is_flagged": flag,
                        "flag_reason": reason or None,
                    }
                )
            self.auto.device_insert_ports(self.session_id, db_rows)
            return CollectorResult("ports", True, {"open": open_n, "suspicious": susp})
        except Exception as exc:
            logger.exception("collect_ports")
            return CollectorResult("ports", False, {"open": 0, "suspicious": 0}, str(exc))

    def _parse_netstat_windows(self, text: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or not line.upper().startswith("TCP"):
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0].lower()
            local = parts[1]
            remote = parts[2]
            state = parts[3] if len(parts) > 4 else ""
            pid = int(parts[-1]) if parts[-1].isdigit() else 0
            lip, lp = local.rsplit(":", 1) if ":" in local else (local, 0)
            rip, rp = remote.rsplit(":", 1) if ":" in remote else (remote, 0)
            try:
                lp = int(lp)
            except ValueError:
                lp = 0
            try:
                rp = int(rp)
            except ValueError:
                rp = 0
            out.append(
                {
                    "protocol": proto,
                    "bound_address": lip,
                    "port": lp,
                    "remote": rip,
                    "state": state,
                    "pid": pid,
                    "process_name": "",
                }
            )
        return out

    def _parse_ss_listen(self, text: str) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if "LISTEN" not in line.upper():
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[3]
            pid = 0
            pname = ""
            m = re.search(r"pid=(\d+)", line)
            if m:
                pid = int(m.group(1))
            m2 = re.search(r'users:\(\("([^"]+)"', line)
            if m2:
                pname = m2.group(1)
            host, port = local, 0
            if "]:" in local:
                host, port_s = local.rsplit(":", 1)
                host = host.strip("[]")
                try:
                    port = int(port_s)
                except ValueError:
                    port = 0
            elif local.count(":") > 1:
                host = local
            else:
                if ":" in local:
                    host, port_s = local.rsplit(":", 1)
                    try:
                        port = int(port_s)
                    except ValueError:
                        port = 0
            rows.append({"protocol": "tcp", "bound_address": host, "port": port, "pid": pid, "process_name": pname, "state": "LISTEN"})
        return rows

    async def collect_software(self) -> CollectorResult:
        apps: List[Dict[str, Any]] = []
        try:
            if self.platform == "win32":
                ps = (
                    "Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "
                    "| Select-Object DisplayName,DisplayVersion,Publisher,InstallDate -ErrorAction SilentlyContinue | ConvertTo-Json -Compress"
                )
                _, out, _ = await asyncio.to_thread(run_exec, "powershell", ["-NoProfile", "-Command", ps], audit=self._audit_cmd, triggered_by=self.triggered_by)
                try:
                    data = json.loads(out or "[]")
                    if isinstance(data, dict):
                        data = [data]
                except json.JSONDecodeError:
                    data = []
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    name = item.get("DisplayName")
                    if not name:
                        continue
                    apps.append(
                        {
                            "name": str(name),
                            "version": str(item.get("DisplayVersion") or ""),
                            "publisher": str(item.get("Publisher") or ""),
                            "install_date": str(item.get("InstallDate") or ""),
                            "known_cves": [],
                        }
                    )
            elif shutil.which("dpkg"):
                _, out, _ = await asyncio.to_thread(run_exec, "dpkg", ["-l"], audit=self._audit_cmd, triggered_by=self.triggered_by)
                for line in out.splitlines():
                    if not line.startswith("ii"):
                        continue
                    parts = line.split(None, 3)
                    if len(parts) < 4:
                        continue
                    apps.append({"name": parts[1], "version": parts[2], "publisher": "dpkg", "install_date": "", "known_cves": []})
            elif shutil.which("rpm"):
                _, out, _ = await asyncio.to_thread(run_exec, "rpm", ["-qa", "--qf", "%{NAME}\t%{VERSION}\t%{VENDOR}\n"], audit=self._audit_cmd, triggered_by=self.triggered_by)
                for line in out.splitlines():
                    bits = line.split("\t")
                    if len(bits) >= 2:
                        apps.append({"name": bits[0], "version": bits[1], "publisher": bits[2] if len(bits) > 2 else "", "install_date": "", "known_cves": []})
            elif self.platform == "darwin":
                _, out, _ = await asyncio.to_thread(
                    run_exec,
                    "system_profiler",
                    ["SPApplicationsDataType", "-json"],
                    audit=self._audit_cmd,
                    triggered_by=self.triggered_by,
                )
                try:
                    payload = json.loads(out or "{}")
                    for sp in (payload.get("SPApplicationsDataType") or [])[:800]:
                        if isinstance(sp, dict):
                            apps.append(
                                {
                                    "name": str(sp.get("_name") or sp.get("path") or "app"),
                                    "version": str(sp.get("version") or ""),
                                    "publisher": str(sp.get("signed_by") or sp.get("obtained_from") or ""),
                                    "install_date": str(sp.get("lastModified") or ""),
                                    "known_cves": [],
                                }
                            )
                except json.JSONDecodeError:
                    pass
            self.auto.device_insert_software(self.session_id, apps)
            return CollectorResult("software", True, {"count": len(apps)})
        except Exception as exc:
            logger.exception("collect_software")
            return CollectorResult("software", False, {"count": 0}, str(exc))

    async def collect_dns(self) -> CollectorResult:
        domains: List[str] = []
        flagged: List[Dict[str, Any]] = []
        try:
            hosts_lines: List[str] = []
            try:
                hosts_lines = Path("/etc/hosts").read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                if self.platform == "win32":
                    try:
                        hosts_lines = Path(os.environ.get("SystemRoot", "C:\\Windows") + "\\System32\\drivers\\etc\\hosts").read_text(
                            encoding="utf-8", errors="replace"
                        ).splitlines()
                    except OSError:
                        hosts_lines = []
            for line in hosts_lines:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                parts = s.split()
                if len(parts) < 2:
                    continue
                ip = parts[0]
                names = parts[1:]
                if ip in {"127.0.0.1", "::1"} and all(n.lower() in {"localhost", "localhost.localdomain"} for n in names):
                    continue
                flagged.append({"domain": " ".join(names), "type": "hosts_override", "ioc_match": False, "verdict": "suspicious", "detail": f"{ip} -> {' '.join(names)}"})
                for n in names:
                    if n not in domains and "." in n:
                        domains.append(n)
            if self.platform == "win32":
                _, out, _ = await asyncio.to_thread(run_exec, "ipconfig", ["/displaydns"], audit=self._audit_cmd, triggered_by=self.triggered_by)
                for m in re.finditer(r"Record Name[^\n:]*:\s*([^\s]+)", out):
                    domains.append(m.group(1).strip().rstrip("."))
            elif self.platform == "darwin":
                _, out, _ = await asyncio.to_thread(
                    run_exec,
                    "dscacheutil",
                    ["-cachedump", "-entries", "Host"],
                    audit=self._audit_cmd,
                    triggered_by=self.triggered_by,
                )
                for m in re.finditer(r"name:\s*([^\s]+)", out, re.I):
                    domains.append(m.group(1).strip())
            else:
                if shutil.which("resolvectl"):
                    _, out, _ = await asyncio.to_thread(run_exec, "resolvectl", ["statistics"], audit=self._audit_cmd, triggered_by=self.triggered_by)
                    for m in re.finditer(r"([a-z0-9-]+\.)+[a-z]{2,}", out, re.I):
                        domains.append(m.group(0).lower())
            uniq = list(dict.fromkeys(d.lower() for d in domains if d and "." in d))[:200]
            checked = len(uniq)
            for d in uniq:
                hit = self._local_ioc_match("domain", d)
                verdict = "malicious" if hit else "clean"
                row = {"domain": d, "type": "cache", "ioc_match": hit, "verdict": verdict}
                if not hit and self.feed.key_status().get("urlscan"):
                    cached = self._ioc_cache_get(d, "domain", "urlscan")
                    if cached is None:
                        resp = await self.feed.request(
                            "urlscan",
                            "GET",
                            "https://urlscan.io/api/v1/search/",
                            params={"q": f"domain:{d}", "size": 1},
                        )
                        top = {}
                        if resp.get("ok") and isinstance(resp.get("data"), dict):
                            results = resp["data"].get("results") or []
                            top = results[0] if results else {}
                        cached_payload = {"top": top, "http": resp.get("http_status")}
                        self._ioc_cache_set(d, "domain", "urlscan", cached_payload)
                        cached = cached_payload
                    overall = ((cached.get("top") or {}).get("verdicts") or {}).get("overall") or {}
                    if overall.get("malicious"):
                        verdict = "malicious"
                        row["ioc_match"] = True
                if verdict != "clean":
                    flagged.append(row)
            dns_payload = {"entries": [{"domain": d, "type": "cache", "ioc_match": False, "verdict": "clean"} for d in uniq[:80]], "flagged": flagged}
            self.auto.device_merge_full_results(self.session_id, {"dns": dns_payload})
            return CollectorResult("dns", True, {"checked": checked, "flagged": len(flagged)})
        except Exception as exc:
            logger.exception("collect_dns")
            return CollectorResult("dns", False, {"checked": 0, "flagged": 0}, str(exc))

    async def collect_startup(self) -> CollectorResult:
        items: List[Dict[str, Any]] = []
        try:
            if self.platform == "win32":
                ps = (
                    "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -ErrorAction SilentlyContinue | ConvertTo-Json -Compress"
                )
                _, out, _ = await asyncio.to_thread(run_exec, "powershell", ["-NoProfile", "-Command", ps], audit=self._audit_cmd, triggered_by=self.triggered_by)
                try:
                    blob = json.loads(out or "{}")
                    if isinstance(blob, dict):
                        for k, v in blob.items():
                            if k in {"PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider"}:
                                continue
                            if isinstance(v, str) and v:
                                flag, reason = suspicious_process_path(v, "win32")
                                items.append(
                                    {
                                        "name": str(k),
                                        "command": v,
                                        "type": "Registry Run Key",
                                        "is_flagged": flag,
                                        "flag_reason": reason or None,
                                        "sha256_hash": sha256_file_stream(v.split()[0].strip('"')) if v.split() else None,
                                        "vt_positives": None,
                                        "verdict": "suspicious" if flag else "clean",
                                    }
                                )
                except json.JSONDecodeError:
                    pass
                _, sch, _ = await asyncio.to_thread(
                    run_exec,
                    "schtasks",
                    ["/query", "/fo", "LIST", "/v"],
                    audit=self._audit_cmd,
                    triggered_by=self.triggered_by,
                )
                cur: Dict[str, str] = {}
                for line in sch.splitlines():
                    if line.startswith("TaskName:"):
                        if cur.get("TaskName"):
                            cmd = cur.get("Task To Run", "")
                            flag, reason = suspicious_process_path(cmd, "win32")
                            items.append(
                                {
                                    "name": cur.get("TaskName", "task"),
                                    "command": cmd,
                                    "type": "Scheduled Task",
                                    "is_flagged": flag,
                                    "flag_reason": reason or None,
                                    "sha256_hash": None,
                                    "vt_positives": None,
                                    "verdict": "suspicious" if flag else "clean",
                                }
                            )
                        cur = {"TaskName": line.split(":", 1)[1].strip()}
                    elif ":" in line:
                        k, v = line.split(":", 1)
                        cur[k.strip()] = v.strip()
                if cur.get("TaskName"):
                    cmd = cur.get("Task To Run", "")
                    flag, reason = suspicious_process_path(cmd, "win32")
                    items.append(
                        {
                            "name": cur["TaskName"],
                            "command": cmd,
                            "type": "Scheduled Task",
                            "is_flagged": flag,
                            "flag_reason": reason or None,
                            "sha256_hash": None,
                            "vt_positives": None,
                            "verdict": "suspicious" if flag else "clean",
                        }
                    )
            elif self.platform == "darwin":
                _, out, _ = await asyncio.to_thread(run_exec, "launchctl", ["list"], audit=self._audit_cmd, triggered_by=self.triggered_by)
                for line in out.splitlines()[1:400]:
                    parts = line.split()
                    if len(parts) >= 3:
                        items.append(
                            {
                                "name": parts[2],
                                "command": line,
                                "type": "Launch Agent",
                                "is_flagged": False,
                                "flag_reason": None,
                                "sha256_hash": None,
                                "vt_positives": None,
                                "verdict": "clean",
                            }
                        )
            else:
                if shutil.which("systemctl"):
                    _, out, _ = await asyncio.to_thread(
                        run_exec,
                        "systemctl",
                        ["list-units", "--type=service", "--no-pager"],
                        audit=self._audit_cmd,
                        triggered_by=self.triggered_by,
                    )
                    for line in out.splitlines():
                        if ".service" in line and "running" in line.lower():
                            bits = line.split()
                            if bits:
                                items.append(
                                    {
                                        "name": bits[0],
                                        "command": line.strip(),
                                        "type": "Service",
                                        "is_flagged": False,
                                        "flag_reason": None,
                                        "sha256_hash": None,
                                        "vt_positives": None,
                                        "verdict": "clean",
                                    }
                                )
                for cron_path in (Path("/etc/crontab"),):
                    try:
                        txt = cron_path.read_text(encoding="utf-8", errors="replace")
                        for ln in txt.splitlines():
                            if ln.strip() and not ln.startswith("#"):
                                items.append(
                                    {
                                        "name": cron_path.name,
                                        "command": ln.strip(),
                                        "type": "Cron Job",
                                        "is_flagged": "/tmp" in ln,
                                        "flag_reason": "temp_reference" if "/tmp" in ln else None,
                                        "sha256_hash": None,
                                        "vt_positives": None,
                                        "verdict": "suspicious" if "/tmp" in ln else "clean",
                                    }
                                )
                    except OSError:
                        pass
            hashes = [i["sha256_hash"] for i in items if i.get("sha256_hash")]
            await self._vt_process_queue([h for h in hashes if h])
            for i in items:
                h = i.get("sha256_hash")
                if h:
                    vt = self._ioc_cache_get(h.lower(), "hash", "virustotal") or {}
                    i["vt_positives"] = int(vt.get("malicious") or 0)
                    if i["vt_positives"] > 0:
                        i["verdict"] = "malicious"
                        i["is_flagged"] = True
            self.auto.device_insert_startup(self.session_id, items)
            flagged = sum(1 for i in items if i.get("is_flagged") or i.get("verdict") != "clean")
            return CollectorResult("startup", True, {"total": len(items), "flagged": flagged})
        except Exception as exc:
            logger.exception("collect_startup")
            return CollectorResult("startup", False, {"total": 0, "flagged": 0}, str(exc))

    def _risk_score(self, summaries: Dict[str, CollectorResult]) -> int:
        score = 0
        net = summaries.get("network")
        proc = summaries.get("processes")
        st = summaries.get("startup")
        dns = summaries.get("dns")
        mal_conn = int(net.summary.get("malicious") or 0) if net and net.ok else 0
        mal_proc = int(proc.summary.get("malicious") or 0) if proc and proc.ok else 0
        if mal_conn:
            score += 30
        if mal_proc:
            score += 20
        if st and st.ok and int(st.summary.get("flagged") or 0) > 0:
            score += 15
        if dns and dns.ok and int(dns.summary.get("flagged") or 0) > 0:
            score += 10
        sus_conn = max(0, int(net.summary.get("flagged") or 0) - mal_conn) if net and net.ok else 0
        score += min(15, sus_conn * 5)
        sus_proc = max(0, int(proc.summary.get("flagged") or 0) - mal_proc) if proc and proc.ok else 0
        score += min(10, sus_proc * 5)
        return min(100, score)

    async def run(self) -> None:
        phase_map = {
            "sysinfo": ("sysinfo", 5, "Collecting system information…"),
            "network": ("network", 30, "Scanning network connections…"),
            "processes": ("processes", 55, "Analyzing running processes…"),
            "ports": ("ports", 65, "Enumerating listening ports…"),
            "software": ("software", 75, "Building software inventory…"),
            "dns": ("dns", 88, "Inspecting DNS / hosts…"),
            "startup": ("startup", 100, "Enumerating startup items…"),
        }

        async def emit_progress(key: str, msg: str, live: Dict[str, Any]) -> None:
            phase, pct, _base = phase_map[key]
            await self._emit(
                {
                    "type": "device_scan_progress",
                    "event": "device_scan_progress",
                    "sessionId": self.session_id,
                    "phase": phase,
                    "percent": pct,
                    "message": msg,
                    "liveStats": live,
                }
            )

        await self._emit({"type": "device_scan_started", "event": "device_scan_started", "sessionId": self.session_id})

        async def tracked(key: str, coro: "asyncio.Future[CollectorResult] | Any") -> CollectorResult:
            try:
                res = await coro
            except Exception as exc:
                logger.exception("collector %s failed", key)
                res = CollectorResult(key, False, {}, str(exc))
            if key == "startup":
                live = {"found": res.summary.get("total", 0), "flagged": res.summary.get("flagged", 0)}
            elif key == "software":
                live = {"found": res.summary.get("count", 0), "flagged": 0}
            elif key == "ports":
                live = {"found": res.summary.get("open", 0), "flagged": res.summary.get("suspicious", 0)}
            elif key == "dns":
                live = {"found": res.summary.get("checked", 0), "flagged": res.summary.get("flagged", 0)}
            else:
                live = {
                    "found": res.summary.get("found", 0),
                    "flagged": res.summary.get("flagged", 0),
                }
            await emit_progress(
                key,
                f"{phase_map[key][2]} {live.get('found', 0)} found, {live.get('flagged', 0)} flagged",
                live,
            )
            return res

        sys_r, net_r, proc_r, ports_r, sw_r, dns_r, st_r = await asyncio.gather(
            tracked("sysinfo", self.collect_system_info()),
            tracked("network", self.collect_network()),
            tracked("processes", self.collect_processes()),
            tracked("ports", self.collect_ports()),
            tracked("software", self.collect_software()),
            tracked("dns", self.collect_dns()),
            tracked("startup", self.collect_startup()),
        )
        results = {
            "sysinfo": sys_r,
            "network": net_r,
            "processes": proc_r,
            "ports": ports_r,
            "software": sw_r,
            "dns": dns_r,
            "startup": st_r,
        }

        risk = self._risk_score(results)
        net = results.get("network", CollectorResult("network", False, {}))
        proc = results.get("processes", CollectorResult("processes", False, {}))
        ports = results.get("ports", CollectorResult("ports", False, {}))
        sw = results.get("software", CollectorResult("software", False, {}))
        dns = results.get("dns", CollectorResult("dns", False, {}))
        st = results.get("startup", CollectorResult("startup", False, {}))
        sysi = results.get("sysinfo", CollectorResult("sysinfo", False, {}))

        full = self.auto.device_get_full_results(self.session_id)
        full.setdefault("collectors", {})
        full["collectors"] = {k: {"ok": v.ok, "summary": v.summary, "error": v.error} for k, v in results.items()}

        system = full.get("system") or {}
        hostname = system.get("hostname") or get_builtin_system_info().get("hostname")
        os_platform = system.get("platform") or self.platform

        self.auto.device_session_finalize(
            self.session_id,
            {
                "status": "complete",
                "completed_at": utc_now_iso(),
                "hostname": hostname,
                "os_platform": os_platform,
                "overall_risk_score": risk,
                "connections_found": int(net.summary.get("found") or 0),
                "connections_flagged": int(net.summary.get("flagged") or 0),
                "processes_found": int(proc.summary.get("found") or 0),
                "processes_flagged": int(proc.summary.get("flagged") or 0),
                "ports_open": int(ports.summary.get("open") or 0),
                "ports_suspicious": int(ports.summary.get("suspicious") or 0),
                "software_count": int(sw.summary.get("count") or 0),
                "dns_entries_checked": int(dns.summary.get("checked") or 0),
                "dns_flagged": int(dns.summary.get("flagged") or 0),
                "startup_items": int(st.summary.get("total") or 0),
                "startup_flagged": int(st.summary.get("flagged") or 0),
                "full_results": full,
            },
        )

        await self.auto.device_scan_create_alerts_and_case(self.session_id, risk, net, proc, st)
        summary = {
            "riskScore": risk,
            "connectionsFound": int(net.summary.get("found") or 0),
            "connectionsFlagged": int(net.summary.get("flagged") or 0),
            "processesFound": int(proc.summary.get("found") or 0),
            "processesFlagged": int(proc.summary.get("flagged") or 0),
            "portsOpen": int(ports.summary.get("open") or 0),
            "softwareCount": int(sw.summary.get("count") or 0),
            "dnsFlagged": int(dns.summary.get("flagged") or 0),
            "startupFlagged": int(st.summary.get("flagged") or 0),
        }
        await self._emit({"type": "device_scan_complete", "event": "device_scan_complete", "sessionId": self.session_id, "summary": summary})

        if getattr(self.auto, "ioc_cache", None):
            asyncio.create_task(
                self.auto.ioc_cache.flush_queue(
                    self.feed,
                    lambda ioc_type, value: self._local_ioc_match(ioc_type, value),
                )
            )


async def run_device_scan_software_only(automation: Any, user_id: str) -> Dict[str, Any]:
    session_id = str(uuid.uuid4())
    automation.device_session_insert_running(session_id, user_id, "manual")
    agent = DeviceScanAgent(automation, user_id, session_id, "manual")
    r = await agent.collect_software()
    automation.device_session_finalize(
        session_id,
        {
            "status": "complete",
            "completed_at": utc_now_iso(),
            "overall_risk_score": 0,
            "connections_found": 0,
            "connections_flagged": 0,
            "processes_found": 0,
            "processes_flagged": 0,
            "ports_open": 0,
            "ports_suspicious": 0,
            "software_count": int(r.summary.get("count") or 0),
            "dns_entries_checked": 0,
            "dns_flagged": 0,
            "startup_items": 0,
            "startup_flagged": 0,
            "full_results": {"collectors": {"software": {"ok": r.ok, "summary": r.summary, "error": r.error}}},
        },
    )
    return {"session_id": session_id, "count": r.summary.get("count", 0), "ok": r.ok}


async def run_device_scan_async(automation: Any, user_id: str, session_id: str, triggered_by: str) -> None:
    agent = DeviceScanAgent(automation, user_id, session_id, triggered_by)
    try:
        await agent.run()
    except Exception as exc:
        logger.exception("run_device_scan_async failed")
        automation.device_session_mark_failed(session_id, str(exc))
        await automation.ws_hub.broadcast(
            {"type": "device_scan_complete", "event": "device_scan_complete", "sessionId": session_id, "summary": {"error": str(exc), "riskScore": 0}}
        )
