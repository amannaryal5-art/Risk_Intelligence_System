from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import os
import re
import socket
import ssl
import time
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from math import exp, sqrt
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlsplit
from urllib.request import Request, urlopen
from xml.etree import ElementTree
from datetime import datetime
import functools
import threading
import httpx

try:
    import whois as python_whois
except Exception:
    python_whois = None

logger = logging.getLogger("riskintel.risk_engine")


# ─────────────────────────────────────────────
# TTL-aware thread-safe in-process cache
# ─────────────────────────────────────────────
class TTLCache:
    """Thread-safe LRU-style cache with per-entry TTL."""

    def __init__(self, maxsize: int = 4096, ttl: float = 3600.0) -> None:
        self._store: Dict[str, Tuple[Any, float]] = {}
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
                # Evict oldest 10%
                oldest = sorted(self._store.items(), key=lambda x: x[1][1])[: self._maxsize // 10]
                for k, _ in oldest:
                    del self._store[k]
            self._store[key] = (value, time.monotonic())

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        return len(self._store)


@dataclass(frozen=True)
class Signal:
    name: str
    score: float
    detail: str


# ─────────────────────────────────────────────
# Extended threat pattern library
# ─────────────────────────────────────────────
RULE_SETS: Dict[str, Dict[str, float]] = {
    "credential_theft": {
        r"\bverify (your )?(account|identity)\b": 0.18,
        r"\breset (your )?password\b": 0.16,
        r"\blogin immediately\b": 0.12,
        r"\bsecurity alert\b": 0.10,
        r"\baccount (suspended|locked|disabled)\b": 0.17,
        r"\bconfirm (your )?(credentials|login|email)\b": 0.15,
    },
    "financial_fraud": {
        r"\bwire transfer\b": 0.17,
        r"\bgift card\b": 0.18,
        r"\bcrypto( wallet| payment)?\b": 0.13,
        r"\bbank details\b": 0.14,
        r"\bpayment failed\b": 0.10,
        r"\bsend (the )?funds?\b": 0.16,
        r"\bbitcoin\b": 0.12,
        r"\bwestern union\b": 0.19,
        r"\bmoney gram\b": 0.18,
        r"\binvoice (overdue|past due)\b": 0.13,
    },
    "urgency_pressure": {
        r"\bwithin (\d+ )?(minutes?|hours?)\b": 0.10,
        r"\bact now\b": 0.14,
        r"\bfinal warning\b": 0.15,
        r"\bimmediate action required\b": 0.18,
        r"\bexpires? (today|tonight|in \d+)\b": 0.12,
        r"\blast chance\b": 0.13,
        r"\btime.sensitive\b": 0.11,
    },
    "social_engineering": {
        r"\bthis is (the )?ceo\b": 0.15,
        r"\bkeep this confidential\b": 0.17,
        r"\bdo not tell anyone\b": 0.16,
        r"\btrusted partner\b": 0.08,
        r"\bpersonal favor\b": 0.11,
        r"\bbetween (us|you and me)\b": 0.10,
        r"\bdon'?t (mention|share|discuss) this\b": 0.14,
    },
    "business_email_compromise": {
        r"\bkindly process\b": 0.13,
        r"\bapproved by management\b": 0.10,
        r"\bout of office\b": 0.08,
        r"\bvendor update\b": 0.12,
        r"\bnew (banking|payment) (details?|instructions?)\b": 0.19,
        r"\bchange (of )?account (details?|number)\b": 0.17,
        r"\bauthorized (by|from) (the )?(cfo|ceo|management)\b": 0.15,
    },
    "malware_delivery": {
        r"\bopen (the |this )?(attached?|file|document)\b": 0.13,
        r"\bdownload (and )?(install|run|execute)\b": 0.16,
        r"\benable (macro|content)\b": 0.18,
        r"\bclick (to |here to )?(view|access|download)\b": 0.12,
        r"\bupdate (required|needed|now)\b": 0.11,
    },
    "romance_scam": {
        r"\bsend (me )?money\b": 0.17,
        r"\bi (love|miss|need) you\b.*\b(send|transfer|help)\b": 0.16,
        r"\bstranded (abroad|overseas|at the airport)\b": 0.19,
        r"\bmedical emergency\b.*\bmoney\b": 0.18,
    },
    "lottery_scam": {
        r"\byou (have |'ve )?(won|been selected)\b": 0.16,
        r"\bclaim (your )?(prize|winnings?|reward)\b": 0.17,
        r"\blottery (winner|jackpot)\b": 0.18,
        r"\bunclaimed (funds?|prize)\b": 0.15,
    },
}

INTENT_PROTOTYPES: Dict[str, str] = {
    "phishing_credential_theft": "Your account is suspended. Verify identity and password now.",
    "invoice_or_wire_fraud": "Urgent transfer required to secure corporate payment channel.",
    "gift_card_scam": "Purchase gift cards immediately and send the claim codes.",
    "malicious_link_delivery": "Security warning: click link to avoid permanent account lock.",
    "executive_impersonation": "Confidential request from executive: process payment discreetly.",
    "bank_detail_tampering": "Update bank details now to prevent payroll disruption.",
    "malware_download": "Enable macros to view important document. Download and install update.",
    "romance_fraud": "I love you and need your help. Send money urgently.",
    "lottery_fraud": "You have won a prize. Claim your lottery winnings now.",
    "advance_fee_fraud": "Transfer fee required to release inheritance funds to your account.",
}


class RiskEngine:
    """
    Hybrid fraud detection engine — deterministic rules + NLP cosine similarity.
    v3: async-ready, parallel link tracing, TTL caches, extended rule library.
    """

    _global_link_cache = TTLCache(maxsize=8192, ttl=1800.0)
    _global_whois_cache = TTLCache(maxsize=2048, ttl=7200.0)
    _global_domain_cache = TTLCache(maxsize=4096, ttl=3600.0)
    _global_cert_cache = TTLCache(maxsize=1024, ttl=3600.0)
    _global_sitemap_cache = TTLCache(maxsize=512, ttl=1800.0)

    def __init__(self) -> None:
        self.rule_sets = RULE_SETS
        self.intent_prototypes = INTENT_PROTOTYPES
        self.prototype_vectors = {
        }
        self.high_risk_terms = {
            "password", "otp", "bank", "transfer", "wallet", "payment", "urgent",
            "verify", "confidential", "gift", "card", "crypto", "pin", "credential",
            "click", "link", "bitcoin", "invoice", "wire", "lottery", "prize",
            "winner", "inheritance", "claim", "fund", "release",
        }
        self.shortener_domains = {
            "bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd", "goo.gl",
            "ow.ly", "shorturl.at", "cutt.ly", "rebrand.ly", "tiny.cc",
            "snip.ly", "bl.ink", "short.io",
        }
        self.suspicious_tlds = {
            "zip", "mov", "top", "gq", "tk", "work", "click", "cam", "rest",
            "country", "stream", "xyz", "pw", "cc", "biz", "info",
        }
        self.sensitive_query_keys = {"url", "redirect", "next", "target", "dest", "continue", "return", "goto"}
        self.suspicious_file_ext = {".exe", ".msi", ".bat", ".cmd", ".scr", ".js", ".vbs", ".jar", ".ps1", ".hta", ".pif"}
        self.link_risk_terms = {"login", "verify", "secure", "wallet", "bank", "password", "update", "payment", "signin", "account"}
        self.reputation_risky_terms = {
            "secure", "verify", "update", "wallet", "login", "account",
            "signin", "support", "billing", "payment", "confirm", "auth",
        }
        self.known_brands = {
            "google", "microsoft", "apple", "amazon", "paypal", "netflix",
            "facebook", "instagram", "whatsapp", "linkedin", "github",
            "dropbox", "twitter", "x", "bankofamerica", "chase", "wellsfargo",
            "citibank", "outlook", "office365", "youtube", "tiktok", "coinbase",
            "binance", "kraken", "robinhood", "stripe", "shopify",
        }
        self.brand_text_terms = {
            "google", "microsoft", "apple", "amazon", "paypal", "netflix",
            "facebook", "instagram", "linkedin", "github", "outlook", "office365",
            "bank of america", "wells fargo", "citi", "chase bank", "youtube",
            "tiktok", "coinbase", "binance",
        }
        self.typo_homograph_map = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})

        # Pre-compiled regex patterns
        self._re_url_scheme = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
        self._re_link_pattern = re.compile(r"(?:(?:https?|ftp)://|www\.)[^\s<>'\"()]+", flags=re.IGNORECASE)
        self._re_asset_ext = re.compile(r"\.(png|jpg|jpeg|gif|svg|ico|webp|woff2?|ttf|eot|css|js|map|mp4|mp3|pdf)$")
        self._re_title = re.compile(r"<title[^>]*>(.*?)</title>", flags=re.IGNORECASE | re.DOTALL)
        self._re_href = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', flags=re.IGNORECASE)
        self._re_tag_strip = re.compile(r"<[^>]+>")
        self._re_script_strip = re.compile(r"<script[\s\S]*?</script>", flags=re.IGNORECASE)
        self._re_style_strip = re.compile(r"<style[\s\S]*?</style>", flags=re.IGNORECASE)
        self._re_multi_ws = re.compile(r"\s+")
        self._re_obfuscated_link = re.compile(r"hxxps?://|\[\.\]|\(\.\)")
        self._re_repeated_chars = re.compile(r"(.)\1{5,}")
        self._re_currency = re.compile(r"\$\d+|\b\d{2,}(?:,\d{3})*(?:\.\d+)?\b")
        self._re_caps = re.compile(r"\b[A-Z]{3,}\b")
        self._re_exec_ext = re.compile(r"\.[a-zA-Z0-9]{2,5}$")
        self._re_whois_date = re.compile(r"(20\d{2})[-/](\d{1,2})[-/](\d{1,2})")

        # Compile rule sets once
        self._rule_sets_compiled: Dict[str, List[Tuple[re.Pattern, float, str]]] = {}
        for category, patterns in self.rule_sets.items():
            self._rule_sets_compiled[category] = [
                (re.compile(pat, re.IGNORECASE), weight, pat)
                for pat, weight in patterns.items()
            ]

        # Thread pool for parallel I/O (link tracing, cert checks, WHOIS)
        self._executor = ThreadPoolExecutor(max_workers=20, thread_name_prefix="riskintel")
        
    # ──────────────────────────────────────────
    # Core NLP helpers
    # ──────────────────────────────────────────
    def _normalize(self, text: str) -> str:
        return self._re_multi_ws.sub(" ", text.strip().lower())

    def _deobfuscate_links_text(self, text: str) -> str:
        return (
            text.replace("[.]", ".").replace("(.)", ".")
            .replace("hxxp://", "http://").replace("hxxps://", "https://")
        )

    def _tokenize(self, text: str) -> List[str]:
        return re.findall(r"[a-zA-Z0-9']+", text)

    def _vectorize(self, text: str) -> Counter:
        tokens = self._tokenize(text)
        if len(tokens) < 2:
            return Counter(tokens)
        bigrams = [f"{tokens[i]}_{tokens[i+1]}" for i in range(len(tokens) - 1)]
        return Counter(tokens + bigrams)

    def _cosine(self, a: Counter, b: Counter) -> float:
        if not a or not b:
            return 0.0
        dot = sum(a[k] * b.get(k, 0) for k in a)
        norm_a = sqrt(sum(v * v for v in a.values()))
        norm_b = sqrt(sum(v * v for v in b.values()))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def _extract_links(self, text: str) -> List[str]:
        candidate_text = self._deobfuscate_links_text(text)
        links = self._re_link_pattern.findall(candidate_text)
        seen: Set[str] = set()
        unique: List[str] = []
        for link in links:
            normalized = link.strip(".,);]}>\"'")
            low = normalized.lower()
            if normalized and low not in seen:
                seen.add(low)
                unique.append(normalized)
        return unique

    @staticmethod
    def _effective_domain(hostname: str) -> str:
        parts = [p for p in hostname.split(".") if p]
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname

    @staticmethod
    def _sld(hostname: str) -> str:
        parts = [p for p in hostname.split(".") if p]
        return parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")

    @staticmethod
    def _levenshtein(a: str, b: str) -> int:
        if a == b:
            return 0
        if not a:
            return len(b)
        if not b:
            return len(a)
        if len(a) < len(b):
            a, b = b, a
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, start=1):
            cur = [i]
            for j, cb in enumerate(b, start=1):
                cur.append(min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + (0 if ca == cb else 1)))
            prev = cur
        return prev[-1]

    # ──────────────────────────────────────────
    # Domain intelligence (with global TTL caches)
    # ──────────────────────────────────────────
    def _domain_reputation_profile(self, hostname: str) -> Dict[str, object]:
        host = (hostname or "").strip().lower()
        if not host:
            return {"score": 0.0, "flags": [], "category": "unknown"}
        cached = self._global_domain_cache.get(host)
        if cached is not None:
            return cached

        score = 0.0
        flags: List[str] = []
        sld = self._sld(host)
        digits = sum(ch.isdigit() for ch in sld)
        hyphens = sld.count("-")
        alpha = sum(ch.isalpha() for ch in sld)
        entropy_like = len(set(sld)) / max(len(sld), 1)
        risky_term_hits = [term for term in self.reputation_risky_terms if term in host]
        tld = host.rsplit(".", 1)[-1] if "." in host else ""

        if digits >= 3:
            score += 0.07; flags.append("Heavy numeric usage in domain")
        if hyphens >= 2:
            score += 0.08; flags.append("Multiple hyphens in domain")
        if len(sld) >= 22:
            score += 0.08; flags.append("Very long second-level domain")
        if entropy_like > 0.82 and len(sld) >= 10 and alpha >= 6:
            score += 0.06; flags.append("High-randomness domain label")
        if risky_term_hits:
            score += min(0.15, 0.04 * len(risky_term_hits))
            flags.append(f"Risky terms in domain: {', '.join(sorted(set(risky_term_hits)))}")
        if tld in self.suspicious_tlds:
            score += 0.10; flags.append(f"Suspicious TLD .{tld}")

        category = "poor" if score >= 0.45 else ("questionable" if score >= 0.25 else "neutral")
        out = {"score": round(min(1.0, score), 3), "flags": flags[:8], "category": category}
        self._global_domain_cache.set(host, out)
        return out

    def _brand_impersonation_profile(self, text: str, hostname: str) -> Dict[str, object]:
        norm = self._normalize(text)
        host = (hostname or "").lower()
        hits = [b for b in self.brand_text_terms if b in norm]
        if not hits:
            return {"score": 0.0, "flags": [], "brands": []}
        effective = self._effective_domain(host)
        flags: List[str] = []
        score = 0.0
        brands: List[str] = []
        for b in hits:
            token = re.sub(r"[^a-z0-9]", "", b.lower())
            if not token:
                continue
            brands.append(b)
            if token not in effective:
                score += 0.07
                flags.append(f"Brand '{b}' mismatches destination domain")
        if len(set(brands)) >= 2:
            score += 0.05; flags.append("Multiple brand references")
        return {"score": round(min(0.35, score), 3), "flags": flags[:8], "brands": sorted(set(brands))[:8]}

    def _typosquat_profile(self, hostname: str) -> Dict[str, object]:
        host = (hostname or "").strip().lower()
        if not host:
            return {"score": 0.0, "flags": [], "closest_brand": None}
        sld = self._sld(host)
        normalized = sld.translate(self.typo_homograph_map)
        if len(normalized) < 3:
            return {"score": 0.0, "flags": [], "closest_brand": None}

        best_brand: Optional[str] = None
        best_dist = 99
        for brand in self.known_brands:
            dist = self._levenshtein(normalized, brand)
            if dist < best_dist:
                best_dist = dist
                best_brand = brand

        score = 0.0
        flags: List[str] = []
        if best_brand and normalized != best_brand:
            if best_dist == 1:
                score += 0.26; flags.append(f"Likely typosquat of '{best_brand}' (edit distance 1)")
            elif best_dist == 2 and len(best_brand) >= 6:
                score += 0.17; flags.append(f"Possible typosquat of '{best_brand}' (edit distance 2)")
        if best_brand and best_brand in normalized and normalized != best_brand:
            extra = normalized.replace(best_brand, "")
            if len(extra) >= 3:
                score += 0.09; flags.append(f"Brand '{best_brand}' embedded with deceptive token")
        return {"score": round(min(0.4, score), 3), "flags": flags[:8], "closest_brand": best_brand}

    def _whois_domain_age_profile(self, hostname: str) -> Dict[str, object]:
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
        status = "unavailable"
        rdap_url = f"https://rdap.org/domain/{root}"
        try:
            req = Request(rdap_url, headers={"User-Agent": "RiskIntel/3.0", "Accept": "application/rdap+json"})
            with urlopen(req, timeout=2.5) as resp:
                payload = resp.read(240000).decode("utf-8", errors="ignore")
            m = self._re_whois_date.search(payload)
            if m:
                year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
                created = datetime(year=year, month=max(1, min(month, 12)), day=max(1, min(day, 28)))
                age_days = max(0, (datetime.utcnow() - created).days)
                status = "ok"
        except Exception:
            status = "unavailable"

        if age_days is not None:
            if age_days < 30:
                score += 0.23; flags.append("Very new domain (<30 days)")
            elif age_days < 90:
                score += 0.16; flags.append("Recently registered (<90 days)")
            elif age_days < 180:
                score += 0.10; flags.append("Young domain (<180 days)")

        out = {"score": round(min(0.3, score), 3), "flags": flags, "age_days": age_days, "status": status}
        self._global_whois_cache.set(host, out)
        return out

    # ──────────────────────────────────────────
    # Link tracing (parallel via thread pool)
    # ──────────────────────────────────────────
    def _trace_single_link(self, raw_link: str) -> Dict[str, object]:
        key = raw_link.strip().lower()
        cached = self._global_link_cache.get(key)
        if cached is not None:
            return cached

        working = raw_link if self._re_url_scheme.match(raw_link) else f"http://{raw_link}"
        parsed = urlsplit(working)
        hostname = (parsed.hostname or "").strip().lower()
        path = parsed.path or ""
        query = parsed.query or ""

        score = 0.0
        flags: List[str] = []

        if parsed.scheme == "http":
            score += 0.10; flags.append("Unencrypted HTTP scheme")
        if "@" in parsed.netloc:
            score += 0.15; flags.append("Credentials in URL (user-info)")
        if hostname in self.shortener_domains:
            score += 0.16; flags.append("Known URL shortener")
        if hostname.startswith("xn--") or ".xn--" in hostname:
            score += 0.12; flags.append("Punycode/IDN domain spoofing risk")
        if any(ord(ch) > 127 for ch in hostname):
            score += 0.10; flags.append("Non-ASCII domain characters")

        subdomain_depth = max(0, len(hostname.split(".")) - 2)
        if subdomain_depth >= 3:
            score += 0.08; flags.append("Deep subdomain chain")
        if len(working) > 140:
            score += 0.08; flags.append("Excessive URL length")
        if parsed.port and parsed.port not in {80, 443}:
            score += 0.08; flags.append(f"Non-standard port {parsed.port}")

        last_dot = hostname.rfind(".")
        tld = hostname[last_dot + 1:] if last_dot > -1 else ""
        if tld in self.suspicious_tlds:
            score += 0.14; flags.append(f"Suspicious TLD .{tld}")

        lower_full = f"{hostname}{path}?{query}".lower()
        keyword_hits = [k for k in self.link_risk_terms if k in lower_full]
        if keyword_hits:
            score += min(0.12, 0.03 * len(keyword_hits))
            flags.append(f"Risk keywords in URL: {', '.join(sorted(set(keyword_hits)))}")

        ext_match = self._re_exec_ext.search(path.lower())
        if ext_match and ext_match.group(0) in self.suspicious_file_ext:
            score += 0.20; flags.append(f"Executable/script extension {ext_match.group(0)}")

        encoded_ratio = working.count("%") / max(len(working), 1)
        if encoded_ratio > 0.03 or working.count("%") >= 4:
            score += 0.07; flags.append("Heavy URL percent-encoding")

        query_map = parse_qs(query, keep_blank_values=True)
        redirect_keys = [k for k in query_map if k.lower() in self.sensitive_query_keys]
        if redirect_keys:
            score += 0.12; flags.append(f"Open redirect parameters: {', '.join(sorted(redirect_keys))}")

        ip_label = ip_type = None
        if hostname:
            try:
                ip_obj = ipaddress.ip_address(hostname)
                ip_label = str(ip_obj)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    score += 0.10; ip_type = "private/local"; flags.append("Private/local IP host")
                else:
                    score += 0.07; ip_type = "public"; flags.append("Direct IP instead of domain")
            except ValueError:
                pass

        reputation = self._domain_reputation_profile(hostname)
        typo = self._typosquat_profile(hostname)
        whois_age = self._whois_domain_age_profile(hostname)
        score += min(0.18, float(reputation.get("score", 0.0)) * 0.7)
        flags.extend(list(reputation.get("flags", []))[:2])
        score += min(0.20, float(typo.get("score", 0.0)) * 0.9)
        flags.extend(list(typo.get("flags", []))[:2])
        score += min(0.12, float(whois_age.get("score", 0.0)) * 0.8)
        flags.extend(list(whois_age.get("flags", []))[:1])

        score = min(1.0, max(0.0, score))
        verdict = "critical" if score >= 0.65 else ("high" if score >= 0.45 else ("medium" if score >= 0.25 else "low"))

        out = {
            "raw": raw_link,
            "normalized": working,
            "scheme": parsed.scheme,
            "host": hostname,
            "port": parsed.port,
            "path": path,
            "query_keys": sorted(query_map.keys()),
            "ip": ip_label,
            "ip_type": ip_type,
            "score": round(score, 3),
            "verdict": verdict,
            "flags": self._dedupe_ordered(flags)[:12],
            "domain_intelligence": {
                "domain_reputation": reputation,
                "typosquatting": typo,
                "whois_age": whois_age,
            },
        }
        self._global_link_cache.set(key, out)
        return out

    def trace_links(self, text: str) -> Dict[str, object]:
        links = self._extract_links(text)
        if not links:
            return {"total_links": 0, "high_risk_links": 0, "medium_risk_links": 0, "aggregate_score": 0.0, "links": []}

        # Parallel link tracing
        futures = {self._executor.submit(self._trace_single_link, link): link for link in links}
        traced: List[Dict[str, object]] = []
        for future in as_completed(futures):
            try:
                traced.append(future.result(timeout=6.0))
            except Exception:
                pass

        high_count = sum(1 for x in traced if x["verdict"] in {"high", "critical"})
        med_count = sum(1 for x in traced if x["verdict"] == "medium")
        total_score = round(sum(float(x["score"]) for x in traced), 3)
        return {
            "total_links": len(traced),
            "high_risk_links": high_count,
            "medium_risk_links": med_count,
            "aggregate_score": total_score,
            "links": sorted(traced, key=lambda x: float(x["score"]), reverse=True),
        }

    # ──────────────────────────────────────────
    # Entity extraction
    # ──────────────────────────────────────────
    def _extract_entities(self, text: str) -> Dict[str, object]:
        emails = re.findall(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", text)
        phones = re.findall(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)\d{3,4}[-.\s]?\d{3,4}\b", text)
        ipv4s = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        crypto_wallets = re.findall(r"\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", text)
        long_numeric_ids = re.findall(r"\b\d{10,18}\b", text)
        cvv_pattern = re.findall(r"\b\d{3,4}\b", text)  # light card CVV indicator
        entities = {
            "emails": sorted(set(emails))[:12],
            "phones": sorted(set(phones))[:12],
            "ipv4s": sorted(set(ipv4s))[:12],
            "crypto_wallets": sorted(set(crypto_wallets))[:12],
            "numeric_ids": sorted(set(long_numeric_ids))[:12],
        }
        entities["counts"] = {k: len(v) for k, v in entities.items() if isinstance(v, list)}
        entities["total"] = sum(entities["counts"].values())
        return entities

    # ──────────────────────────────────────────
    # Intent profiling
    # ──────────────────────────────────────────
    def _intent_profile(self, text: str) -> Dict[str, object]:
        norm = self._normalize(text)
        query_vector =         self._vectorize(norm)
        intent_scores = [
            {"intent": intent, "similarity": round(self._cosine(query_vector, proto), 3)}
            for intent, proto in self.prototype_vectors.items()
        ]
        top_intents = sorted(intent_scores, key=lambda x: x["similarity"], reverse=True)[:3]
        return {"top_intents": top_intents, "max_similarity": top_intents[0]["similarity"] if top_intents else 0.0}

    # ──────────────────────────────────────────
    # Signal extraction
    # ──────────────────────────────────────────
    def _extract_rule_signals(self, text: str) -> List[Signal]:
        norm = self._normalize(text)
        signals: List[Signal] = []
        for category, patterns in self._rule_sets_compiled.items():
            cat_hits: List[Tuple[str, float]] = []
            for compiled, weight, raw_pattern in patterns:
                if compiled.search(norm):
                    cat_hits.append((raw_pattern, weight))
            if not cat_hits:
                continue
            cat_hits.sort(key=lambda x: x[1], reverse=True)
            cat_score = sum(w * (1.0 if i == 0 else (0.62 if i == 1 else 0.30)) for i, (_, w) in enumerate(cat_hits))
            cat_score = min(0.28, cat_score)
            signals.append(Signal(
                name=f"rule::{category}",
                score=cat_score,
                detail=f"Matched {len(cat_hits)} pattern(s) in {category}; strongest '{cat_hits[0][0]}'.",
            ))
        return signals

    def _nlp_signals(
        self,
        text: str,
        extracted_links: Optional[List[str]] = None,
        intent_profile: Optional[Dict[str, object]] = None,
    ) -> List[Signal]:
        norm = self._normalize(text)
        words = self._tokenize(norm)
        total_words = max(len(words), 1)
        high_risk_hits = sum(1 for w in words if w in self.high_risk_terms)
        risk_density = high_risk_hits / total_words
        exclamations = text.count("!")
        caps_words = self._re_caps.findall(text)
        link_hits = len(extracted_links) if extracted_links is not None else len(self._extract_links(text))
        currency_hits = len(self._re_currency.findall(text))
        obfuscated_hits = len(self._re_obfuscated_link.findall(text.lower()))
        profile = intent_profile if intent_profile is not None else self._intent_profile(text)
        sim = float(profile["max_similarity"])

        signals: List[Signal] = []
        if risk_density > 0.08:
            signals.append(Signal("nlp::risk_term_density", min(0.18, risk_density * 1.4), f"High-risk term density {risk_density:.2f}"))
        if sim > 0.25:
            signals.append(Signal("nlp::intent_similarity", min(0.25, sim * 0.55), f"Fraud intent similarity {sim:.2f}"))
        if exclamations >= 3:
            signals.append(Signal("nlp::pressure_tone", min(0.08, exclamations * 0.02), f"{exclamations} exclamation marks"))
        if len(caps_words) >= 2:
            signals.append(Signal("nlp::aggressive_caps", 0.07, "Multiple ALL-CAPS tokens"))
        if link_hits > 0:
            signals.append(Signal("nlp::external_link", min(0.10, 0.05 + 0.02 * link_hits), f"{link_hits} external link(s)"))
        if currency_hits > 0:
            signals.append(Signal("nlp::money_reference", min(0.09, 0.03 + currency_hits * 0.02), f"{currency_hits} currency indicator(s)"))
        if obfuscated_hits > 0:
            signals.append(Signal("nlp::link_obfuscation", min(0.16, 0.06 + obfuscated_hits * 0.03), f"{obfuscated_hits} obfuscated link(s)"))
        if self._re_repeated_chars.search(text):
            signals.append(Signal("nlp::pattern_anomaly", 0.06, "Repeated-character pattern anomaly"))
        return signals

    # ──────────────────────────────────────────
    # Score synthesis
    # ──────────────────────────────────────────
    def _score_from_evidence(self, signals: List[Signal], link_analysis: Dict[str, object]) -> Dict[str, float]:
        rule_sum = nlp_sum = intel_sum = 0.0
        signal_names = [s.name for s in signals]
        for s in signals:
            if s.name.startswith("rule::"):
                rule_sum += s.score
            elif s.name.startswith("nlp::"):
                nlp_sum += s.score
            else:
                intel_sum += s.score

        rule_capped = min(0.56, rule_sum)
        nlp_capped = min(0.34, nlp_sum)
        intel_capped = min(0.24, intel_sum)
        raw_capped = rule_capped + nlp_capped + intel_capped

        fusion_boost = 0.0
        if rule_capped > 0.25 and nlp_capped > 0.14:
            fusion_boost += 0.06
        if int(link_analysis.get("high_risk_links", 0)) > 0 and (
            "nlp::link_obfuscation" in signal_names or intel_capped > 0.08
        ):
            fusion_boost += 0.05
        if "rule::financial_fraud" in signal_names and "rule::social_engineering" in signal_names:
            fusion_boost += 0.04
        if "nlp::intent_similarity" in signal_names and nlp_capped > 0.18:
            fusion_boost += 0.03

        blended = min(1.0, raw_capped + fusion_boost)
        calibrated = min(0.96, max(0.0, 1.0 - exp(-1.45 * blended)))
        return {
            "rule": round(rule_capped, 3),
            "nlp": round(nlp_capped, 3),
            "intel": round(intel_capped, 3),
            "fusion": round(fusion_boost, 3),
            "raw": round(blended, 3),
            "calibrated": round(calibrated, 3),
        }

    def _dimension_scores(self, signals: List[Signal], link_analysis: Dict, entities: Dict) -> Dict[str, int]:
        dims = {k: 0.0 for k in ("credential_theft", "financial_fraud", "social_engineering", "coercion_pressure", "link_abuse", "data_exposure")}
        for s in signals:
            n = s.name
            if "credential" in n or "password" in s.detail.lower():
                dims["credential_theft"] += s.score * 120
            if "financial" in n or "money" in n or "payment" in s.detail.lower():
                dims["financial_fraud"] += s.score * 120
            if "social_engineering" in n or "impersonation" in n:
                dims["social_engineering"] += s.score * 120
            if "urgency" in n or "pressure" in n or "aggressive_caps" in n:
                dims["coercion_pressure"] += s.score * 110
            if "link" in n:
                dims["link_abuse"] += s.score * 140
        dims["link_abuse"] += float(link_analysis.get("aggregate_score", 0.0)) * 45
        dims["link_abuse"] += int(link_analysis.get("high_risk_links", 0)) * 10
        entity_counts = entities.get("counts", {})
        dims["data_exposure"] += entity_counts.get("emails", 0) * 8
        dims["data_exposure"] += entity_counts.get("phones", 0) * 6
        dims["data_exposure"] += entity_counts.get("numeric_ids", 0) * 5
        dims["financial_fraud"] += entity_counts.get("crypto_wallets", 0) * 10
        return {k: min(100, int(round(v))) for k, v in dims.items()}

    def _confidence_score(self, score_100: int, signal_count: int, text_length: int) -> int:
        confidence = (score_100 / 100) * 0.6 + min(0.25, signal_count * 0.03) + min(0.15, text_length / 1400)
        return min(99, max(10, int(round(confidence * 100))))

    def _recommendations(self, risk_level: str, link_analysis: Dict, entities: Dict) -> List[str]:
        recs: List[str] = []
        if risk_level in {"high", "critical"}:
            recs.append("Immediately isolate this message and trigger analyst review.")
            recs.append("Block detected URLs/domains at email gateway, DNS, and proxy controls.")
        if int(link_analysis.get("high_risk_links", 0)) > 0:
            recs.append("Perform safe detonation/sandboxing for all extracted links.")
        if entities.get("counts", {}).get("crypto_wallets", 0):
            recs.append("Escalate to financial fraud — cryptocurrency transfer indicators found.")
        if entities.get("counts", {}).get("numeric_ids", 0):
            recs.append("Mask sensitive numeric identifiers and open data-exposure case.")
        if risk_level in {"low", "medium"}:
            recs.append("Keep under monitoring; auto-recheck on repeated sender patterns.")
        recs.append("Preserve message headers and metadata for forensic correlation.")
        return recs[:6]

    @staticmethod
    def _dedupe_ordered(items: List[str]) -> List[str]:
        seen: Set[str] = set()
        return [item for item in items if item.strip() and not (item.strip() in seen or seen.add(item.strip()))]

    def _dedupe_signals(self, signals: List[Signal]) -> List[Signal]:
        best: Dict[Tuple[str, str], Signal] = {}
        for sig in signals:
            key = (sig.name, sig.detail)
            if key not in best or sig.score > best[key].score:
                best[key] = sig
        return list(best.values())

    def _benign_context_reduction(self, text: str, link_analysis: Dict) -> float:
        norm = self._normalize(text)
        benign_terms = {"meeting", "agenda", "minutes", "calendar", "schedule", "review", "draft", "notes", "thanks", "regards", "tomorrow", "team", "update"}
        tokens = set(self._tokenize(norm))
        benign_hits = len(tokens.intersection(benign_terms))
        risky_links = int(link_analysis.get("high_risk_links", 0)) + int(link_analysis.get("medium_risk_links", 0))
        if benign_hits < 3 or risky_links > 0:
            return 0.0
        return min(0.12, 0.02 * (benign_hits - 2))

    # ──────────────────────────────────────────
    # Main analyze entry point
    # ──────────────────────────────────────────
    def analyze(self, text: str) -> Dict[str, object]:
        if not text or not text.strip():
            return {
                "score": 0, "risk_level": "low", "plain_verdict": "No content to analyze.",
                "top_flags": [], "signals": [], "summary": "No content provided.",
                "link_analysis": {"total_links": 0, "high_risk_links": 0, "medium_risk_links": 0, "aggregate_score": 0.0, "links": []},
                "entities": {"emails": [], "phones": [], "ipv4s": [], "crypto_wallets": [], "numeric_ids": [], "counts": {}, "total": 0},
                "intent_profile": {"top_intents": [], "max_similarity": 0.0},
                "dimensions": {}, "confidence": 0,
                "domain_intelligence": {"brand_impersonation": {"score": 0.0, "flags": [], "brands": []}, "best_link_host": None},
                "recommendations": [], "threat_fingerprint": None,
            }

        # Parallel: link tracing + entity extraction + intent profiling simultaneously
        with ThreadPoolExecutor(max_workers=3) as pool:
            future_links = pool.submit(self.trace_links, text)
            future_entities = pool.submit(self._extract_entities, text)
            future_intent = pool.submit(self._intent_profile, text)
            link_analysis = future_links.result()
            entities = future_entities.result()
            intent_profile = future_intent.result()

        extracted_links = [str(item.get("raw", "")) for item in link_analysis.get("links", []) if item.get("raw")]
        signals = self._extract_rule_signals(text) + self._nlp_signals(text, extracted_links=extracted_links, intent_profile=intent_profile)

        best_link = max(link_analysis.get("links", []) or [{}], key=lambda x: float(x.get("score", 0.0)), default={})
        target_host = str((best_link or {}).get("host", "")).lower()
        brand_intel = self._brand_impersonation_profile(text, target_host)
        if float(brand_intel.get("score", 0.0)) > 0:
            signals.append(Signal("intel::brand_impersonation", min(0.20, float(brand_intel["score"])), "Brand impersonation content-domain mismatch"))
        signals = self._dedupe_signals(signals)
        if link_analysis["total_links"] > 0:
            signals.append(Signal("intel::link_trace", min(0.28, float(link_analysis["aggregate_score"]) * 0.22),
                                  f"Traced {link_analysis['total_links']} link(s), {link_analysis['high_risk_links']} high-risk."))
        if entities.get("total", 0) > 0:
            signals.append(Signal("intel::sensitive_entity_presence", min(0.14, 0.03 + entities["total"] * 0.015),
                                  f"Detected {entities['total']} sensitive entity indicator(s)."))

        score_breakdown = self._score_from_evidence(signals, link_analysis)
        benign_reduction = self._benign_context_reduction(text, link_analysis)
        calibrated = max(0.0, float(score_breakdown["calibrated"]) - benign_reduction)
        score_breakdown.update({"benign_reduction": round(benign_reduction, 3), "final": round(calibrated, 3)})
        score_100 = int(round(calibrated * 100))

        level = "critical" if score_100 >= 84 else ("high" if score_100 >= 66 else ("medium" if score_100 >= 42 else "low"))
        dimensions = self._dimension_scores(signals, link_analysis, entities)
        confidence = self._confidence_score(score_100, len(signals), len(text))
        if level == "critical" and confidence < 78:
            level = "high"
        if level == "high" and confidence < 48:
            level = "medium"

        summary = ("No explicit fraud indicators found." if not signals
                   else "Top indicators: " + "; ".join(f"{x.name} ({x.score:.2f})" for x in sorted(signals, key=lambda s: s.score, reverse=True)[:3]))
        top_flags = self._dedupe_ordered([s.detail for s in sorted(signals, key=lambda s: s.score, reverse=True)])[:5]
        plain_verdicts = {
            "critical": "High probability of scam or malicious content. Block immediately.",
            "high": "Strong risk indicators found. Requires analyst verification.",
            "medium": "Suspicious patterns detected. Proceed with caution.",
            "low": "No major fraud signals detected.",
        }

        return {
            "score": score_100,
            "risk_level": level,
            "confidence": confidence,
            "score_breakdown": score_breakdown,
            "plain_verdict": plain_verdicts[level],
            "top_flags": top_flags,
            "signals": [{"name": s.name, "score": round(s.score, 3), "detail": s.detail} for s in signals],
            "summary": summary,
            "intent_profile": intent_profile,
            "dimensions": dimensions,
            "entities": entities,
            "link_analysis": link_analysis,
            "domain_intelligence": {"brand_impersonation": brand_intel, "best_link_host": target_host or None},
            "recommendations": self._recommendations(level, link_analysis, entities),
            "threat_fingerprint": hashlib.sha256(self._normalize(text).encode()).hexdigest()[:24],
        }

    # ──────────────────────────────────────────
    # Async wrappers for FastAPI async endpoints
    # ──────────────────────────────────────────
    async def analyze_async(self, text: str) -> Dict[str, object]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self.analyze, text)

    async def analyze_batch_async(self, texts: List[str]) -> List[Dict[str, object]]:
        loop = asyncio.get_event_loop()
        tasks = [loop.run_in_executor(self._executor, self.analyze, t) for t in texts]
        return await asyncio.gather(*tasks)

    # ──────────────────────────────────────────
    # Website tracer (unchanged logic, optimized I/O)
    # ──────────────────────────────────────────
    def _normalize_site_url(self, website_url: str) -> str:
        cleaned = website_url.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
            cleaned = f"https://{cleaned}"
        parsed = urlsplit(cleaned)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Only http/https URLs are supported.")
        if not parsed.netloc:
            raise ValueError("Invalid website URL.")
        return cleaned

    def _same_site(self, root_host: str, host: str) -> bool:
        return bool(host) and (host == root_host or host.endswith(f".{root_host}"))

    def _extract_html_links(self, html: str, base_url: str) -> List[str]:
        seen: Set[str] = set()
        unique: List[str] = []
        for href in self._re_href.findall(html):
            if href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            abs_url = urljoin(base_url, href).split("#")[0].strip()
            if not abs_url:
                continue
            if urlsplit(abs_url).scheme not in {"http", "https"}:
                continue
            if abs_url not in seen:
                seen.add(abs_url)
                unique.append(abs_url)
        return unique

    def _html_to_text(self, html: str) -> str:
        return self._re_multi_ws.sub(" ", self._re_tag_strip.sub(" ", self._re_style_strip.sub(" ", self._re_script_strip.sub(" ", html)))).strip()

    def _extract_title(self, html: str) -> str:
        m = self._re_title.search(html)
        return re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""

    def _format_cert_time(self, value: str) -> str:
        try:
            return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").strftime("%d %b %Y %H:%M")
        except Exception:
            return value

    def _flatten_cert_name(self, cert_name: object) -> str:
        out: List[str] = []
        if isinstance(cert_name, tuple):
            for rdn in cert_name:
                if isinstance(rdn, tuple):
                    for item in rdn:
                        if isinstance(item, tuple) and len(item) == 2:
                            out.append(str(item[1]))
        return ", ".join([x for x in out if x]) or "Unknown"

    def _fetch_certificate(self, host: str, port: int = 443) -> Dict[str, object]:
        cached = self._global_cert_cache.get(host)
        if cached is not None:
            return cached
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=2.5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            out = {
                "host": host,
                "subject": self._flatten_cert_name(cert.get("subject", ())),
                "issuer": self._flatten_cert_name(cert.get("issuer", ())),
                "valid_from": self._format_cert_time(str(cert.get("notBefore", ""))),
                "valid_to": self._format_cert_time(str(cert.get("notAfter", ""))),
                "status": "ok",
            }
        except Exception as exc:
            out = {"host": host, "subject": "Unknown", "issuer": "Unknown", "valid_from": "", "valid_to": "", "status": "error", "error": str(exc)[:180]}
        self._global_cert_cache.set(host, out)
        return out

    def _is_probable_asset(self, content_type: str, url: str) -> bool:
        ct = (content_type or "").lower()
        if any(x in ct for x in ["image/", "font/", "audio/", "video/", "application/octet-stream", "javascript", "text/css"]):
            return True
        return bool(self._re_asset_ext.search((urlsplit(url).path or "").lower()))

    def _extract_sitemap_urls(self, seed: str, seed_host: str) -> List[str]:
        cache_key = f"{seed_host}|{seed.rstrip('/')}"
        cached = self._global_sitemap_cache.get(cache_key)
        if cached is not None:
            return cached
        found: List[str] = []
        for sm_url in [urljoin(seed, p) for p in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"]]:
            try:
                req = Request(sm_url, headers={"User-Agent": "RiskIntelCrawler/3.0"})
                with urlopen(req, timeout=4) as resp:
                    raw = resp.read(600000).decode("utf-8", errors="ignore")
                for node in ElementTree.fromstring(raw).findall(".//{*}loc"):
                    if node.text and self._same_site(seed_host, (urlsplit(node.text.strip()).hostname or "").lower()):
                        found.append(node.text.strip())
            except Exception:
                continue
        dedup: List[str] = []
        seen: Set[str] = set()
        for u in found:
            k = u.rstrip("/")
            if k not in seen:
                seen.add(k)
                dedup.append(u)
        out = dedup[:400]
        self._global_sitemap_cache.set(cache_key, out)
        return out

    def _malware_signals_from_html(self, html: str, page_url: str) -> Dict[str, object]:
        flags: List[str] = []
        score = 0.0
        lowered = html.lower()
        if re.search(r"eval\s*\(", lowered):
            score += 0.12; flags.append("JavaScript eval() usage")
        if "fromcharcode" in lowered:
            score += 0.10; flags.append("String.fromCharCode obfuscation")
        if re.search(r"\batob\s*\(", lowered):
            score += 0.08; flags.append("Base64 decode atob()")
        if re.search(r"\bunescape\s*\(", lowered):
            score += 0.08; flags.append("unescape() obfuscation primitive")
        if re.search(r"document\.write\s*\(", lowered):
            score += 0.05; flags.append("document.write dynamic injection")
        if re.findall(r"[A-Za-z0-9+/]{200,}={0,2}", html):
            score += 0.14; flags.append("Large base64-encoded blob")
        if re.search(r"<iframe[^>]*(display\s*:\s*none|width\s*=\s*[\"']?0|height\s*=\s*[\"']?0)", lowered):
            score += 0.15; flags.append("Hidden iframe behavior")
        if re.search(r"(download=|application/(x-msdownload|octet-stream))", lowered):
            score += 0.18; flags.append("Executable download vector")
        suspicious_downloads = [href for href in self._extract_html_links(html, page_url)
                                  if re.search(r"\.[a-z0-9]{2,5}$", urlsplit(href).path.lower()) and
                                  re.search(r"\.[a-z0-9]{2,5}$", urlsplit(href).path.lower()).group(0) in self.suspicious_file_ext]
        if suspicious_downloads:
            score += min(0.25, 0.09 + len(suspicious_downloads) * 0.03)
            flags.append(f"Suspicious download links: {len(suspicious_downloads)}")

        score = min(1.0, max(0.0, score))
        verdict = "likely_malicious" if score >= 0.62 else ("suspicious" if score >= 0.36 else "no_strong_malware_signal")
        return {"score": round(score, 3), "verdict": verdict, "flags": flags[:10], "suspicious_downloads": suspicious_downloads[:20]}

    def trace_website(
        self,
        website_url: str,
        max_pages: int = 120,
        max_depth: int = 4,
        include_external: bool = False,
        exhaustive: bool = True,
    ) -> Dict[str, object]:
        seed = self._normalize_site_url(website_url)
        seed_host = (urlsplit(seed).hostname or "").lower()
        if not seed_host:
            raise ValueError("Unable to parse website hostname.")

        max_pages = max(1, min(max_pages, 500))
        max_depth = max(0, min(max_depth, 8))

        queue: deque = deque([(seed, 0, None)])
        queued: Set[str] = {seed.rstrip("/")}
        visited: Set[str] = set()
        page_reports: List[Dict[str, object]] = []
        discovered_hosts: Set[str] = set()
        discovered_internal_urls: Set[str] = {seed.rstrip("/")}
        https_hosts_seen: Set[str] = set()

        if exhaustive:
            for sm_url in self._extract_sitemap_urls(seed, seed_host):
                key = sm_url.rstrip("/")
                if key not in discovered_internal_urls:
                    discovered_internal_urls.add(key)
                    if key not in queued and key not in visited:
                        queue.append((sm_url, 0, "sitemap"))
                        queued.add(key)

        while queue and len(page_reports) < max_pages:
            current, depth, parent = queue.popleft()
            canonical = current.rstrip("/")
            if canonical in visited:
                continue
            visited.add(canonical)

            page_result: Dict[str, object] = {
                "url": current, "depth": depth, "parent": parent,
                "status": "error", "status_code": None, "title": "",
                "risk_level": "low", "score": 0, "summary": "",
                "link_counts": {"internal": 0, "external": 0}, "error": None,
            }

            try:
                req = Request(current, headers={"User-Agent": "RiskIntelCrawler/3.0"})
                with urlopen(req, timeout=8) as resp:
                    status_code = int(getattr(resp, "status", resp.getcode()))
                    content_type = str(resp.headers.get("Content-Type", ""))
                    final_url = str(getattr(resp, "url", current))
                    payload = resp.read(1200000)
                final_parts = urlsplit(final_url)
                if final_parts.scheme == "https" and final_parts.hostname:
                    https_hosts_seen.add(final_parts.hostname.lower())
                html = payload.decode("utf-8", errors="ignore")
                page_text = self._html_to_text(html)[:14000]
                title = self._extract_title(html)
                malware = self._malware_signals_from_html(html, final_url)
                is_asset = self._is_probable_asset(content_type, final_url)
                ai = {"risk_level": "low", "score": 0, "summary": "Static asset.", "threat_fingerprint": None} if is_asset else self.analyze(page_text)
                extracted_links = self._extract_html_links(html, current)
                internal_links: List[str] = []
                external_links: List[str] = []
                for link in extracted_links:
                    host = (urlsplit(link).hostname or "").lower()
                    if host:
                        discovered_hosts.add(host)
                    if self._same_site(seed_host, host):
                        internal_links.append(link)
                        discovered_internal_urls.add(link.rstrip("/"))
                    else:
                        external_links.append(link)

                page_result.update({
                    "status": "ok", "status_code": status_code, "final_url": final_url,
                    "content_type": content_type, "is_asset": is_asset, "title": title,
                    "risk_level": ai["risk_level"], "score": ai["score"], "summary": ai["summary"],
                    "malware_score": int(round(float(malware["score"]) * 100)),
                    "malware_verdict": malware["verdict"], "malware_flags": malware["flags"],
                    "suspicious_downloads": malware["suspicious_downloads"],
                    "threat_fingerprint": ai["threat_fingerprint"],
                    "link_counts": {"internal": len(internal_links), "external": len(external_links)},
                    "link_preview": {"internal": internal_links[:12], "external": external_links[:12]},
                })

                if depth < max_depth:
                    for nxt in internal_links:
                        key = nxt.rstrip("/")
                        if key not in visited and key not in queued:
                            queue.append((nxt, depth + 1, current))
                            queued.add(key)
                    if include_external:
                        for nxt in external_links:
                            key = nxt.rstrip("/")
                            if key not in visited and key not in queued:
                                queue.append((nxt, depth + 1, current))
                                queued.add(key)
            except Exception as exc:
                page_result["error"] = str(exc)[:220]

            page_reports.append(page_result)

        ok_pages = [p for p in page_reports if p["status"] == "ok"]
        business_ok_pages = [p for p in ok_pages if not p.get("is_asset")]
        asset_ok_pages = [p for p in ok_pages if p.get("is_asset")]
        failed_pages = [p for p in page_reports if p["status"] != "ok"]
        high_pages = [p for p in business_ok_pages if p["risk_level"] in {"high", "critical"}]
        medium_pages = [p for p in business_ok_pages if p["risk_level"] == "medium"]
        malware_suspicious = [p for p in business_ok_pages if p.get("malware_verdict") in {"suspicious", "likely_malicious"}]
        malware_likely = [p for p in business_ok_pages if p.get("malware_verdict") == "likely_malicious"]
        top_pages = sorted(business_ok_pages, key=lambda x: int(x["score"]), reverse=True)[:8]
        avg_score = int(round(sum(int(p["score"]) for p in business_ok_pages) / max(len(business_ok_pages), 1)))
        highest = int(max((int(p["score"]) for p in business_ok_pages), default=0))
        avg_malware = int(round(sum(int(p.get("malware_score", 0)) for p in business_ok_pages) / max(len(business_ok_pages), 1)))
        highest_malware = int(max((int(p.get("malware_score", 0)) for p in business_ok_pages), default=0))

        overall = ("critical" if highest >= 80 or len(high_pages) >= 3 or len(malware_likely) >= 1
                   else ("high" if highest >= 60 or len(high_pages) >= 1 or len(malware_suspicious) >= 2
                         else ("medium" if avg_score >= 35 or len(medium_pages) >= 2 else "low")))
        coverage = int(round((len(visited) / max(len(discovered_internal_urls), 1)) * 100))
        scam_likelihood = int(min(100, round((avg_score * 0.55) + (len(high_pages) * 6) + (len(medium_pages) * 2) + (highest * 0.12))))
        malware_likelihood = int(min(100, round((avg_malware * 0.65) + (highest_malware * 0.2) + (len(malware_likely) * 15) + (len(malware_suspicious) * 4))))
        crawl_failed = bool(page_reports) and not ok_pages
        crawl_partial = bool(failed_pages) and coverage < 60
        if crawl_failed:
            overall = "medium"
            scam_likelihood = max(scam_likelihood, 35)
            malware_likelihood = max(malware_likelihood, 20)
            final_site_verdict = "suspicious"
        elif crawl_partial and overall == "low":
            overall = "medium"
            scam_likelihood = max(scam_likelihood, 25)
            final_site_verdict = "suspicious"
        else:
            final_site_verdict = ("likely_malicious" if scam_likelihood >= 70 or malware_likelihood >= 65 or overall == "critical"
                                  else ("suspicious" if scam_likelihood >= 45 or malware_likelihood >= 40 or overall in {"high", "medium"} else "likely_safe"))

        recs = []
        if high_pages: recs.append("Block/monitor high-risk pages and enforce user click protection.")
        if malware_likely: recs.append("Malware behavior detected; isolate domain and sandbox artifacts.")
        if malware_suspicious and not malware_likely: recs.append("Suspicious script patterns; perform dynamic analysis before allowing access.")
        if crawl_failed: recs.append("Crawler could not retrieve any pages; treat the scan as incomplete and verify network or host controls.")
        if failed_pages: recs.append("Review failed crawl targets; hidden paths may contain suspicious content.")
        if len(discovered_hosts) > 8: recs.append("High host diversity; investigate redirect/chaining behavior.")
        if coverage < 60: recs.append("Coverage limited; increase max_pages/max_depth for full trace.")
        recs += ["Enable scheduled recrawls for threat drift detection.", "Store crawl snapshots for historical analysis."]

        cert_hosts = sorted(https_hosts_seen)[:40]
        if cert_hosts:
            with ThreadPoolExecutor(max_workers=min(10, len(cert_hosts))) as ex:
                certificates = list(ex.map(self._fetch_certificate, cert_hosts))
        else:
            certificates = []

        return {
            "seed_url": seed, "scope_host": seed_host,
            "pages_crawled": len(page_reports), "pages_ok": len(ok_pages),
            "business_pages_scanned": len(business_ok_pages), "asset_pages_skipped": len(asset_ok_pages),
            "pages_failed": len(failed_pages), "coverage_percent": coverage,
            "risk_level": overall, "average_score": avg_score, "highest_score": highest,
            "high_risk_pages": len(high_pages), "medium_risk_pages": len(medium_pages),
            "malware_suspicious_pages": len(malware_suspicious), "malware_likely_pages": len(malware_likely),
            "average_malware_score": avg_malware, "highest_malware_score": highest_malware,
            "scam_likelihood": scam_likelihood, "malware_likelihood": malware_likelihood,
            "site_verdict": final_site_verdict,
            "discovered_host_count": len(discovered_hosts), "discovered_internal_urls": len(discovered_internal_urls),
            "certificates": certificates, "certificate_hosts_scanned": len(certificates),
            "certificate_hosts_ok": sum(1 for c in certificates if c.get("status") == "ok"),
            "top_risky_pages": [
                {"url": p["url"], "title": p.get("title", ""), "score": p["score"], "risk_level": p["risk_level"],
                 "malware_score": p.get("malware_score", 0), "malware_verdict": p.get("malware_verdict", "no_strong_malware_signal"),
                 "summary": p["summary"]} for p in top_pages
            ],
            "pages": page_reports,
            "recommendations": recs[:6],
        }


_riskintel_original_trace_website = RiskEngine.trace_website


def _patched_trace_website(
    self: RiskEngine,
    seed_url: str,
    max_pages: int = 80,
    max_depth: int = 3,
    include_external: bool = False,
    exhaustive: bool = True,
) -> Dict[str, object]:
    result = _riskintel_original_trace_website(
        self,
        seed_url,
        max_pages=max_pages,
        max_depth=max_depth,
        include_external=include_external,
        exhaustive=exhaustive,
    )
    if not isinstance(result, dict):
        return result

    pages_ok = int(result.get("pages_ok") or 0)
    pages_failed = int(result.get("pages_failed") or 0)
    coverage = int(result.get("coverage_percent") or 0)
    recommendations = list(result.get("recommendations") or [])

    if pages_failed and pages_ok == 0:
        result["risk_level"] = "medium"
        result["site_verdict"] = "suspicious"
        result["scam_likelihood"] = max(int(result.get("scam_likelihood") or 0), 35)
        result["malware_likelihood"] = max(int(result.get("malware_likelihood") or 0), 20)
        message = "Crawler could not retrieve any pages; treat the scan as incomplete and verify network or host controls."
        if message not in recommendations:
            recommendations.insert(0, message)
    elif pages_failed and coverage < 60 and str(result.get("risk_level") or "low") == "low":
        result["risk_level"] = "medium"
        result["site_verdict"] = "suspicious"
        result["scam_likelihood"] = max(int(result.get("scam_likelihood") or 0), 25)

    result["recommendations"] = recommendations[:6]
    return result


RiskEngine.trace_website = _patched_trace_website


FRAUD_TEMPLATES: Dict[str, List[str]] = {
    "romance_fraud": ["i love you", "send money", "emergency abroad", "military deployment", "offshore account"],
    "lottery_fraud": ["you have won", "claim your prize", "lottery winner", "transfer fee required"],
    "phishing_credential_theft": ["verify your account", "click here to login", "your password has expired", "confirm your identity"],
    "advance_fee_fraud": ["million dollars", "inheritance", "need your help to transfer", "percentage commission"],
    "tech_support_scam": ["your computer is infected", "call microsoft", "remote access", "your ip was hacked"],
}


def _patched_whois_domain_age_profile(self: RiskEngine, hostname: str) -> Dict[str, object]:
    host = (hostname or "").strip().lower()
    if not host:
        return {"score": 0.0, "flags": [], "age_days": None, "status": "unavailable"}
    cached = self._global_whois_cache.get(host)
    if cached is not None:
        return cached

    root = self._effective_domain(host)
    age_days: Optional[int] = None
    creation_date = None
    registrar = None
    expiration_date = None
    status = "unavailable"
    flags: List[str] = []
    score = 0.0

    if python_whois is not None:
        try:
            record = python_whois.whois(root)
            creation_date = getattr(record, "creation_date", None)
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            expiration_date = getattr(record, "expiration_date", None)
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            registrar = getattr(record, "registrar", None)
            if creation_date:
                age_days = max(0, (datetime.utcnow() - creation_date.replace(tzinfo=None) if getattr(creation_date, "tzinfo", None) else datetime.utcnow() - creation_date).days)
                status = "ok"
        except Exception as exc:
            logger.warning("WHOIS lookup failed for %s: %s", root, exc)

    if age_days is None:
        try:
            with httpx.Client(timeout=8.0, follow_redirects=True) as client:
                response = client.get(f"https://rdap.org/domain/{root}", headers={"Accept": "application/rdap+json", "User-Agent": "RiskIntel/3.0"})
            if response.status_code == 200:
                data = response.json()
                for event in data.get("events", []):
                    if event.get("eventAction") == "registration" and event.get("eventDate"):
                        raw = event["eventDate"].replace("Z", "+00:00")
                        creation_date = datetime.fromisoformat(raw)
                        age_days = max(0, (datetime.utcnow() - creation_date.replace(tzinfo=None)).days)
                        status = "ok"
                        break
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
        "status": status,
        "creation_date": creation_date.isoformat() if creation_date else None,
        "registrar": registrar,
        "expiration_date": expiration_date.isoformat() if hasattr(expiration_date, "isoformat") else None,
        "error": None if age_days is not None else "WHOIS unavailable",
    }
    self._global_whois_cache.set(host, out)
    return out


def _patched_domain_reputation_profile(self: RiskEngine, hostname: str) -> Dict[str, object]:
    base = RiskEngine._original_domain_reputation_profile(self, hostname)
    host = (hostname or "").strip().lower()
    if not host:
        return base
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip() or os.getenv("RISKINTEL_VT_API_KEY", "").strip()
    otx_key = os.getenv("OTX_API_KEY", "").strip() or os.getenv("RISKINTEL_OTX_API_KEY", "").strip()
    source_hits: List[Dict[str, object]] = []
    total_malicious = 0
    try:
        if vt_key:
            with httpx.Client(timeout=6.0, follow_redirects=True) as client:
                response = client.get(
                    f"https://www.virustotal.com/api/v3/domains/{host}",
                    headers={"x-apikey": vt_key, "User-Agent": "RiskIntel/3.0"},
                )
            if response.status_code == 200:
                stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
                total_malicious += malicious
                source_hits.append({"source": "virustotal", "malicious": malicious})
        if otx_key:
            with httpx.Client(timeout=6.0, follow_redirects=True) as client:
                response = client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{host}/general",
                    headers={"X-OTX-API-KEY": otx_key, "User-Agent": "RiskIntel/3.0"},
                )
            if response.status_code == 200:
                count = int(response.json().get("pulse_info", {}).get("count", 0))
                total_malicious += count
                source_hits.append({"source": "alienvault_otx", "malicious": count})
    except Exception as exc:
        logger.warning("Domain reputation lookup failed for %s: %s", host, exc)

    if source_hits:
        category = "malicious" if total_malicious >= 3 else ("suspicious" if total_malicious > 0 else "clean")
        flags = list(base.get("flags", []))
        if total_malicious > 0:
            flags.append(f"Feed hits detected: {total_malicious}")
        return {
            **base,
            "score": round(min(1.0, float(base.get("score", 0.0)) + min(0.4, total_malicious * 0.08)), 3),
            "flags": flags[:8],
            "category": category,
            "sources": source_hits,
            "total_malicious_hits": total_malicious,
        }
    return {**base, "sources": [], "total_malicious_hits": 0}


def _patched_intent_profile(self: RiskEngine, text: str) -> Dict[str, object]:
    norm = self._normalize(text)
    if len(norm.strip()) < 10:
        return {"top_intents": [], "max_similarity": 0.0}
    query_vector = self._vectorize(norm)
    intent_scores = []
    for intent, templates in FRAUD_TEMPLATES.items():
        similarities = [self._cosine(query_vector, self._vectorize(self._normalize(template))) for template in templates]
        best = max(similarities) if similarities else 0.0
        intent_scores.append({"intent": intent, "similarity": round(best * 100, 1)})
    top_intents = sorted(intent_scores, key=lambda item: item["similarity"], reverse=True)[:4]
    return {"top_intents": top_intents, "max_similarity": top_intents[0]["similarity"] if top_intents else 0.0}


RiskEngine._original_domain_reputation_profile = RiskEngine._domain_reputation_profile
RiskEngine._whois_domain_age_profile = _patched_whois_domain_age_profile
RiskEngine._domain_reputation_profile = _patched_domain_reputation_profile
RiskEngine._intent_profile = _patched_intent_profile


import asyncio
import hashlib
import ipaddress
import re
import socket
import ssl
import time
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from math import exp, sqrt
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlsplit
from urllib.request import Request, urlopen
from xml.etree import ElementTree
from datetime import datetime
import functools
import threading


# ─────────────────────────────────────────────
# TTL-aware thread-safe in-process cache
# ─────────────────────────────────────────────
class TTLCache:
    """Thread-safe LRU-style cache with per-entry TTL."""

    def __init__(self, maxsize: int = 4096, ttl: float = 3600.0) -> None:
        self._store: Dict[str, Tuple[Any, float]] = {}
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
                # Evict oldest 10%
                oldest = sorted(self._store.items(), key=lambda x: x[1][1])[: self._maxsize // 10]
                for k, _ in oldest:
                    del self._store[k]
            self._store[key] = (value, time.monotonic())

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        return len(self._store)


@dataclass(frozen=True)
class Signal:
    name: str
    score: float
    detail: str


# ─────────────────────────────────────────────
# Extended threat pattern library
# ─────────────────────────────────────────────
RULE_SETS: Dict[str, Dict[str, float]] = {
    "credential_theft": {
        r"\bverify (your )?(account|identity)\b": 0.18,
        r"\breset (your )?password\b": 0.16,
        r"\blogin immediately\b": 0.12,
        r"\bsecurity alert\b": 0.10,
        r"\baccount (suspended|locked|disabled)\b": 0.17,
        r"\bconfirm (your )?(credentials|login|email)\b": 0.15,
    },
    "financial_fraud": {
        r"\bwire transfer\b": 0.17,
        r"\bgift card\b": 0.18,
        r"\bcrypto( wallet| payment)?\b": 0.13,
        r"\bbank details\b": 0.14,
        r"\bpayment failed\b": 0.10,
        r"\bsend (the )?funds?\b": 0.16,
        r"\bbitcoin\b": 0.12,
        r"\bwestern union\b": 0.19,
        r"\bmoney gram\b": 0.18,
        r"\binvoice (overdue|past due)\b": 0.13,
    },
    "urgency_pressure": {
        r"\bwithin (\d+ )?(minutes?|hours?)\b": 0.10,
        r"\bact now\b": 0.14,
        r"\bfinal warning\b": 0.15,
        r"\bimmediate action required\b": 0.18,
        r"\bexpires? (today|tonight|in \d+)\b": 0.12,
        r"\blast chance\b": 0.13,
        r"\btime.sensitive\b": 0.11,
    },
    "social_engineering": {
        r"\bthis is (the )?ceo\b": 0.15,
        r"\bkeep this confidential\b": 0.17,
        r"\bdo not tell anyone\b": 0.16,
        r"\btrusted partner\b": 0.08,
        r"\bpersonal favor\b": 0.11,
        r"\bbetween (us|you and me)\b": 0.10,
        r"\bdon'?t (mention|share|discuss) this\b": 0.14,
    },
    "business_email_compromise": {
        r"\bkindly process\b": 0.13,
        r"\bapproved by management\b": 0.10,
        r"\bout of office\b": 0.08,
        r"\bvendor update\b": 0.12,
        r"\bnew (banking|payment) (details?|instructions?)\b": 0.19,
        r"\bchange (of )?account (details?|number)\b": 0.17,
        r"\bauthorized (by|from) (the )?(cfo|ceo|management)\b": 0.15,
    },
    "malware_delivery": {
        r"\bopen (the |this )?(attached?|file|document)\b": 0.13,
        r"\bdownload (and )?(install|run|execute)\b": 0.16,
        r"\benable (macro|content)\b": 0.18,
        r"\bclick (to |here to )?(view|access|download)\b": 0.12,
        r"\bupdate (required|needed|now)\b": 0.11,
    },
    "romance_scam": {
        r"\bsend (me )?money\b": 0.17,
        r"\bi (love|miss|need) you\b.*\b(send|transfer|help)\b": 0.16,
        r"\bstranded (abroad|overseas|at the airport)\b": 0.19,
        r"\bmedical emergency\b.*\bmoney\b": 0.18,
    },
    "lottery_scam": {
        r"\byou (have |'ve )?(won|been selected)\b": 0.16,
        r"\bclaim (your )?(prize|winnings?|reward)\b": 0.17,
        r"\blottery (winner|jackpot)\b": 0.18,
        r"\bunclaimed (funds?|prize)\b": 0.15,
    },
}

INTENT_PROTOTYPES: Dict[str, str] = {
    "phishing_credential_theft": "Your account is suspended. Verify identity and password now.",
    "invoice_or_wire_fraud": "Urgent transfer required to secure corporate payment channel.",
    "gift_card_scam": "Purchase gift cards immediately and send the claim codes.",
    "malicious_link_delivery": "Security warning: click link to avoid permanent account lock.",
    "executive_impersonation": "Confidential request from executive: process payment discreetly.",
    "bank_detail_tampering": "Update bank details now to prevent payroll disruption.",
    "malware_download": "Enable macros to view important document. Download and install update.",
    "romance_fraud": "I love you and need your help. Send money urgently.",
    "lottery_fraud": "You have won a prize. Claim your lottery winnings now.",
    "advance_fee_fraud": "Transfer fee required to release inheritance funds to your account.",
}


class RiskEngine:
    """
    Hybrid fraud detection engine — deterministic rules + NLP cosine similarity.
    v3: async-ready, parallel link tracing, TTL caches, extended rule library.
    """

    _global_link_cache = TTLCache(maxsize=8192, ttl=1800.0)
    _global_whois_cache = TTLCache(maxsize=2048, ttl=7200.0)
    _global_domain_cache = TTLCache(maxsize=4096, ttl=3600.0)
    _global_cert_cache = TTLCache(maxsize=1024, ttl=3600.0)
    _global_sitemap_cache = TTLCache(maxsize=512, ttl=1800.0)

    def __init__(self) -> None:
        self.rule_sets = RULE_SETS
        self.intent_prototypes = INTENT_PROTOTYPES
        self.prototype_vectors = {
            intent:         self._vectorize(self._normalize(text))
            for intent, text in self.intent_prototypes.items()
        }
        self.high_risk_terms = {
            "password", "otp", "bank", "transfer", "wallet", "payment", "urgent",
            "verify", "confidential", "gift", "card", "crypto", "pin", "credential",
            "click", "link", "bitcoin", "invoice", "wire", "lottery", "prize",
            "winner", "inheritance", "claim", "fund", "release",
        }
        self.shortener_domains = {
            "bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd", "goo.gl",
            "ow.ly", "shorturl.at", "cutt.ly", "rebrand.ly", "tiny.cc",
            "snip.ly", "bl.ink", "short.io",
        }
        self.suspicious_tlds = {
            "zip", "mov", "top", "gq", "tk", "work", "click", "cam", "rest",
            "country", "stream", "xyz", "pw", "cc", "biz", "info",
        }
        self.sensitive_query_keys = {"url", "redirect", "next", "target", "dest", "continue", "return", "goto"}
        self.suspicious_file_ext = {".exe", ".msi", ".bat", ".cmd", ".scr", ".js", ".vbs", ".jar", ".ps1", ".hta", ".pif"}
        self.link_risk_terms = {"login", "verify", "secure", "wallet", "bank", "password", "update", "payment", "signin", "account"}
        self.reputation_risky_terms = {
            "secure", "verify", "update", "wallet", "login", "account",
            "signin", "support", "billing", "payment", "confirm", "auth",
        }
        self.known_brands = {
            "google", "microsoft", "apple", "amazon", "paypal", "netflix",
            "facebook", "instagram", "whatsapp", "linkedin", "github",
            "dropbox", "twitter", "x", "bankofamerica", "chase", "wellsfargo",
            "citibank", "outlook", "office365", "youtube", "tiktok", "coinbase",
            "binance", "kraken", "robinhood", "stripe", "shopify",
        }
        self.brand_text_terms = {
            "google", "microsoft", "apple", "amazon", "paypal", "netflix",
            "facebook", "instagram", "linkedin", "github", "outlook", "office365",
            "bank of america", "wells fargo", "citi", "chase bank", "youtube",
            "tiktok", "coinbase", "binance",
        }
        self.typo_homograph_map = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})

        # Pre-compiled regex patterns
        self._re_url_scheme = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
        self._re_link_pattern = re.compile(r"(?:(?:https?|ftp)://|www\.)[^\s<>'\"()]+", flags=re.IGNORECASE)
        self._re_asset_ext = re.compile(r"\.(png|jpg|jpeg|gif|svg|ico|webp|woff2?|ttf|eot|css|js|map|mp4|mp3|pdf)$")
        self._re_title = re.compile(r"<title[^>]*>(.*?)</title>", flags=re.IGNORECASE | re.DOTALL)
        self._re_href = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', flags=re.IGNORECASE)
        self._re_tag_strip = re.compile(r"<[^>]+>")
        self._re_script_strip = re.compile(r"<script[\s\S]*?</script>", flags=re.IGNORECASE)
        self._re_style_strip = re.compile(r"<style[\s\S]*?</style>", flags=re.IGNORECASE)
        self._re_multi_ws = re.compile(r"\s+")
        self._re_obfuscated_link = re.compile(r"hxxps?://|\[\.\]|\(\.\)")
        self._re_repeated_chars = re.compile(r"(.)\1{5,}")
        self._re_currency = re.compile(r"\$\d+|\b\d{2,}(?:,\d{3})*(?:\.\d+)?\b")
        self._re_caps = re.compile(r"\b[A-Z]{3,}\b")
        self._re_exec_ext = re.compile(r"\.[a-zA-Z0-9]{2,5}$")
        self._re_whois_date = re.compile(r"(20\d{2})[-/](\d{1,2})[-/](\d{1,2})")

        # Compile rule sets once
        self._rule_sets_compiled: Dict[str, List[Tuple[re.Pattern, float, str]]] = {}
        for category, patterns in self.rule_sets.items():
            self._rule_sets_compiled[category] = [
                (re.compile(pat, re.IGNORECASE), weight, pat)
                for pat, weight in patterns.items()
            ]

        # Thread pool for parallel I/O (link tracing, cert checks, WHOIS)
        self._executor = ThreadPoolExecutor(max_workers=20, thread_name_prefix="riskintel")
        
    # ──────────────────────────────────────────
    # Core NLP helpers
    # ──────────────────────────────────────────
    def _normalize(self, text: str) -> str:
        return self._re_multi_ws.sub(" ", text.strip().lower())

    def _deobfuscate_links_text(self, text: str) -> str:
        return (
            text.replace("[.]", ".").replace("(.)", ".")
            .replace("hxxp://", "http://").replace("hxxps://", "https://")
        )

    def _tokenize(self, text: str) -> List[str]:
        return re.findall(r"[a-zA-Z0-9']+", text)

    def _vectorize(self, text: str) -> Counter:
        tokens = self._tokenize(text)
        if len(tokens) < 2:
            return Counter(tokens)
        bigrams = [f"{tokens[i]}_{tokens[i+1]}" for i in range(len(tokens) - 1)]
        return Counter(tokens + bigrams)

    def _cosine(self, a: Counter, b: Counter) -> float:
        if not a or not b:
            return 0.0
        dot = sum(a[k] * b.get(k, 0) for k in a)
        norm_a = sqrt(sum(v * v for v in a.values()))
        norm_b = sqrt(sum(v * v for v in b.values()))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def _extract_links(self, text: str) -> List[str]:
        candidate_text = self._deobfuscate_links_text(text)
        links = self._re_link_pattern.findall(candidate_text)
        seen: Set[str] = set()
        unique: List[str] = []
        for link in links:
            normalized = link.strip(".,);]}>\"'")
            low = normalized.lower()
            if normalized and low not in seen:
                seen.add(low)
                unique.append(normalized)
        return unique

    @staticmethod
    def _effective_domain(hostname: str) -> str:
        parts = [p for p in hostname.split(".") if p]
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname

    @staticmethod
    def _sld(hostname: str) -> str:
        parts = [p for p in hostname.split(".") if p]
        return parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")

    @staticmethod
    def _levenshtein(a: str, b: str) -> int:
        if a == b:
            return 0
        if not a:
            return len(b)
        if not b:
            return len(a)
        if len(a) < len(b):
            a, b = b, a
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, start=1):
            cur = [i]
            for j, cb in enumerate(b, start=1):
                cur.append(min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + (0 if ca == cb else 1)))
            prev = cur
        return prev[-1]

    # ──────────────────────────────────────────
    # Domain intelligence (with global TTL caches)
    # ──────────────────────────────────────────
    def _domain_reputation_profile(self, hostname: str) -> Dict[str, object]:
        host = (hostname or "").strip().lower()
        if not host:
            return {"score": 0.0, "flags": [], "category": "unknown"}
        cached = self._global_domain_cache.get(host)
        if cached is not None:
            return cached

        score = 0.0
        flags: List[str] = []
        sld = self._sld(host)
        digits = sum(ch.isdigit() for ch in sld)
        hyphens = sld.count("-")
        alpha = sum(ch.isalpha() for ch in sld)
        entropy_like = len(set(sld)) / max(len(sld), 1)
        risky_term_hits = [term for term in self.reputation_risky_terms if term in host]
        tld = host.rsplit(".", 1)[-1] if "." in host else ""

        if digits >= 3:
            score += 0.07; flags.append("Heavy numeric usage in domain")
        if hyphens >= 2:
            score += 0.08; flags.append("Multiple hyphens in domain")
        if len(sld) >= 22:
            score += 0.08; flags.append("Very long second-level domain")
        if entropy_like > 0.82 and len(sld) >= 10 and alpha >= 6:
            score += 0.06; flags.append("High-randomness domain label")
        if risky_term_hits:
            score += min(0.15, 0.04 * len(risky_term_hits))
            flags.append(f"Risky terms in domain: {', '.join(sorted(set(risky_term_hits)))}")
        if tld in self.suspicious_tlds:
            score += 0.10; flags.append(f"Suspicious TLD .{tld}")

        category = "poor" if score >= 0.45 else ("questionable" if score >= 0.25 else "neutral")
        out = {"score": round(min(1.0, score), 3), "flags": flags[:8], "category": category}
        self._global_domain_cache.set(host, out)
        return out

    def _brand_impersonation_profile(self, text: str, hostname: str) -> Dict[str, object]:
        norm = self._normalize(text)
        host = (hostname or "").lower()
        hits = [b for b in self.brand_text_terms if b in norm]
        if not hits:
            return {"score": 0.0, "flags": [], "brands": []}
        effective = self._effective_domain(host)
        flags: List[str] = []
        score = 0.0
        brands: List[str] = []
        for b in hits:
            token = re.sub(r"[^a-z0-9]", "", b.lower())
            if not token:
                continue
            brands.append(b)
            if token not in effective:
                score += 0.07
                flags.append(f"Brand '{b}' mismatches destination domain")
        if len(set(brands)) >= 2:
            score += 0.05; flags.append("Multiple brand references")
        return {"score": round(min(0.35, score), 3), "flags": flags[:8], "brands": sorted(set(brands))[:8]}

    def _typosquat_profile(self, hostname: str) -> Dict[str, object]:
        host = (hostname or "").strip().lower()
        if not host:
            return {"score": 0.0, "flags": [], "closest_brand": None}
        sld = self._sld(host)
        normalized = sld.translate(self.typo_homograph_map)
        if len(normalized) < 3:
            return {"score": 0.0, "flags": [], "closest_brand": None}

        best_brand: Optional[str] = None
        best_dist = 99
        for brand in self.known_brands:
            dist = self._levenshtein(normalized, brand)
            if dist < best_dist:
                best_dist = dist
                best_brand = brand

        score = 0.0
        flags: List[str] = []
        if best_brand and normalized != best_brand:
            if best_dist == 1:
                score += 0.26; flags.append(f"Likely typosquat of '{best_brand}' (edit distance 1)")
            elif best_dist == 2 and len(best_brand) >= 6:
                score += 0.17; flags.append(f"Possible typosquat of '{best_brand}' (edit distance 2)")
        if best_brand and best_brand in normalized and normalized != best_brand:
            extra = normalized.replace(best_brand, "")
            if len(extra) >= 3:
                score += 0.09; flags.append(f"Brand '{best_brand}' embedded with deceptive token")
        return {"score": round(min(0.4, score), 3), "flags": flags[:8], "closest_brand": best_brand}

    def _whois_domain_age_profile(self, hostname: str) -> Dict[str, object]:
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
        status = "unavailable"
        rdap_url = f"https://rdap.org/domain/{root}"
        try:
            req = Request(rdap_url, headers={"User-Agent": "RiskIntel/3.0", "Accept": "application/rdap+json"})
            with urlopen(req, timeout=2.5) as resp:
                payload = resp.read(240000).decode("utf-8", errors="ignore")
            m = self._re_whois_date.search(payload)
            if m:
                year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
                created = datetime(year=year, month=max(1, min(month, 12)), day=max(1, min(day, 28)))
                age_days = max(0, (datetime.utcnow() - created).days)
                status = "ok"
        except Exception:
            status = "unavailable"

        if age_days is not None:
            if age_days < 30:
                score += 0.23; flags.append("Very new domain (<30 days)")
            elif age_days < 90:
                score += 0.16; flags.append("Recently registered (<90 days)")
            elif age_days < 180:
                score += 0.10; flags.append("Young domain (<180 days)")

        out = {"score": round(min(0.3, score), 3), "flags": flags, "age_days": age_days, "status": status}
        self._global_whois_cache.set(host, out)
        return out

    # ──────────────────────────────────────────
    # Link tracing (parallel via thread pool)
    # ──────────────────────────────────────────
    def _trace_single_link(self, raw_link: str) -> Dict[str, object]:
        key = raw_link.strip().lower()
        cached = self._global_link_cache.get(key)
        if cached is not None:
            return cached

        working = raw_link if self._re_url_scheme.match(raw_link) else f"http://{raw_link}"
        parsed = urlsplit(working)
        hostname = (parsed.hostname or "").strip().lower()
        path = parsed.path or ""
        query = parsed.query or ""

        score = 0.0
        flags: List[str] = []

        if parsed.scheme == "http":
            score += 0.10; flags.append("Unencrypted HTTP scheme")
        if "@" in parsed.netloc:
            score += 0.15; flags.append("Credentials in URL (user-info)")
        if hostname in self.shortener_domains:
            score += 0.16; flags.append("Known URL shortener")
        if hostname.startswith("xn--") or ".xn--" in hostname:
            score += 0.12; flags.append("Punycode/IDN domain spoofing risk")
        if any(ord(ch) > 127 for ch in hostname):
            score += 0.10; flags.append("Non-ASCII domain characters")

        subdomain_depth = max(0, len(hostname.split(".")) - 2)
        if subdomain_depth >= 3:
            score += 0.08; flags.append("Deep subdomain chain")
        if len(working) > 140:
            score += 0.08; flags.append("Excessive URL length")
        if parsed.port and parsed.port not in {80, 443}:
            score += 0.08; flags.append(f"Non-standard port {parsed.port}")

        last_dot = hostname.rfind(".")
        tld = hostname[last_dot + 1:] if last_dot > -1 else ""
        if tld in self.suspicious_tlds:
            score += 0.14; flags.append(f"Suspicious TLD .{tld}")

        lower_full = f"{hostname}{path}?{query}".lower()
        keyword_hits = [k for k in self.link_risk_terms if k in lower_full]
        if keyword_hits:
            score += min(0.12, 0.03 * len(keyword_hits))
            flags.append(f"Risk keywords in URL: {', '.join(sorted(set(keyword_hits)))}")

        ext_match = self._re_exec_ext.search(path.lower())
        if ext_match and ext_match.group(0) in self.suspicious_file_ext:
            score += 0.20; flags.append(f"Executable/script extension {ext_match.group(0)}")

        encoded_ratio = working.count("%") / max(len(working), 1)
        if encoded_ratio > 0.03 or working.count("%") >= 4:
            score += 0.07; flags.append("Heavy URL percent-encoding")

        query_map = parse_qs(query, keep_blank_values=True)
        redirect_keys = [k for k in query_map if k.lower() in self.sensitive_query_keys]
        if redirect_keys:
            score += 0.12; flags.append(f"Open redirect parameters: {', '.join(sorted(redirect_keys))}")

        ip_label = ip_type = None
        if hostname:
            try:
                ip_obj = ipaddress.ip_address(hostname)
                ip_label = str(ip_obj)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    score += 0.10; ip_type = "private/local"; flags.append("Private/local IP host")
                else:
                    score += 0.07; ip_type = "public"; flags.append("Direct IP instead of domain")
            except ValueError:
                pass

        reputation = self._domain_reputation_profile(hostname)
        typo = self._typosquat_profile(hostname)
        whois_age = self._whois_domain_age_profile(hostname)
        score += min(0.18, float(reputation.get("score", 0.0)) * 0.7)
        flags.extend(list(reputation.get("flags", []))[:2])
        score += min(0.20, float(typo.get("score", 0.0)) * 0.9)
        flags.extend(list(typo.get("flags", []))[:2])
        score += min(0.12, float(whois_age.get("score", 0.0)) * 0.8)
        flags.extend(list(whois_age.get("flags", []))[:1])

        score = min(1.0, max(0.0, score))
        verdict = "critical" if score >= 0.65 else ("high" if score >= 0.45 else ("medium" if score >= 0.25 else "low"))

        out = {
            "raw": raw_link,
            "normalized": working,
            "scheme": parsed.scheme,
            "host": hostname,
            "port": parsed.port,
            "path": path,
            "query_keys": sorted(query_map.keys()),
            "ip": ip_label,
            "ip_type": ip_type,
            "score": round(score, 3),
            "verdict": verdict,
            "flags": self._dedupe_ordered(flags)[:12],
            "domain_intelligence": {
                "domain_reputation": reputation,
                "typosquatting": typo,
                "whois_age": whois_age,
            },
        }
        self._global_link_cache.set(key, out)
        return out

    def trace_links(self, text: str) -> Dict[str, object]:
        links = self._extract_links(text)
        if not links:
            return {"total_links": 0, "high_risk_links": 0, "medium_risk_links": 0, "aggregate_score": 0.0, "links": []}

        # Parallel link tracing
        futures = {self._executor.submit(self._trace_single_link, link): link for link in links}
        traced: List[Dict[str, object]] = []
        for future in as_completed(futures):
            try:
                traced.append(future.result(timeout=6.0))
            except Exception:
                pass

        high_count = sum(1 for x in traced if x["verdict"] in {"high", "critical"})
        med_count = sum(1 for x in traced if x["verdict"] == "medium")
        total_score = round(sum(float(x["score"]) for x in traced), 3)
        return {
            "total_links": len(traced),
            "high_risk_links": high_count,
            "medium_risk_links": med_count,
            "aggregate_score": total_score,
            "links": sorted(traced, key=lambda x: float(x["score"]), reverse=True),
        }

    # ──────────────────────────────────────────
    # Entity extraction
    # ──────────────────────────────────────────
    def _extract_entities(self, text: str) -> Dict[str, object]:
        emails = re.findall(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", text)
        phones = re.findall(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)\d{3,4}[-.\s]?\d{3,4}\b", text)
        ipv4s = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        crypto_wallets = re.findall(r"\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", text)
        long_numeric_ids = re.findall(r"\b\d{10,18}\b", text)
        cvv_pattern = re.findall(r"\b\d{3,4}\b", text)  # light card CVV indicator
        entities = {
            "emails": sorted(set(emails))[:12],
            "phones": sorted(set(phones))[:12],
            "ipv4s": sorted(set(ipv4s))[:12],
            "crypto_wallets": sorted(set(crypto_wallets))[:12],
            "numeric_ids": sorted(set(long_numeric_ids))[:12],
        }
        entities["counts"] = {k: len(v) for k, v in entities.items() if isinstance(v, list)}
        entities["total"] = sum(entities["counts"].values())
        return entities

    # ──────────────────────────────────────────
    # Intent profiling
    # ──────────────────────────────────────────
    def _intent_profile(self, text: str) -> Dict[str, object]:
        norm = self._normalize(text)
        query_vector =         self._vectorize(norm)
        intent_scores = [
            {"intent": intent, "similarity": round(self._cosine(query_vector, proto), 3)}
            for intent, proto in self.prototype_vectors.items()
        ]
        top_intents = sorted(intent_scores, key=lambda x: x["similarity"], reverse=True)[:3]
        return {"top_intents": top_intents, "max_similarity": top_intents[0]["similarity"] if top_intents else 0.0}

    # ──────────────────────────────────────────
    # Signal extraction
    # ──────────────────────────────────────────
    def _extract_rule_signals(self, text: str) -> List[Signal]:
        norm = self._normalize(text)
        signals: List[Signal] = []
        for category, patterns in self._rule_sets_compiled.items():
            cat_hits: List[Tuple[str, float]] = []
            for compiled, weight, raw_pattern in patterns:
                if compiled.search(norm):
                    cat_hits.append((raw_pattern, weight))
            if not cat_hits:
                continue
            cat_hits.sort(key=lambda x: x[1], reverse=True)
            cat_score = sum(w * (1.0 if i == 0 else (0.62 if i == 1 else 0.30)) for i, (_, w) in enumerate(cat_hits))
            cat_score = min(0.28, cat_score)
            signals.append(Signal(
                name=f"rule::{category}",
                score=cat_score,
                detail=f"Matched {len(cat_hits)} pattern(s) in {category}; strongest '{cat_hits[0][0]}'.",
            ))
        return signals

    def _nlp_signals(
        self,
        text: str,
        extracted_links: Optional[List[str]] = None,
        intent_profile: Optional[Dict[str, object]] = None,
    ) -> List[Signal]:
        norm = self._normalize(text)
        words = self._tokenize(norm)
        total_words = max(len(words), 1)
        high_risk_hits = sum(1 for w in words if w in self.high_risk_terms)
        risk_density = high_risk_hits / total_words
        exclamations = text.count("!")
        caps_words = self._re_caps.findall(text)
        link_hits = len(extracted_links) if extracted_links is not None else len(self._extract_links(text))
        currency_hits = len(self._re_currency.findall(text))
        obfuscated_hits = len(self._re_obfuscated_link.findall(text.lower()))
        profile = intent_profile if intent_profile is not None else self._intent_profile(text)
        sim = float(profile["max_similarity"])

        signals: List[Signal] = []
        if risk_density > 0.08:
            signals.append(Signal("nlp::risk_term_density", min(0.18, risk_density * 1.4), f"High-risk term density {risk_density:.2f}"))
        if sim > 0.25:
            signals.append(Signal("nlp::intent_similarity", min(0.25, sim * 0.55), f"Fraud intent similarity {sim:.2f}"))
        if exclamations >= 3:
            signals.append(Signal("nlp::pressure_tone", min(0.08, exclamations * 0.02), f"{exclamations} exclamation marks"))
        if len(caps_words) >= 2:
            signals.append(Signal("nlp::aggressive_caps", 0.07, "Multiple ALL-CAPS tokens"))
        if link_hits > 0:
            signals.append(Signal("nlp::external_link", min(0.10, 0.05 + 0.02 * link_hits), f"{link_hits} external link(s)"))
        if currency_hits > 0:
            signals.append(Signal("nlp::money_reference", min(0.09, 0.03 + currency_hits * 0.02), f"{currency_hits} currency indicator(s)"))
        if obfuscated_hits > 0:
            signals.append(Signal("nlp::link_obfuscation", min(0.16, 0.06 + obfuscated_hits * 0.03), f"{obfuscated_hits} obfuscated link(s)"))
        if self._re_repeated_chars.search(text):
            signals.append(Signal("nlp::pattern_anomaly", 0.06, "Repeated-character pattern anomaly"))
        return signals

    # ──────────────────────────────────────────
    # Score synthesis
    # ──────────────────────────────────────────
    def _score_from_evidence(self, signals: List[Signal], link_analysis: Dict[str, object]) -> Dict[str, float]:
        rule_sum = nlp_sum = intel_sum = 0.0
        signal_names = [s.name for s in signals]
        for s in signals:
            if s.name.startswith("rule::"):
                rule_sum += s.score
            elif s.name.startswith("nlp::"):
                nlp_sum += s.score
            else:
                intel_sum += s.score

        rule_capped = min(0.56, rule_sum)
        nlp_capped = min(0.34, nlp_sum)
        intel_capped = min(0.24, intel_sum)
        raw_capped = rule_capped + nlp_capped + intel_capped

        fusion_boost = 0.0
        if rule_capped > 0.25 and nlp_capped > 0.14:
            fusion_boost += 0.06
        if int(link_analysis.get("high_risk_links", 0)) > 0 and (
            "nlp::link_obfuscation" in signal_names or intel_capped > 0.08
        ):
            fusion_boost += 0.05
        if "rule::financial_fraud" in signal_names and "rule::social_engineering" in signal_names:
            fusion_boost += 0.04
        if "nlp::intent_similarity" in signal_names and nlp_capped > 0.18:
            fusion_boost += 0.03

        blended = min(1.0, raw_capped + fusion_boost)
        calibrated = min(0.96, max(0.0, 1.0 - exp(-1.45 * blended)))
        return {
            "rule": round(rule_capped, 3),
            "nlp": round(nlp_capped, 3),
            "intel": round(intel_capped, 3),
            "fusion": round(fusion_boost, 3),
            "raw": round(blended, 3),
            "calibrated": round(calibrated, 3),
        }

    def _dimension_scores(self, signals: List[Signal], link_analysis: Dict, entities: Dict) -> Dict[str, int]:
        dims = {k: 0.0 for k in ("credential_theft", "financial_fraud", "social_engineering", "coercion_pressure", "link_abuse", "data_exposure")}
        for s in signals:
            n = s.name
            if "credential" in n or "password" in s.detail.lower():
                dims["credential_theft"] += s.score * 120
            if "financial" in n or "money" in n or "payment" in s.detail.lower():
                dims["financial_fraud"] += s.score * 120
            if "social_engineering" in n or "impersonation" in n:
                dims["social_engineering"] += s.score * 120
            if "urgency" in n or "pressure" in n or "aggressive_caps" in n:
                dims["coercion_pressure"] += s.score * 110
            if "link" in n:
                dims["link_abuse"] += s.score * 140
        dims["link_abuse"] += float(link_analysis.get("aggregate_score", 0.0)) * 45
        dims["link_abuse"] += int(link_analysis.get("high_risk_links", 0)) * 10
        entity_counts = entities.get("counts", {})
        dims["data_exposure"] += entity_counts.get("emails", 0) * 8
        dims["data_exposure"] += entity_counts.get("phones", 0) * 6
        dims["data_exposure"] += entity_counts.get("numeric_ids", 0) * 5
        dims["financial_fraud"] += entity_counts.get("crypto_wallets", 0) * 10
        return {k: min(100, int(round(v))) for k, v in dims.items()}

    def _confidence_score(self, score_100: int, signal_count: int, text_length: int) -> int:
        confidence = (score_100 / 100) * 0.6 + min(0.25, signal_count * 0.03) + min(0.15, text_length / 1400)
        return min(99, max(10, int(round(confidence * 100))))

    def _recommendations(self, risk_level: str, link_analysis: Dict, entities: Dict) -> List[str]:
        recs: List[str] = []
        if risk_level in {"high", "critical"}:
            recs.append("Immediately isolate this message and trigger analyst review.")
            recs.append("Block detected URLs/domains at email gateway, DNS, and proxy controls.")
        if int(link_analysis.get("high_risk_links", 0)) > 0:
            recs.append("Perform safe detonation/sandboxing for all extracted links.")
        if entities.get("counts", {}).get("crypto_wallets", 0):
            recs.append("Escalate to financial fraud — cryptocurrency transfer indicators found.")
        if entities.get("counts", {}).get("numeric_ids", 0):
            recs.append("Mask sensitive numeric identifiers and open data-exposure case.")
        if risk_level in {"low", "medium"}:
            recs.append("Keep under monitoring; auto-recheck on repeated sender patterns.")
        recs.append("Preserve message headers and metadata for forensic correlation.")
        return recs[:6]

    @staticmethod
    def _dedupe_ordered(items: List[str]) -> List[str]:
        seen: Set[str] = set()
        return [item for item in items if item.strip() and not (item.strip() in seen or seen.add(item.strip()))]

    def _dedupe_signals(self, signals: List[Signal]) -> List[Signal]:
        best: Dict[Tuple[str, str], Signal] = {}
        for sig in signals:
            key = (sig.name, sig.detail)
            if key not in best or sig.score > best[key].score:
                best[key] = sig
        return list(best.values())

    def _benign_context_reduction(self, text: str, link_analysis: Dict) -> float:
        norm = self._normalize(text)
        benign_terms = {"meeting", "agenda", "minutes", "calendar", "schedule", "review", "draft", "notes", "thanks", "regards", "tomorrow", "team", "update"}
        tokens = set(self._tokenize(norm))
        benign_hits = len(tokens.intersection(benign_terms))
        risky_links = int(link_analysis.get("high_risk_links", 0)) + int(link_analysis.get("medium_risk_links", 0))
        if benign_hits < 3 or risky_links > 0:
            return 0.0
        return min(0.12, 0.02 * (benign_hits - 2))

    # ──────────────────────────────────────────
    # Main analyze entry point
    # ──────────────────────────────────────────
    def analyze(self, text: str) -> Dict[str, object]:
        if not text or not text.strip():
            return {
                "score": 0, "risk_level": "low", "plain_verdict": "No content to analyze.",
                "top_flags": [], "signals": [], "summary": "No content provided.",
                "link_analysis": {"total_links": 0, "high_risk_links": 0, "medium_risk_links": 0, "aggregate_score": 0.0, "links": []},
                "entities": {"emails": [], "phones": [], "ipv4s": [], "crypto_wallets": [], "numeric_ids": [], "counts": {}, "total": 0},
                "intent_profile": {"top_intents": [], "max_similarity": 0.0},
                "dimensions": {}, "confidence": 0,
                "domain_intelligence": {"brand_impersonation": {"score": 0.0, "flags": [], "brands": []}, "best_link_host": None},
                "recommendations": [], "threat_fingerprint": None,
            }

        # Parallel: link tracing + entity extraction + intent profiling simultaneously
        with ThreadPoolExecutor(max_workers=3) as pool:
            future_links = pool.submit(self.trace_links, text)
            future_entities = pool.submit(self._extract_entities, text)
            future_intent = pool.submit(self._intent_profile, text)
            link_analysis = future_links.result()
            entities = future_entities.result()
            intent_profile = future_intent.result()

        extracted_links = [str(item.get("raw", "")) for item in link_analysis.get("links", []) if item.get("raw")]
        signals = self._extract_rule_signals(text) + self._nlp_signals(text, extracted_links=extracted_links, intent_profile=intent_profile)

        best_link = max(link_analysis.get("links", []) or [{}], key=lambda x: float(x.get("score", 0.0)), default={})
        target_host = str((best_link or {}).get("host", "")).lower()
        brand_intel = self._brand_impersonation_profile(text, target_host)
        if float(brand_intel.get("score", 0.0)) > 0:
            signals.append(Signal("intel::brand_impersonation", min(0.20, float(brand_intel["score"])), "Brand impersonation content-domain mismatch"))
        signals = self._dedupe_signals(signals)
        if link_analysis["total_links"] > 0:
            signals.append(Signal("intel::link_trace", min(0.28, float(link_analysis["aggregate_score"]) * 0.22),
                                  f"Traced {link_analysis['total_links']} link(s), {link_analysis['high_risk_links']} high-risk."))
        if entities.get("total", 0) > 0:
            signals.append(Signal("intel::sensitive_entity_presence", min(0.14, 0.03 + entities["total"] * 0.015),
                                  f"Detected {entities['total']} sensitive entity indicator(s)."))

        score_breakdown = self._score_from_evidence(signals, link_analysis)
        benign_reduction = self._benign_context_reduction(text, link_analysis)
        calibrated = max(0.0, float(score_breakdown["calibrated"]) - benign_reduction)
        score_breakdown.update({"benign_reduction": round(benign_reduction, 3), "final": round(calibrated, 3)})
        score_100 = int(round(calibrated * 100))

        level = "critical" if score_100 >= 84 else ("high" if score_100 >= 66 else ("medium" if score_100 >= 42 else "low"))
        dimensions = self._dimension_scores(signals, link_analysis, entities)
        confidence = self._confidence_score(score_100, len(signals), len(text))
        if level == "critical" and confidence < 78:
            level = "high"
        if level == "high" and confidence < 48:
            level = "medium"

        summary = ("No explicit fraud indicators found." if not signals
                   else "Top indicators: " + "; ".join(f"{x.name} ({x.score:.2f})" for x in sorted(signals, key=lambda s: s.score, reverse=True)[:3]))
        top_flags = self._dedupe_ordered([s.detail for s in sorted(signals, key=lambda s: s.score, reverse=True)])[:5]
        plain_verdicts = {
            "critical": "High probability of scam or malicious content. Block immediately.",
            "high": "Strong risk indicators found. Requires analyst verification.",
            "medium": "Suspicious patterns detected. Proceed with caution.",
            "low": "No major fraud signals detected.",
        }

        return {
            "score": score_100,
            "risk_level": level,
            "confidence": confidence,
            "score_breakdown": score_breakdown,
            "plain_verdict": plain_verdicts[level],
            "top_flags": top_flags,
            "signals": [{"name": s.name, "score": round(s.score, 3), "detail": s.detail} for s in signals],
            "summary": summary,
            "intent_profile": intent_profile,
            "dimensions": dimensions,
            "entities": entities,
            "link_analysis": link_analysis,
            "domain_intelligence": {"brand_impersonation": brand_intel, "best_link_host": target_host or None},
            "recommendations": self._recommendations(level, link_analysis, entities),
            "threat_fingerprint": hashlib.sha256(self._normalize(text).encode()).hexdigest()[:24],
        }

    # ──────────────────────────────────────────
    # Async wrappers for FastAPI async endpoints
    # ──────────────────────────────────────────
    async def analyze_async(self, text: str) -> Dict[str, object]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self.analyze, text)

    async def analyze_batch_async(self, texts: List[str]) -> List[Dict[str, object]]:
        loop = asyncio.get_event_loop()
        tasks = [loop.run_in_executor(self._executor, self.analyze, t) for t in texts]
        return await asyncio.gather(*tasks)

    # ──────────────────────────────────────────
    # Website tracer (unchanged logic, optimized I/O)
    # ──────────────────────────────────────────
    def _normalize_site_url(self, website_url: str) -> str:
        cleaned = website_url.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
            cleaned = f"https://{cleaned}"
        parsed = urlsplit(cleaned)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Only http/https URLs are supported.")
        if not parsed.netloc:
            raise ValueError("Invalid website URL.")
        return cleaned

    def _same_site(self, root_host: str, host: str) -> bool:
        return bool(host) and (host == root_host or host.endswith(f".{root_host}"))

    def _extract_html_links(self, html: str, base_url: str) -> List[str]:
        seen: Set[str] = set()
        unique: List[str] = []
        for href in self._re_href.findall(html):
            if href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            abs_url = urljoin(base_url, href).split("#")[0].strip()
            if not abs_url:
                continue
            if urlsplit(abs_url).scheme not in {"http", "https"}:
                continue
            if abs_url not in seen:
                seen.add(abs_url)
                unique.append(abs_url)
        return unique

    def _html_to_text(self, html: str) -> str:
        return self._re_multi_ws.sub(" ", self._re_tag_strip.sub(" ", self._re_style_strip.sub(" ", self._re_script_strip.sub(" ", html)))).strip()

    def _extract_title(self, html: str) -> str:
        m = self._re_title.search(html)
        return re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""

    def _format_cert_time(self, value: str) -> str:
        try:
            return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").strftime("%d %b %Y %H:%M")
        except Exception:
            return value

    def _flatten_cert_name(self, cert_name: object) -> str:
        out: List[str] = []
        if isinstance(cert_name, tuple):
            for rdn in cert_name:
                if isinstance(rdn, tuple):
                    for item in rdn:
                        if isinstance(item, tuple) and len(item) == 2:
                            out.append(str(item[1]))
        return ", ".join([x for x in out if x]) or "Unknown"

    def _fetch_certificate(self, host: str, port: int = 443) -> Dict[str, object]:
        cached = self._global_cert_cache.get(host)
        if cached is not None:
            return cached
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=2.5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            out = {
                "host": host,
                "subject": self._flatten_cert_name(cert.get("subject", ())),
                "issuer": self._flatten_cert_name(cert.get("issuer", ())),
                "valid_from": self._format_cert_time(str(cert.get("notBefore", ""))),
                "valid_to": self._format_cert_time(str(cert.get("notAfter", ""))),
                "status": "ok",
            }
        except Exception as exc:
            out = {"host": host, "subject": "Unknown", "issuer": "Unknown", "valid_from": "", "valid_to": "", "status": "error", "error": str(exc)[:180]}
        self._global_cert_cache.set(host, out)
        return out

    def _is_probable_asset(self, content_type: str, url: str) -> bool:
        ct = (content_type or "").lower()
        if any(x in ct for x in ["image/", "font/", "audio/", "video/", "application/octet-stream", "javascript", "text/css"]):
            return True
        return bool(self._re_asset_ext.search((urlsplit(url).path or "").lower()))

    def _extract_sitemap_urls(self, seed: str, seed_host: str) -> List[str]:
        cache_key = f"{seed_host}|{seed.rstrip('/')}"
        cached = self._global_sitemap_cache.get(cache_key)
        if cached is not None:
            return cached
        found: List[str] = []
        for sm_url in [urljoin(seed, p) for p in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"]]:
            try:
                req = Request(sm_url, headers={"User-Agent": "RiskIntelCrawler/3.0"})
                with urlopen(req, timeout=4) as resp:
                    raw = resp.read(600000).decode("utf-8", errors="ignore")
                for node in ElementTree.fromstring(raw).findall(".//{*}loc"):
                    if node.text and self._same_site(seed_host, (urlsplit(node.text.strip()).hostname or "").lower()):
                        found.append(node.text.strip())
            except Exception:
                continue
        dedup: List[str] = []
        seen: Set[str] = set()
        for u in found:
            k = u.rstrip("/")
            if k not in seen:
                seen.add(k)
                dedup.append(u)
        out = dedup[:400]
        self._global_sitemap_cache.set(cache_key, out)
        return out

    def _malware_signals_from_html(self, html: str, page_url: str) -> Dict[str, object]:
        flags: List[str] = []
        score = 0.0
        lowered = html.lower()
        if re.search(r"eval\s*\(", lowered):
            score += 0.12; flags.append("JavaScript eval() usage")
        if "fromcharcode" in lowered:
            score += 0.10; flags.append("String.fromCharCode obfuscation")
        if re.search(r"\batob\s*\(", lowered):
            score += 0.08; flags.append("Base64 decode atob()")
        if re.search(r"\bunescape\s*\(", lowered):
            score += 0.08; flags.append("unescape() obfuscation primitive")
        if re.search(r"document\.write\s*\(", lowered):
            score += 0.05; flags.append("document.write dynamic injection")
        if re.findall(r"[A-Za-z0-9+/]{200,}={0,2}", html):
            score += 0.14; flags.append("Large base64-encoded blob")
        if re.search(r"<iframe[^>]*(display\s*:\s*none|width\s*=\s*[\"']?0|height\s*=\s*[\"']?0)", lowered):
            score += 0.15; flags.append("Hidden iframe behavior")
        if re.search(r"(download=|application/(x-msdownload|octet-stream))", lowered):
            score += 0.18; flags.append("Executable download vector")
        suspicious_downloads = [href for href in self._extract_html_links(html, page_url)
                                  if re.search(r"\.[a-z0-9]{2,5}$", urlsplit(href).path.lower()) and
                                  re.search(r"\.[a-z0-9]{2,5}$", urlsplit(href).path.lower()).group(0) in self.suspicious_file_ext]
        if suspicious_downloads:
            score += min(0.25, 0.09 + len(suspicious_downloads) * 0.03)
            flags.append(f"Suspicious download links: {len(suspicious_downloads)}")

        score = min(1.0, max(0.0, score))
        verdict = "likely_malicious" if score >= 0.62 else ("suspicious" if score >= 0.36 else "no_strong_malware_signal")
        return {"score": round(score, 3), "verdict": verdict, "flags": flags[:10], "suspicious_downloads": suspicious_downloads[:20]}

    def trace_website(
        self,
        website_url: str,
        max_pages: int = 120,
        max_depth: int = 4,
        include_external: bool = False,
        exhaustive: bool = True,
    ) -> Dict[str, object]:
        seed = self._normalize_site_url(website_url)
        seed_host = (urlsplit(seed).hostname or "").lower()
        if not seed_host:
            raise ValueError("Unable to parse website hostname.")

        max_pages = max(1, min(max_pages, 500))
        max_depth = max(0, min(max_depth, 8))

        queue: deque = deque([(seed, 0, None)])
        queued: Set[str] = {seed.rstrip("/")}
        visited: Set[str] = set()
        page_reports: List[Dict[str, object]] = []
        discovered_hosts: Set[str] = set()
        discovered_internal_urls: Set[str] = {seed.rstrip("/")}
        https_hosts_seen: Set[str] = set()

        if exhaustive:
            for sm_url in self._extract_sitemap_urls(seed, seed_host):
                key = sm_url.rstrip("/")
                if key not in discovered_internal_urls:
                    discovered_internal_urls.add(key)
                    if key not in queued and key not in visited:
                        queue.append((sm_url, 0, "sitemap"))
                        queued.add(key)

        while queue and len(page_reports) < max_pages:
            current, depth, parent = queue.popleft()
            canonical = current.rstrip("/")
            if canonical in visited:
                continue
            visited.add(canonical)

            page_result: Dict[str, object] = {
                "url": current, "depth": depth, "parent": parent,
                "status": "error", "status_code": None, "title": "",
                "risk_level": "low", "score": 0, "summary": "",
                "link_counts": {"internal": 0, "external": 0}, "error": None,
            }

            try:
                req = Request(current, headers={"User-Agent": "RiskIntelCrawler/3.0"})
                with urlopen(req, timeout=8) as resp:
                    status_code = int(getattr(resp, "status", resp.getcode()))
                    content_type = str(resp.headers.get("Content-Type", ""))
                    final_url = str(getattr(resp, "url", current))
                    payload = resp.read(1200000)
                final_parts = urlsplit(final_url)
                if final_parts.scheme == "https" and final_parts.hostname:
                    https_hosts_seen.add(final_parts.hostname.lower())
                html = payload.decode("utf-8", errors="ignore")
                page_text = self._html_to_text(html)[:14000]
                title = self._extract_title(html)
                malware = self._malware_signals_from_html(html, final_url)
                is_asset = self._is_probable_asset(content_type, final_url)
                ai = {"risk_level": "low", "score": 0, "summary": "Static asset.", "threat_fingerprint": None} if is_asset else self.analyze(page_text)
                extracted_links = self._extract_html_links(html, current)
                internal_links: List[str] = []
                external_links: List[str] = []
                for link in extracted_links:
                    host = (urlsplit(link).hostname or "").lower()
                    if host:
                        discovered_hosts.add(host)
                    if self._same_site(seed_host, host):
                        internal_links.append(link)
                        discovered_internal_urls.add(link.rstrip("/"))
                    else:
                        external_links.append(link)

                page_result.update({
                    "status": "ok", "status_code": status_code, "final_url": final_url,
                    "content_type": content_type, "is_asset": is_asset, "title": title,
                    "risk_level": ai["risk_level"], "score": ai["score"], "summary": ai["summary"],
                    "malware_score": int(round(float(malware["score"]) * 100)),
                    "malware_verdict": malware["verdict"], "malware_flags": malware["flags"],
                    "suspicious_downloads": malware["suspicious_downloads"],
                    "threat_fingerprint": ai["threat_fingerprint"],
                    "link_counts": {"internal": len(internal_links), "external": len(external_links)},
                    "link_preview": {"internal": internal_links[:12], "external": external_links[:12]},
                })

                if depth < max_depth:
                    for nxt in internal_links:
                        key = nxt.rstrip("/")
                        if key not in visited and key not in queued:
                            queue.append((nxt, depth + 1, current))
                            queued.add(key)
                    if include_external:
                        for nxt in external_links:
                            key = nxt.rstrip("/")
                            if key not in visited and key not in queued:
                                queue.append((nxt, depth + 1, current))
                                queued.add(key)
            except Exception as exc:
                page_result["error"] = str(exc)[:220]

            page_reports.append(page_result)

        ok_pages = [p for p in page_reports if p["status"] == "ok"]
        business_ok_pages = [p for p in ok_pages if not p.get("is_asset")]
        asset_ok_pages = [p for p in ok_pages if p.get("is_asset")]
        failed_pages = [p for p in page_reports if p["status"] != "ok"]
        high_pages = [p for p in business_ok_pages if p["risk_level"] in {"high", "critical"}]
        medium_pages = [p for p in business_ok_pages if p["risk_level"] == "medium"]
        malware_suspicious = [p for p in business_ok_pages if p.get("malware_verdict") in {"suspicious", "likely_malicious"}]
        malware_likely = [p for p in business_ok_pages if p.get("malware_verdict") == "likely_malicious"]
        top_pages = sorted(business_ok_pages, key=lambda x: int(x["score"]), reverse=True)[:8]
        avg_score = int(round(sum(int(p["score"]) for p in business_ok_pages) / max(len(business_ok_pages), 1)))
        highest = int(max((int(p["score"]) for p in business_ok_pages), default=0))
        avg_malware = int(round(sum(int(p.get("malware_score", 0)) for p in business_ok_pages) / max(len(business_ok_pages), 1)))
        highest_malware = int(max((int(p.get("malware_score", 0)) for p in business_ok_pages), default=0))

        overall = ("critical" if highest >= 80 or len(high_pages) >= 3 or len(malware_likely) >= 1
                   else ("high" if highest >= 60 or len(high_pages) >= 1 or len(malware_suspicious) >= 2
                         else ("medium" if avg_score >= 35 or len(medium_pages) >= 2 else "low")))
        coverage = int(round((len(visited) / max(len(discovered_internal_urls), 1)) * 100))
        scam_likelihood = int(min(100, round((avg_score * 0.55) + (len(high_pages) * 6) + (len(medium_pages) * 2) + (highest * 0.12))))
        malware_likelihood = int(min(100, round((avg_malware * 0.65) + (highest_malware * 0.2) + (len(malware_likely) * 15) + (len(malware_suspicious) * 4))))
        crawl_failed = bool(page_reports) and not ok_pages
        crawl_partial = bool(failed_pages) and coverage < 60
        if crawl_failed:
            overall = "medium"
            scam_likelihood = max(scam_likelihood, 35)
            malware_likelihood = max(malware_likelihood, 20)
            final_site_verdict = "suspicious"
        elif crawl_partial and overall == "low":
            overall = "medium"
            scam_likelihood = max(scam_likelihood, 25)
            final_site_verdict = "suspicious"
        else:
            final_site_verdict = ("likely_malicious" if scam_likelihood >= 70 or malware_likelihood >= 65 or overall == "critical"
                                  else ("suspicious" if scam_likelihood >= 45 or malware_likelihood >= 40 or overall in {"high", "medium"} else "likely_safe"))

        recs = []
        if high_pages: recs.append("Block/monitor high-risk pages and enforce user click protection.")
        if malware_likely: recs.append("Malware behavior detected; isolate domain and sandbox artifacts.")
        if malware_suspicious and not malware_likely: recs.append("Suspicious script patterns; perform dynamic analysis before allowing access.")
        if crawl_failed: recs.append("Crawler could not retrieve any pages; treat the scan as incomplete and verify network or host controls.")
        if failed_pages: recs.append("Review failed crawl targets; hidden paths may contain suspicious content.")
        if len(discovered_hosts) > 8: recs.append("High host diversity; investigate redirect/chaining behavior.")
        if coverage < 60: recs.append("Coverage limited; increase max_pages/max_depth for full trace.")
        recs += ["Enable scheduled recrawls for threat drift detection.", "Store crawl snapshots for historical analysis."]

        cert_hosts = sorted(https_hosts_seen)[:40]
        if cert_hosts:
            with ThreadPoolExecutor(max_workers=min(10, len(cert_hosts))) as ex:
                certificates = list(ex.map(self._fetch_certificate, cert_hosts))
        else:
            certificates = []

        return {
            "seed_url": seed, "scope_host": seed_host,
            "pages_crawled": len(page_reports), "pages_ok": len(ok_pages),
            "business_pages_scanned": len(business_ok_pages), "asset_pages_skipped": len(asset_ok_pages),
            "pages_failed": len(failed_pages), "coverage_percent": coverage,
            "risk_level": overall, "average_score": avg_score, "highest_score": highest,
            "high_risk_pages": len(high_pages), "medium_risk_pages": len(medium_pages),
            "malware_suspicious_pages": len(malware_suspicious), "malware_likely_pages": len(malware_likely),
            "average_malware_score": avg_malware, "highest_malware_score": highest_malware,
            "scam_likelihood": scam_likelihood, "malware_likelihood": malware_likelihood,
            "site_verdict": final_site_verdict,
            "discovered_host_count": len(discovered_hosts), "discovered_internal_urls": len(discovered_internal_urls),
            "certificates": certificates, "certificate_hosts_scanned": len(certificates),
            "certificate_hosts_ok": sum(1 for c in certificates if c.get("status") == "ok"),
            "top_risky_pages": [
                {"url": p["url"], "title": p.get("title", ""), "score": p["score"], "risk_level": p["risk_level"],
                 "malware_score": p.get("malware_score", 0), "malware_verdict": p.get("malware_verdict", "no_strong_malware_signal"),
                 "summary": p["summary"]} for p in top_pages
            ],
            "pages": page_reports,
            "recommendations": recs[:6],
        }


import asyncio
import hashlib
import ipaddress
import re
import socket
import ssl
import time
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from math import exp, sqrt
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlsplit
from urllib.request import Request, urlopen
from xml.etree import ElementTree
from datetime import datetime
import functools
import threading


# ─────────────────────────────────────────────
# TTL-aware thread-safe in-process cache
# ─────────────────────────────────────────────
class TTLCache:
    """Thread-safe LRU-style cache with per-entry TTL."""

    def __init__(self, maxsize: int = 4096, ttl: float = 3600.0) -> None:
        self._store: Dict[str, Tuple[Any, float]] = {}
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
                # Evict oldest 10%
                oldest = sorted(self._store.items(), key=lambda x: x[1][1])[: self._maxsize // 10]
                for k, _ in oldest:
                    del self._store[k]
            self._store[key] = (value, time.monotonic())

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        return len(self._store)


@dataclass(frozen=True)
class Signal:
    name: str
    score: float
    detail: str


# ─────────────────────────────────────────────
# Extended threat pattern library
# ─────────────────────────────────────────────
RULE_SETS: Dict[str, Dict[str, float]] = {
    "credential_theft": {
        r"\bverify (your )?(account|identity)\b": 0.18,
        r"\breset (your )?password\b": 0.16,
        r"\blogin immediately\b": 0.12,
        r"\bsecurity alert\b": 0.10,
        r"\baccount (suspended|locked|disabled)\b": 0.17,
        r"\bconfirm (your )?(credentials|login|email)\b": 0.15,
    },
    "financial_fraud": {
        r"\bwire transfer\b": 0.17,
        r"\bgift card\b": 0.18,
        r"\bcrypto( wallet| payment)?\b": 0.13,
        r"\bbank details\b": 0.14,
        r"\bpayment failed\b": 0.10,
        r"\bsend (the )?funds?\b": 0.16,
        r"\bbitcoin\b": 0.12,
        r"\bwestern union\b": 0.19,
        r"\bmoney gram\b": 0.18,
        r"\binvoice (overdue|past due)\b": 0.13,
    },
    "urgency_pressure": {
        r"\bwithin (\d+ )?(minutes?|hours?)\b": 0.10,
        r"\bact now\b": 0.14,
        r"\bfinal warning\b": 0.15,
        r"\bimmediate action required\b": 0.18,
        r"\bexpires? (today|tonight|in \d+)\b": 0.12,
        r"\blast chance\b": 0.13,
        r"\btime.sensitive\b": 0.11,
    },
    "social_engineering": {
        r"\bthis is (the )?ceo\b": 0.15,
        r"\bkeep this confidential\b": 0.17,
        r"\bdo not tell anyone\b": 0.16,
        r"\btrusted partner\b": 0.08,
        r"\bpersonal favor\b": 0.11,
        r"\bbetween (us|you and me)\b": 0.10,
        r"\bdon'?t (mention|share|discuss) this\b": 0.14,
    },
    "business_email_compromise": {
        r"\bkindly process\b": 0.13,
        r"\bapproved by management\b": 0.10,
        r"\bout of office\b": 0.08,
        r"\bvendor update\b": 0.12,
        r"\bnew (banking|payment) (details?|instructions?)\b": 0.19,
        r"\bchange (of )?account (details?|number)\b": 0.17,
        r"\bauthorized (by|from) (the )?(cfo|ceo|management)\b": 0.15,
    },
    "malware_delivery": {
        r"\bopen (the |this )?(attached?|file|document)\b": 0.13,
        r"\bdownload (and )?(install|run|execute)\b": 0.16,
        r"\benable (macro|content)\b": 0.18,
        r"\bclick (to |here to )?(view|access|download)\b": 0.12,
        r"\bupdate (required|needed|now)\b": 0.11,
    },
    "romance_scam": {
        r"\bsend (me )?money\b": 0.17,
        r"\bi (love|miss|need) you\b.*\b(send|transfer|help)\b": 0.16,
        r"\bstranded (abroad|overseas|at the airport)\b": 0.19,
        r"\bmedical emergency\b.*\bmoney\b": 0.18,
    },
    "lottery_scam": {
        r"\byou (have |'ve )?(won|been selected)\b": 0.16,
        r"\bclaim (your )?(prize|winnings?|reward)\b": 0.17,
        r"\blottery (winner|jackpot)\b": 0.18,
        r"\bunclaimed (funds?|prize)\b": 0.15,
    },
}

INTENT_PROTOTYPES: Dict[str, str] = {
    "phishing_credential_theft": "Your account is suspended. Verify identity and password now.",
    "invoice_or_wire_fraud": "Urgent transfer required to secure corporate payment channel.",
    "gift_card_scam": "Purchase gift cards immediately and send the claim codes.",
    "malicious_link_delivery": "Security warning: click link to avoid permanent account lock.",
    "executive_impersonation": "Confidential request from executive: process payment discreetly.",
    "bank_detail_tampering": "Update bank details now to prevent payroll disruption.",
    "malware_download": "Enable macros to view important document. Download and install update.",
    "romance_fraud": "I love you and need your help. Send money urgently.",
    "lottery_fraud": "You have won a prize. Claim your lottery winnings now.",
    "advance_fee_fraud": "Transfer fee required to release inheritance funds to your account.",
}


class RiskEngine:
    """
    Hybrid fraud detection engine — deterministic rules + NLP cosine similarity.
    v3: async-ready, parallel link tracing, TTL caches, extended rule library.
    """

    _global_link_cache = TTLCache(maxsize=8192, ttl=1800.0)
    _global_whois_cache = TTLCache(maxsize=2048, ttl=7200.0)
    _global_domain_cache = TTLCache(maxsize=4096, ttl=3600.0)
    _global_cert_cache = TTLCache(maxsize=1024, ttl=3600.0)
    _global_sitemap_cache = TTLCache(maxsize=512, ttl=1800.0)

    def __init__(self) -> None:
        self.rule_sets = RULE_SETS
        self.intent_prototypes = INTENT_PROTOTYPES
        self.prototype_vectors = {
            intent:         self._vectorize(self._normalize(text))
            for intent, text in self.intent_prototypes.items()
        }
        self.high_risk_terms = {
            "password", "otp", "bank", "transfer", "wallet", "payment", "urgent",
            "verify", "confidential", "gift", "card", "crypto", "pin", "credential",
            "click", "link", "bitcoin", "invoice", "wire", "lottery", "prize",
            "winner", "inheritance", "claim", "fund", "release",
        }
        self.shortener_domains = {
            "bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd", "goo.gl",
            "ow.ly", "shorturl.at", "cutt.ly", "rebrand.ly", "tiny.cc",
            "snip.ly", "bl.ink", "short.io",
        }
        self.suspicious_tlds = {
            "zip", "mov", "top", "gq", "tk", "work", "click", "cam", "rest",
            "country", "stream", "xyz", "pw", "cc", "biz", "info",
        }
        self.sensitive_query_keys = {"url", "redirect", "next", "target", "dest", "continue", "return", "goto"}
        self.suspicious_file_ext = {".exe", ".msi", ".bat", ".cmd", ".scr", ".js", ".vbs", ".jar", ".ps1", ".hta", ".pif"}
        self.link_risk_terms = {"login", "verify", "secure", "wallet", "bank", "password", "update", "payment", "signin", "account"}
        self.reputation_risky_terms = {
            "secure", "verify", "update", "wallet", "login", "account",
            "signin", "support", "billing", "payment", "confirm", "auth",
        }
        self.known_brands = {
            "google", "microsoft", "apple", "amazon", "paypal", "netflix",
            "facebook", "instagram", "whatsapp", "linkedin", "github",
            "dropbox", "twitter", "x", "bankofamerica", "chase", "wellsfargo",
            "citibank", "outlook", "office365", "youtube", "tiktok", "coinbase",
            "binance", "kraken", "robinhood", "stripe", "shopify",
        }
        self.brand_text_terms = {
            "google", "microsoft", "apple", "amazon", "paypal", "netflix",
            "facebook", "instagram", "linkedin", "github", "outlook", "office365",
            "bank of america", "wells fargo", "citi", "chase bank", "youtube",
            "tiktok", "coinbase", "binance",
        }
        self.typo_homograph_map = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})

        # Pre-compiled regex patterns
        self._re_url_scheme = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
        self._re_link_pattern = re.compile(r"(?:(?:https?|ftp)://|www\.)[^\s<>'\"()]+", flags=re.IGNORECASE)
        self._re_asset_ext = re.compile(r"\.(png|jpg|jpeg|gif|svg|ico|webp|woff2?|ttf|eot|css|js|map|mp4|mp3|pdf)$")
        self._re_title = re.compile(r"<title[^>]*>(.*?)</title>", flags=re.IGNORECASE | re.DOTALL)
        self._re_href = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', flags=re.IGNORECASE)
        self._re_tag_strip = re.compile(r"<[^>]+>")
        self._re_script_strip = re.compile(r"<script[\s\S]*?</script>", flags=re.IGNORECASE)
        self._re_style_strip = re.compile(r"<style[\s\S]*?</style>", flags=re.IGNORECASE)
        self._re_multi_ws = re.compile(r"\s+")
        self._re_obfuscated_link = re.compile(r"hxxps?://|\[\.\]|\(\.\)")
        self._re_repeated_chars = re.compile(r"(.)\1{5,}")
        self._re_currency = re.compile(r"\$\d+|\b\d{2,}(?:,\d{3})*(?:\.\d+)?\b")
        self._re_caps = re.compile(r"\b[A-Z]{3,}\b")
        self._re_exec_ext = re.compile(r"\.[a-zA-Z0-9]{2,5}$")
        self._re_whois_date = re.compile(r"(20\d{2})[-/](\d{1,2})[-/](\d{1,2})")

        # Compile rule sets once
        self._rule_sets_compiled: Dict[str, List[Tuple[re.Pattern, float, str]]] = {}
        for category, patterns in self.rule_sets.items():
            self._rule_sets_compiled[category] = [
                (re.compile(pat, re.IGNORECASE), weight, pat)
                for pat, weight in patterns.items()
            ]

        # Thread pool for parallel I/O (link tracing, cert checks, WHOIS)
        self._executor = ThreadPoolExecutor(max_workers=20, thread_name_prefix="riskintel")
        
    # ──────────────────────────────────────────
    # Core NLP helpers
    # ──────────────────────────────────────────
    def _normalize(self, text: str) -> str:
        return self._re_multi_ws.sub(" ", text.strip().lower())

    def _deobfuscate_links_text(self, text: str) -> str:
        return (
            text.replace("[.]", ".").replace("(.)", ".")
            .replace("hxxp://", "http://").replace("hxxps://", "https://")
        )

    def _tokenize(self, text: str) -> List[str]:
        return re.findall(r"[a-zA-Z0-9']+", text)

    def _vectorize(self, text: str) -> Counter:
        tokens = self._tokenize(text)
        if len(tokens) < 2:
            return Counter(tokens)
        bigrams = [f"{tokens[i]}_{tokens[i+1]}" for i in range(len(tokens) - 1)]
        return Counter(tokens + bigrams)

    def _cosine(self, a: Counter, b: Counter) -> float:
        if not a or not b:
            return 0.0
        dot = sum(a[k] * b.get(k, 0) for k in a)
        norm_a = sqrt(sum(v * v for v in a.values()))
        norm_b = sqrt(sum(v * v for v in b.values()))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def _extract_links(self, text: str) -> List[str]:
        candidate_text = self._deobfuscate_links_text(text)
        links = self._re_link_pattern.findall(candidate_text)
        seen: Set[str] = set()
        unique: List[str] = []
        for link in links:
            normalized = link.strip(".,);]}>\"'")
            low = normalized.lower()
            if normalized and low not in seen:
                seen.add(low)
                unique.append(normalized)
        return unique

    @staticmethod
    def _effective_domain(hostname: str) -> str:
        parts = [p for p in hostname.split(".") if p]
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname

    @staticmethod
    def _sld(hostname: str) -> str:
        parts = [p for p in hostname.split(".") if p]
        return parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")

    @staticmethod
    def _levenshtein(a: str, b: str) -> int:
        if a == b:
            return 0
        if not a:
            return len(b)
        if not b:
            return len(a)
        if len(a) < len(b):
            a, b = b, a
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, start=1):
            cur = [i]
            for j, cb in enumerate(b, start=1):
                cur.append(min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + (0 if ca == cb else 1)))
            prev = cur
        return prev[-1]

    # ──────────────────────────────────────────
    # Domain intelligence (with global TTL caches)
    # ──────────────────────────────────────────
    def _domain_reputation_profile(self, hostname: str) -> Dict[str, object]:
        host = (hostname or "").strip().lower()
        if not host:
            return {"score": 0.0, "flags": [], "category": "unknown"}
        cached = self._global_domain_cache.get(host)
        if cached is not None:
            return cached

        score = 0.0
        flags: List[str] = []
        sld = self._sld(host)
        digits = sum(ch.isdigit() for ch in sld)
        hyphens = sld.count("-")
        alpha = sum(ch.isalpha() for ch in sld)
        entropy_like = len(set(sld)) / max(len(sld), 1)
        risky_term_hits = [term for term in self.reputation_risky_terms if term in host]
        tld = host.rsplit(".", 1)[-1] if "." in host else ""

        if digits >= 3:
            score += 0.07; flags.append("Heavy numeric usage in domain")
        if hyphens >= 2:
            score += 0.08; flags.append("Multiple hyphens in domain")
        if len(sld) >= 22:
            score += 0.08; flags.append("Very long second-level domain")
        if entropy_like > 0.82 and len(sld) >= 10 and alpha >= 6:
            score += 0.06; flags.append("High-randomness domain label")
        if risky_term_hits:
            score += min(0.15, 0.04 * len(risky_term_hits))
            flags.append(f"Risky terms in domain: {', '.join(sorted(set(risky_term_hits)))}")
        if tld in self.suspicious_tlds:
            score += 0.10; flags.append(f"Suspicious TLD .{tld}")

        category = "poor" if score >= 0.45 else ("questionable" if score >= 0.25 else "neutral")
        out = {"score": round(min(1.0, score), 3), "flags": flags[:8], "category": category}
        self._global_domain_cache.set(host, out)
        return out

    def _brand_impersonation_profile(self, text: str, hostname: str) -> Dict[str, object]:
        norm = self._normalize(text)
        host = (hostname or "").lower()
        hits = [b for b in self.brand_text_terms if b in norm]
        if not hits:
            return {"score": 0.0, "flags": [], "brands": []}
        effective = self._effective_domain(host)
        flags: List[str] = []
        score = 0.0
        brands: List[str] = []
        for b in hits:
            token = re.sub(r"[^a-z0-9]", "", b.lower())
            if not token:
                continue
            brands.append(b)
            if token not in effective:
                score += 0.07
                flags.append(f"Brand '{b}' mismatches destination domain")
        if len(set(brands)) >= 2:
            score += 0.05; flags.append("Multiple brand references")
        return {"score": round(min(0.35, score), 3), "flags": flags[:8], "brands": sorted(set(brands))[:8]}

    def _typosquat_profile(self, hostname: str) -> Dict[str, object]:
        host = (hostname or "").strip().lower()
        if not host:
            return {"score": 0.0, "flags": [], "closest_brand": None}
        sld = self._sld(host)
        normalized = sld.translate(self.typo_homograph_map)
        if len(normalized) < 3:
            return {"score": 0.0, "flags": [], "closest_brand": None}

        best_brand: Optional[str] = None
        best_dist = 99
        for brand in self.known_brands:
            dist = self._levenshtein(normalized, brand)
            if dist < best_dist:
                best_dist = dist
                best_brand = brand

        score = 0.0
        flags: List[str] = []
        if best_brand and normalized != best_brand:
            if best_dist == 1:
                score += 0.26; flags.append(f"Likely typosquat of '{best_brand}' (edit distance 1)")
            elif best_dist == 2 and len(best_brand) >= 6:
                score += 0.17; flags.append(f"Possible typosquat of '{best_brand}' (edit distance 2)")
        if best_brand and best_brand in normalized and normalized != best_brand:
            extra = normalized.replace(best_brand, "")
            if len(extra) >= 3:
                score += 0.09; flags.append(f"Brand '{best_brand}' embedded with deceptive token")
        return {"score": round(min(0.4, score), 3), "flags": flags[:8], "closest_brand": best_brand}

    def _whois_domain_age_profile(self, hostname: str) -> Dict[str, object]:
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
        status = "unavailable"
        rdap_url = f"https://rdap.org/domain/{root}"
        try:
            req = Request(rdap_url, headers={"User-Agent": "RiskIntel/3.0", "Accept": "application/rdap+json"})
            with urlopen(req, timeout=2.5) as resp:
                payload = resp.read(240000).decode("utf-8", errors="ignore")
            m = self._re_whois_date.search(payload)
            if m:
                year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
                created = datetime(year=year, month=max(1, min(month, 12)), day=max(1, min(day, 28)))
                age_days = max(0, (datetime.utcnow() - created).days)
                status = "ok"
        except Exception:
            status = "unavailable"

        if age_days is not None:
            if age_days < 30:
                score += 0.23; flags.append("Very new domain (<30 days)")
            elif age_days < 90:
                score += 0.16; flags.append("Recently registered (<90 days)")
            elif age_days < 180:
                score += 0.10; flags.append("Young domain (<180 days)")

        out = {"score": round(min(0.3, score), 3), "flags": flags, "age_days": age_days, "status": status}
        self._global_whois_cache.set(host, out)
        return out

    # ──────────────────────────────────────────
    # Link tracing (parallel via thread pool)
    # ──────────────────────────────────────────
    def _trace_single_link(self, raw_link: str) -> Dict[str, object]:
        key = raw_link.strip().lower()
        cached = self._global_link_cache.get(key)
        if cached is not None:
            return cached

        working = raw_link if self._re_url_scheme.match(raw_link) else f"http://{raw_link}"
        parsed = urlsplit(working)
        hostname = (parsed.hostname or "").strip().lower()
        path = parsed.path or ""
        query = parsed.query or ""

        score = 0.0
        flags: List[str] = []

        if parsed.scheme == "http":
            score += 0.10; flags.append("Unencrypted HTTP scheme")
        if "@" in parsed.netloc:
            score += 0.15; flags.append("Credentials in URL (user-info)")
        if hostname in self.shortener_domains:
            score += 0.16; flags.append("Known URL shortener")
        if hostname.startswith("xn--") or ".xn--" in hostname:
            score += 0.12; flags.append("Punycode/IDN domain spoofing risk")
        if any(ord(ch) > 127 for ch in hostname):
            score += 0.10; flags.append("Non-ASCII domain characters")

        subdomain_depth = max(0, len(hostname.split(".")) - 2)
        if subdomain_depth >= 3:
            score += 0.08; flags.append("Deep subdomain chain")
        if len(working) > 140:
            score += 0.08; flags.append("Excessive URL length")
        if parsed.port and parsed.port not in {80, 443}:
            score += 0.08; flags.append(f"Non-standard port {parsed.port}")

        last_dot = hostname.rfind(".")
        tld = hostname[last_dot + 1:] if last_dot > -1 else ""
        if tld in self.suspicious_tlds:
            score += 0.14; flags.append(f"Suspicious TLD .{tld}")

        lower_full = f"{hostname}{path}?{query}".lower()
        keyword_hits = [k for k in self.link_risk_terms if k in lower_full]
        if keyword_hits:
            score += min(0.12, 0.03 * len(keyword_hits))
            flags.append(f"Risk keywords in URL: {', '.join(sorted(set(keyword_hits)))}")

        ext_match = self._re_exec_ext.search(path.lower())
        if ext_match and ext_match.group(0) in self.suspicious_file_ext:
            score += 0.20; flags.append(f"Executable/script extension {ext_match.group(0)}")

        encoded_ratio = working.count("%") / max(len(working), 1)
        if encoded_ratio > 0.03 or working.count("%") >= 4:
            score += 0.07; flags.append("Heavy URL percent-encoding")

        query_map = parse_qs(query, keep_blank_values=True)
        redirect_keys = [k for k in query_map if k.lower() in self.sensitive_query_keys]
        if redirect_keys:
            score += 0.12; flags.append(f"Open redirect parameters: {', '.join(sorted(redirect_keys))}")

        ip_label = ip_type = None
        if hostname:
            try:
                ip_obj = ipaddress.ip_address(hostname)
                ip_label = str(ip_obj)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    score += 0.10; ip_type = "private/local"; flags.append("Private/local IP host")
                else:
                    score += 0.07; ip_type = "public"; flags.append("Direct IP instead of domain")
            except ValueError:
                pass

        reputation = self._domain_reputation_profile(hostname)
        typo = self._typosquat_profile(hostname)
        whois_age = self._whois_domain_age_profile(hostname)
        score += min(0.18, float(reputation.get("score", 0.0)) * 0.7)
        flags.extend(list(reputation.get("flags", []))[:2])
        score += min(0.20, float(typo.get("score", 0.0)) * 0.9)
        flags.extend(list(typo.get("flags", []))[:2])
        score += min(0.12, float(whois_age.get("score", 0.0)) * 0.8)
        flags.extend(list(whois_age.get("flags", []))[:1])

        score = min(1.0, max(0.0, score))
        verdict = "critical" if score >= 0.65 else ("high" if score >= 0.45 else ("medium" if score >= 0.25 else "low"))

        out = {
            "raw": raw_link,
            "normalized": working,
            "scheme": parsed.scheme,
            "host": hostname,
            "port": parsed.port,
            "path": path,
            "query_keys": sorted(query_map.keys()),
            "ip": ip_label,
            "ip_type": ip_type,
            "score": round(score, 3),
            "verdict": verdict,
            "flags": self._dedupe_ordered(flags)[:12],
            "domain_intelligence": {
                "domain_reputation": reputation,
                "typosquatting": typo,
                "whois_age": whois_age,
            },
        }
        self._global_link_cache.set(key, out)
        return out

    def trace_links(self, text: str) -> Dict[str, object]:
        links = self._extract_links(text)
        if not links:
            return {"total_links": 0, "high_risk_links": 0, "medium_risk_links": 0, "aggregate_score": 0.0, "links": []}

        # Parallel link tracing
        futures = {self._executor.submit(self._trace_single_link, link): link for link in links}
        traced: List[Dict[str, object]] = []
        for future in as_completed(futures):
            try:
                traced.append(future.result(timeout=6.0))
            except Exception:
                pass

        high_count = sum(1 for x in traced if x["verdict"] in {"high", "critical"})
        med_count = sum(1 for x in traced if x["verdict"] == "medium")
        total_score = round(sum(float(x["score"]) for x in traced), 3)
        return {
            "total_links": len(traced),
            "high_risk_links": high_count,
            "medium_risk_links": med_count,
            "aggregate_score": total_score,
            "links": sorted(traced, key=lambda x: float(x["score"]), reverse=True),
        }

    # ──────────────────────────────────────────
    # Entity extraction
    # ──────────────────────────────────────────
    def _extract_entities(self, text: str) -> Dict[str, object]:
        emails = re.findall(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", text)
        phones = re.findall(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)\d{3,4}[-.\s]?\d{3,4}\b", text)
        ipv4s = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        crypto_wallets = re.findall(r"\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", text)
        long_numeric_ids = re.findall(r"\b\d{10,18}\b", text)
        cvv_pattern = re.findall(r"\b\d{3,4}\b", text)  # light card CVV indicator
        entities = {
            "emails": sorted(set(emails))[:12],
            "phones": sorted(set(phones))[:12],
            "ipv4s": sorted(set(ipv4s))[:12],
            "crypto_wallets": sorted(set(crypto_wallets))[:12],
            "numeric_ids": sorted(set(long_numeric_ids))[:12],
        }
        entities["counts"] = {k: len(v) for k, v in entities.items() if isinstance(v, list)}
        entities["total"] = sum(entities["counts"].values())
        return entities

    # ──────────────────────────────────────────
    # Intent profiling
    # ──────────────────────────────────────────
    def _intent_profile(self, text: str) -> Dict[str, object]:
        norm = self._normalize(text)
        query_vector =         self._vectorize(norm)
        intent_scores = [
            {"intent": intent, "similarity": round(self._cosine(query_vector, proto), 3)}
            for intent, proto in self.prototype_vectors.items()
        ]
        top_intents = sorted(intent_scores, key=lambda x: x["similarity"], reverse=True)[:3]
        return {"top_intents": top_intents, "max_similarity": top_intents[0]["similarity"] if top_intents else 0.0}

    # ──────────────────────────────────────────
    # Signal extraction
    # ──────────────────────────────────────────
    def _extract_rule_signals(self, text: str) -> List[Signal]:
        norm = self._normalize(text)
        signals: List[Signal] = []
        for category, patterns in self._rule_sets_compiled.items():
            cat_hits: List[Tuple[str, float]] = []
            for compiled, weight, raw_pattern in patterns:
                if compiled.search(norm):
                    cat_hits.append((raw_pattern, weight))
            if not cat_hits:
                continue
            cat_hits.sort(key=lambda x: x[1], reverse=True)
            cat_score = sum(w * (1.0 if i == 0 else (0.62 if i == 1 else 0.30)) for i, (_, w) in enumerate(cat_hits))
            cat_score = min(0.28, cat_score)
            signals.append(Signal(
                name=f"rule::{category}",
                score=cat_score,
                detail=f"Matched {len(cat_hits)} pattern(s) in {category}; strongest '{cat_hits[0][0]}'.",
            ))
        return signals

    def _nlp_signals(
        self,
        text: str,
        extracted_links: Optional[List[str]] = None,
        intent_profile: Optional[Dict[str, object]] = None,
    ) -> List[Signal]:
        norm = self._normalize(text)
        words = self._tokenize(norm)
        total_words = max(len(words), 1)
        high_risk_hits = sum(1 for w in words if w in self.high_risk_terms)
        risk_density = high_risk_hits / total_words
        exclamations = text.count("!")
        caps_words = self._re_caps.findall(text)
        link_hits = len(extracted_links) if extracted_links is not None else len(self._extract_links(text))
        currency_hits = len(self._re_currency.findall(text))
        obfuscated_hits = len(self._re_obfuscated_link.findall(text.lower()))
        profile = intent_profile if intent_profile is not None else self._intent_profile(text)
        sim = float(profile["max_similarity"])

        signals: List[Signal] = []
        if risk_density > 0.08:
            signals.append(Signal("nlp::risk_term_density", min(0.18, risk_density * 1.4), f"High-risk term density {risk_density:.2f}"))
        if sim > 0.25:
            signals.append(Signal("nlp::intent_similarity", min(0.25, sim * 0.55), f"Fraud intent similarity {sim:.2f}"))
        if exclamations >= 3:
            signals.append(Signal("nlp::pressure_tone", min(0.08, exclamations * 0.02), f"{exclamations} exclamation marks"))
        if len(caps_words) >= 2:
            signals.append(Signal("nlp::aggressive_caps", 0.07, "Multiple ALL-CAPS tokens"))
        if link_hits > 0:
            signals.append(Signal("nlp::external_link", min(0.10, 0.05 + 0.02 * link_hits), f"{link_hits} external link(s)"))
        if currency_hits > 0:
            signals.append(Signal("nlp::money_reference", min(0.09, 0.03 + currency_hits * 0.02), f"{currency_hits} currency indicator(s)"))
        if obfuscated_hits > 0:
            signals.append(Signal("nlp::link_obfuscation", min(0.16, 0.06 + obfuscated_hits * 0.03), f"{obfuscated_hits} obfuscated link(s)"))
        if self._re_repeated_chars.search(text):
            signals.append(Signal("nlp::pattern_anomaly", 0.06, "Repeated-character pattern anomaly"))
        return signals

    # ──────────────────────────────────────────
    # Score synthesis
    # ──────────────────────────────────────────
    def _score_from_evidence(self, signals: List[Signal], link_analysis: Dict[str, object]) -> Dict[str, float]:
        rule_sum = nlp_sum = intel_sum = 0.0
        signal_names = [s.name for s in signals]
        for s in signals:
            if s.name.startswith("rule::"):
                rule_sum += s.score
            elif s.name.startswith("nlp::"):
                nlp_sum += s.score
            else:
                intel_sum += s.score

        rule_capped = min(0.56, rule_sum)
        nlp_capped = min(0.34, nlp_sum)
        intel_capped = min(0.24, intel_sum)
        raw_capped = rule_capped + nlp_capped + intel_capped

        fusion_boost = 0.0
        if rule_capped > 0.25 and nlp_capped > 0.14:
            fusion_boost += 0.06
        if int(link_analysis.get("high_risk_links", 0)) > 0 and (
            "nlp::link_obfuscation" in signal_names or intel_capped > 0.08
        ):
            fusion_boost += 0.05
        if "rule::financial_fraud" in signal_names and "rule::social_engineering" in signal_names:
            fusion_boost += 0.04
        if "nlp::intent_similarity" in signal_names and nlp_capped > 0.18:
            fusion_boost += 0.03

        blended = min(1.0, raw_capped + fusion_boost)
        calibrated = min(0.96, max(0.0, 1.0 - exp(-1.45 * blended)))
        return {
            "rule": round(rule_capped, 3),
            "nlp": round(nlp_capped, 3),
            "intel": round(intel_capped, 3),
            "fusion": round(fusion_boost, 3),
            "raw": round(blended, 3),
            "calibrated": round(calibrated, 3),
        }

    def _dimension_scores(self, signals: List[Signal], link_analysis: Dict, entities: Dict) -> Dict[str, int]:
        dims = {k: 0.0 for k in ("credential_theft", "financial_fraud", "social_engineering", "coercion_pressure", "link_abuse", "data_exposure")}
        for s in signals:
            n = s.name
            if "credential" in n or "password" in s.detail.lower():
                dims["credential_theft"] += s.score * 120
            if "financial" in n or "money" in n or "payment" in s.detail.lower():
                dims["financial_fraud"] += s.score * 120
            if "social_engineering" in n or "impersonation" in n:
                dims["social_engineering"] += s.score * 120
            if "urgency" in n or "pressure" in n or "aggressive_caps" in n:
                dims["coercion_pressure"] += s.score * 110
            if "link" in n:
                dims["link_abuse"] += s.score * 140
        dims["link_abuse"] += float(link_analysis.get("aggregate_score", 0.0)) * 45
        dims["link_abuse"] += int(link_analysis.get("high_risk_links", 0)) * 10
        entity_counts = entities.get("counts", {})
        dims["data_exposure"] += entity_counts.get("emails", 0) * 8
        dims["data_exposure"] += entity_counts.get("phones", 0) * 6
        dims["data_exposure"] += entity_counts.get("numeric_ids", 0) * 5
        dims["financial_fraud"] += entity_counts.get("crypto_wallets", 0) * 10
        return {k: min(100, int(round(v))) for k, v in dims.items()}

    def _confidence_score(self, score_100: int, signal_count: int, text_length: int) -> int:
        confidence = (score_100 / 100) * 0.6 + min(0.25, signal_count * 0.03) + min(0.15, text_length / 1400)
        return min(99, max(10, int(round(confidence * 100))))

    def _recommendations(self, risk_level: str, link_analysis: Dict, entities: Dict) -> List[str]:
        recs: List[str] = []
        if risk_level in {"high", "critical"}:
            recs.append("Immediately isolate this message and trigger analyst review.")
            recs.append("Block detected URLs/domains at email gateway, DNS, and proxy controls.")
        if int(link_analysis.get("high_risk_links", 0)) > 0:
            recs.append("Perform safe detonation/sandboxing for all extracted links.")
        if entities.get("counts", {}).get("crypto_wallets", 0):
            recs.append("Escalate to financial fraud — cryptocurrency transfer indicators found.")
        if entities.get("counts", {}).get("numeric_ids", 0):
            recs.append("Mask sensitive numeric identifiers and open data-exposure case.")
        if risk_level in {"low", "medium"}:
            recs.append("Keep under monitoring; auto-recheck on repeated sender patterns.")
        recs.append("Preserve message headers and metadata for forensic correlation.")
        return recs[:6]

    @staticmethod
    def _dedupe_ordered(items: List[str]) -> List[str]:
        seen: Set[str] = set()
        return [item for item in items if item.strip() and not (item.strip() in seen or seen.add(item.strip()))]

    def _dedupe_signals(self, signals: List[Signal]) -> List[Signal]:
        best: Dict[Tuple[str, str], Signal] = {}
        for sig in signals:
            key = (sig.name, sig.detail)
            if key not in best or sig.score > best[key].score:
                best[key] = sig
        return list(best.values())

    def _benign_context_reduction(self, text: str, link_analysis: Dict) -> float:
        norm = self._normalize(text)
        benign_terms = {"meeting", "agenda", "minutes", "calendar", "schedule", "review", "draft", "notes", "thanks", "regards", "tomorrow", "team", "update"}
        tokens = set(self._tokenize(norm))
        benign_hits = len(tokens.intersection(benign_terms))
        risky_links = int(link_analysis.get("high_risk_links", 0)) + int(link_analysis.get("medium_risk_links", 0))
        if benign_hits < 3 or risky_links > 0:
            return 0.0
        return min(0.12, 0.02 * (benign_hits - 2))

    # ──────────────────────────────────────────
    # Main analyze entry point
    # ──────────────────────────────────────────
    def analyze(self, text: str) -> Dict[str, object]:
        if not text or not text.strip():
            return {
                "score": 0, "risk_level": "low", "plain_verdict": "No content to analyze.",
                "top_flags": [], "signals": [], "summary": "No content provided.",
                "link_analysis": {"total_links": 0, "high_risk_links": 0, "medium_risk_links": 0, "aggregate_score": 0.0, "links": []},
                "entities": {"emails": [], "phones": [], "ipv4s": [], "crypto_wallets": [], "numeric_ids": [], "counts": {}, "total": 0},
                "intent_profile": {"top_intents": [], "max_similarity": 0.0},
                "dimensions": {}, "confidence": 0,
                "domain_intelligence": {"brand_impersonation": {"score": 0.0, "flags": [], "brands": []}, "best_link_host": None},
                "recommendations": [], "threat_fingerprint": None,
            }

        # Parallel: link tracing + entity extraction + intent profiling simultaneously
        with ThreadPoolExecutor(max_workers=3) as pool:
            future_links = pool.submit(self.trace_links, text)
            future_entities = pool.submit(self._extract_entities, text)
            future_intent = pool.submit(self._intent_profile, text)
            link_analysis = future_links.result()
            entities = future_entities.result()
            intent_profile = future_intent.result()

        extracted_links = [str(item.get("raw", "")) for item in link_analysis.get("links", []) if item.get("raw")]
        signals = self._extract_rule_signals(text) + self._nlp_signals(text, extracted_links=extracted_links, intent_profile=intent_profile)

        best_link = max(link_analysis.get("links", []) or [{}], key=lambda x: float(x.get("score", 0.0)), default={})
        target_host = str((best_link or {}).get("host", "")).lower()
        brand_intel = self._brand_impersonation_profile(text, target_host)
        if float(brand_intel.get("score", 0.0)) > 0:
            signals.append(Signal("intel::brand_impersonation", min(0.20, float(brand_intel["score"])), "Brand impersonation content-domain mismatch"))
        signals = self._dedupe_signals(signals)
        if link_analysis["total_links"] > 0:
            signals.append(Signal("intel::link_trace", min(0.28, float(link_analysis["aggregate_score"]) * 0.22),
                                  f"Traced {link_analysis['total_links']} link(s), {link_analysis['high_risk_links']} high-risk."))
        if entities.get("total", 0) > 0:
            signals.append(Signal("intel::sensitive_entity_presence", min(0.14, 0.03 + entities["total"] * 0.015),
                                  f"Detected {entities['total']} sensitive entity indicator(s)."))

        score_breakdown = self._score_from_evidence(signals, link_analysis)
        benign_reduction = self._benign_context_reduction(text, link_analysis)
        calibrated = max(0.0, float(score_breakdown["calibrated"]) - benign_reduction)
        score_breakdown.update({"benign_reduction": round(benign_reduction, 3), "final": round(calibrated, 3)})
        score_100 = int(round(calibrated * 100))

        level = "critical" if score_100 >= 84 else ("high" if score_100 >= 66 else ("medium" if score_100 >= 42 else "low"))
        dimensions = self._dimension_scores(signals, link_analysis, entities)
        confidence = self._confidence_score(score_100, len(signals), len(text))
        if level == "critical" and confidence < 78:
            level = "high"
        if level == "high" and confidence < 48:
            level = "medium"

        summary = ("No explicit fraud indicators found." if not signals
                   else "Top indicators: " + "; ".join(f"{x.name} ({x.score:.2f})" for x in sorted(signals, key=lambda s: s.score, reverse=True)[:3]))
        top_flags = self._dedupe_ordered([s.detail for s in sorted(signals, key=lambda s: s.score, reverse=True)])[:5]
        plain_verdicts = {
            "critical": "High probability of scam or malicious content. Block immediately.",
            "high": "Strong risk indicators found. Requires analyst verification.",
            "medium": "Suspicious patterns detected. Proceed with caution.",
            "low": "No major fraud signals detected.",
        }

        return {
            "score": score_100,
            "risk_level": level,
            "confidence": confidence,
            "score_breakdown": score_breakdown,
            "plain_verdict": plain_verdicts[level],
            "top_flags": top_flags,
            "signals": [{"name": s.name, "score": round(s.score, 3), "detail": s.detail} for s in signals],
            "summary": summary,
            "intent_profile": intent_profile,
            "dimensions": dimensions,
            "entities": entities,
            "link_analysis": link_analysis,
            "domain_intelligence": {"brand_impersonation": brand_intel, "best_link_host": target_host or None},
            "recommendations": self._recommendations(level, link_analysis, entities),
            "threat_fingerprint": hashlib.sha256(self._normalize(text).encode()).hexdigest()[:24],
        }

    # ──────────────────────────────────────────
    # Async wrappers for FastAPI async endpoints
    # ──────────────────────────────────────────
    async def analyze_async(self, text: str) -> Dict[str, object]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self.analyze, text)

    async def analyze_batch_async(self, texts: List[str]) -> List[Dict[str, object]]:
        loop = asyncio.get_event_loop()
        tasks = [loop.run_in_executor(self._executor, self.analyze, t) for t in texts]
        return await asyncio.gather(*tasks)

    # ──────────────────────────────────────────
    # Website tracer (unchanged logic, optimized I/O)
    # ──────────────────────────────────────────
    def _normalize_site_url(self, website_url: str) -> str:
        cleaned = website_url.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
            cleaned = f"https://{cleaned}"
        parsed = urlsplit(cleaned)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Only http/https URLs are supported.")
        if not parsed.netloc:
            raise ValueError("Invalid website URL.")
        return cleaned

    def _same_site(self, root_host: str, host: str) -> bool:
        return bool(host) and (host == root_host or host.endswith(f".{root_host}"))

    def _extract_html_links(self, html: str, base_url: str) -> List[str]:
        seen: Set[str] = set()
        unique: List[str] = []
        for href in self._re_href.findall(html):
            if href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            abs_url = urljoin(base_url, href).split("#")[0].strip()
            if not abs_url:
                continue
            if urlsplit(abs_url).scheme not in {"http", "https"}:
                continue
            if abs_url not in seen:
                seen.add(abs_url)
                unique.append(abs_url)
        return unique

    def _html_to_text(self, html: str) -> str:
        return self._re_multi_ws.sub(" ", self._re_tag_strip.sub(" ", self._re_style_strip.sub(" ", self._re_script_strip.sub(" ", html)))).strip()

    def _extract_title(self, html: str) -> str:
        m = self._re_title.search(html)
        return re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""

    def _format_cert_time(self, value: str) -> str:
        try:
            return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").strftime("%d %b %Y %H:%M")
        except Exception:
            return value

    def _flatten_cert_name(self, cert_name: object) -> str:
        out: List[str] = []
        if isinstance(cert_name, tuple):
            for rdn in cert_name:
                if isinstance(rdn, tuple):
                    for item in rdn:
                        if isinstance(item, tuple) and len(item) == 2:
                            out.append(str(item[1]))
        return ", ".join([x for x in out if x]) or "Unknown"

    def _fetch_certificate(self, host: str, port: int = 443) -> Dict[str, object]:
        cached = self._global_cert_cache.get(host)
        if cached is not None:
            return cached
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=2.5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            out = {
                "host": host,
                "subject": self._flatten_cert_name(cert.get("subject", ())),
                "issuer": self._flatten_cert_name(cert.get("issuer", ())),
                "valid_from": self._format_cert_time(str(cert.get("notBefore", ""))),
                "valid_to": self._format_cert_time(str(cert.get("notAfter", ""))),
                "status": "ok",
            }
        except Exception as exc:
            out = {"host": host, "subject": "Unknown", "issuer": "Unknown", "valid_from": "", "valid_to": "", "status": "error", "error": str(exc)[:180]}
        self._global_cert_cache.set(host, out)
        return out

    def _is_probable_asset(self, content_type: str, url: str) -> bool:
        ct = (content_type or "").lower()
        if any(x in ct for x in ["image/", "font/", "audio/", "video/", "application/octet-stream", "javascript", "text/css"]):
            return True
        return bool(self._re_asset_ext.search((urlsplit(url).path or "").lower()))

    def _extract_sitemap_urls(self, seed: str, seed_host: str) -> List[str]:
        cache_key = f"{seed_host}|{seed.rstrip('/')}"
        cached = self._global_sitemap_cache.get(cache_key)
        if cached is not None:
            return cached
        found: List[str] = []
        for sm_url in [urljoin(seed, p) for p in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"]]:
            try:
                req = Request(sm_url, headers={"User-Agent": "RiskIntelCrawler/3.0"})
                with urlopen(req, timeout=4) as resp:
                    raw = resp.read(600000).decode("utf-8", errors="ignore")
                for node in ElementTree.fromstring(raw).findall(".//{*}loc"):
                    if node.text and self._same_site(seed_host, (urlsplit(node.text.strip()).hostname or "").lower()):
                        found.append(node.text.strip())
            except Exception:
                continue
        dedup: List[str] = []
        seen: Set[str] = set()
        for u in found:
            k = u.rstrip("/")
            if k not in seen:
                seen.add(k)
                dedup.append(u)
        out = dedup[:400]
        self._global_sitemap_cache.set(cache_key, out)
        return out

    def _malware_signals_from_html(self, html: str, page_url: str) -> Dict[str, object]:
        flags: List[str] = []
        score = 0.0
        lowered = html.lower()
        if re.search(r"eval\s*\(", lowered):
            score += 0.12; flags.append("JavaScript eval() usage")
        if "fromcharcode" in lowered:
            score += 0.10; flags.append("String.fromCharCode obfuscation")
        if re.search(r"\batob\s*\(", lowered):
            score += 0.08; flags.append("Base64 decode atob()")
        if re.search(r"\bunescape\s*\(", lowered):
            score += 0.08; flags.append("unescape() obfuscation primitive")
        if re.search(r"document\.write\s*\(", lowered):
            score += 0.05; flags.append("document.write dynamic injection")
        if re.findall(r"[A-Za-z0-9+/]{200,}={0,2}", html):
            score += 0.14; flags.append("Large base64-encoded blob")
        if re.search(r"<iframe[^>]*(display\s*:\s*none|width\s*=\s*[\"']?0|height\s*=\s*[\"']?0)", lowered):
            score += 0.15; flags.append("Hidden iframe behavior")
        if re.search(r"(download=|application/(x-msdownload|octet-stream))", lowered):
            score += 0.18; flags.append("Executable download vector")
        suspicious_downloads = [href for href in self._extract_html_links(html, page_url)
                                  if re.search(r"\.[a-z0-9]{2,5}$", urlsplit(href).path.lower()) and
                                  re.search(r"\.[a-z0-9]{2,5}$", urlsplit(href).path.lower()).group(0) in self.suspicious_file_ext]
        if suspicious_downloads:
            score += min(0.25, 0.09 + len(suspicious_downloads) * 0.03)
            flags.append(f"Suspicious download links: {len(suspicious_downloads)}")

        score = min(1.0, max(0.0, score))
        verdict = "likely_malicious" if score >= 0.62 else ("suspicious" if score >= 0.36 else "no_strong_malware_signal")
        return {"score": round(score, 3), "verdict": verdict, "flags": flags[:10], "suspicious_downloads": suspicious_downloads[:20]}

    def trace_website(
        self,
        website_url: str,
        max_pages: int = 120,
        max_depth: int = 4,
        include_external: bool = False,
        exhaustive: bool = True,
    ) -> Dict[str, object]:
        seed = self._normalize_site_url(website_url)
        seed_host = (urlsplit(seed).hostname or "").lower()
        if not seed_host:
            raise ValueError("Unable to parse website hostname.")

        max_pages = max(1, min(max_pages, 500))
        max_depth = max(0, min(max_depth, 8))

        queue: deque = deque([(seed, 0, None)])
        queued: Set[str] = {seed.rstrip("/")}
        visited: Set[str] = set()
        page_reports: List[Dict[str, object]] = []
        discovered_hosts: Set[str] = set()
        discovered_internal_urls: Set[str] = {seed.rstrip("/")}
        https_hosts_seen: Set[str] = set()

        if exhaustive:
            for sm_url in self._extract_sitemap_urls(seed, seed_host):
                key = sm_url.rstrip("/")
                if key not in discovered_internal_urls:
                    discovered_internal_urls.add(key)
                    if key not in queued and key not in visited:
                        queue.append((sm_url, 0, "sitemap"))
                        queued.add(key)

        while queue and len(page_reports) < max_pages:
            current, depth, parent = queue.popleft()
            canonical = current.rstrip("/")
            if canonical in visited:
                continue
            visited.add(canonical)

            page_result: Dict[str, object] = {
                "url": current, "depth": depth, "parent": parent,
                "status": "error", "status_code": None, "title": "",
                "risk_level": "low", "score": 0, "summary": "",
                "link_counts": {"internal": 0, "external": 0}, "error": None,
            }

            try:
                req = Request(current, headers={"User-Agent": "RiskIntelCrawler/3.0"})
                with urlopen(req, timeout=8) as resp:
                    status_code = int(getattr(resp, "status", resp.getcode()))
                    content_type = str(resp.headers.get("Content-Type", ""))
                    final_url = str(getattr(resp, "url", current))
                    payload = resp.read(1200000)
                final_parts = urlsplit(final_url)
                if final_parts.scheme == "https" and final_parts.hostname:
                    https_hosts_seen.add(final_parts.hostname.lower())
                html = payload.decode("utf-8", errors="ignore")
                page_text = self._html_to_text(html)[:14000]
                title = self._extract_title(html)
                malware = self._malware_signals_from_html(html, final_url)
                is_asset = self._is_probable_asset(content_type, final_url)
                ai = {"risk_level": "low", "score": 0, "summary": "Static asset.", "threat_fingerprint": None} if is_asset else self.analyze(page_text)
                extracted_links = self._extract_html_links(html, current)
                internal_links: List[str] = []
                external_links: List[str] = []
                for link in extracted_links:
                    host = (urlsplit(link).hostname or "").lower()
                    if host:
                        discovered_hosts.add(host)
                    if self._same_site(seed_host, host):
                        internal_links.append(link)
                        discovered_internal_urls.add(link.rstrip("/"))
                    else:
                        external_links.append(link)

                page_result.update({
                    "status": "ok", "status_code": status_code, "final_url": final_url,
                    "content_type": content_type, "is_asset": is_asset, "title": title,
                    "risk_level": ai["risk_level"], "score": ai["score"], "summary": ai["summary"],
                    "malware_score": int(round(float(malware["score"]) * 100)),
                    "malware_verdict": malware["verdict"], "malware_flags": malware["flags"],
                    "suspicious_downloads": malware["suspicious_downloads"],
                    "threat_fingerprint": ai["threat_fingerprint"],
                    "link_counts": {"internal": len(internal_links), "external": len(external_links)},
                    "link_preview": {"internal": internal_links[:12], "external": external_links[:12]},
                })

                if depth < max_depth:
                    for nxt in internal_links:
                        key = nxt.rstrip("/")
                        if key not in visited and key not in queued:
                            queue.append((nxt, depth + 1, current))
                            queued.add(key)
                    if include_external:
                        for nxt in external_links:
                            key = nxt.rstrip("/")
                            if key not in visited and key not in queued:
                                queue.append((nxt, depth + 1, current))
                                queued.add(key)
            except Exception as exc:
                page_result["error"] = str(exc)[:220]

            page_reports.append(page_result)

        ok_pages = [p for p in page_reports if p["status"] == "ok"]
        business_ok_pages = [p for p in ok_pages if not p.get("is_asset")]
        asset_ok_pages = [p for p in ok_pages if p.get("is_asset")]
        failed_pages = [p for p in page_reports if p["status"] != "ok"]
        high_pages = [p for p in business_ok_pages if p["risk_level"] in {"high", "critical"}]
        medium_pages = [p for p in business_ok_pages if p["risk_level"] == "medium"]
        malware_suspicious = [p for p in business_ok_pages if p.get("malware_verdict") in {"suspicious", "likely_malicious"}]
        malware_likely = [p for p in business_ok_pages if p.get("malware_verdict") == "likely_malicious"]
        top_pages = sorted(business_ok_pages, key=lambda x: int(x["score"]), reverse=True)[:8]
        avg_score = int(round(sum(int(p["score"]) for p in business_ok_pages) / max(len(business_ok_pages), 1)))
        highest = int(max((int(p["score"]) for p in business_ok_pages), default=0))
        avg_malware = int(round(sum(int(p.get("malware_score", 0)) for p in business_ok_pages) / max(len(business_ok_pages), 1)))
        highest_malware = int(max((int(p.get("malware_score", 0)) for p in business_ok_pages), default=0))

        overall = ("critical" if highest >= 80 or len(high_pages) >= 3 or len(malware_likely) >= 1
                   else ("high" if highest >= 60 or len(high_pages) >= 1 or len(malware_suspicious) >= 2
                         else ("medium" if avg_score >= 35 or len(medium_pages) >= 2 else "low")))
        coverage = int(round((len(visited) / max(len(discovered_internal_urls), 1)) * 100))
        scam_likelihood = int(min(100, round((avg_score * 0.55) + (len(high_pages) * 6) + (len(medium_pages) * 2) + (highest * 0.12))))
        malware_likelihood = int(min(100, round((avg_malware * 0.65) + (highest_malware * 0.2) + (len(malware_likely) * 15) + (len(malware_suspicious) * 4))))
        final_site_verdict = ("likely_malicious" if scam_likelihood >= 70 or malware_likelihood >= 65 or overall == "critical"
                              else ("suspicious" if scam_likelihood >= 45 or malware_likelihood >= 40 or overall in {"high", "medium"} else "likely_safe"))

        recs = []
        if high_pages: recs.append("Block/monitor high-risk pages and enforce user click protection.")
        if malware_likely: recs.append("Malware behavior detected; isolate domain and sandbox artifacts.")
        if malware_suspicious and not malware_likely: recs.append("Suspicious script patterns; perform dynamic analysis before allowing access.")
        if failed_pages: recs.append("Review failed crawl targets; hidden paths may contain suspicious content.")
        if len(discovered_hosts) > 8: recs.append("High host diversity; investigate redirect/chaining behavior.")
        if coverage < 60: recs.append("Coverage limited; increase max_pages/max_depth for full trace.")
        recs += ["Enable scheduled recrawls for threat drift detection.", "Store crawl snapshots for historical analysis."]

        cert_hosts = sorted(https_hosts_seen)[:40]
        if cert_hosts:
            with ThreadPoolExecutor(max_workers=min(10, len(cert_hosts))) as ex:
                certificates = list(ex.map(self._fetch_certificate, cert_hosts))
        else:
            certificates = []

        return {
            "seed_url": seed, "scope_host": seed_host,
            "pages_crawled": len(page_reports), "pages_ok": len(ok_pages),
            "business_pages_scanned": len(business_ok_pages), "asset_pages_skipped": len(asset_ok_pages),
            "pages_failed": len(failed_pages), "coverage_percent": coverage,
            "risk_level": overall, "average_score": avg_score, "highest_score": highest,
            "high_risk_pages": len(high_pages), "medium_risk_pages": len(medium_pages),
            "malware_suspicious_pages": len(malware_suspicious), "malware_likely_pages": len(malware_likely),
            "average_malware_score": avg_malware, "highest_malware_score": highest_malware,
            "scam_likelihood": scam_likelihood, "malware_likelihood": malware_likelihood,
            "site_verdict": final_site_verdict,
            "discovered_host_count": len(discovered_hosts), "discovered_internal_urls": len(discovered_internal_urls),
            "certificates": certificates, "certificate_hosts_scanned": len(certificates),
            "certificate_hosts_ok": sum(1 for c in certificates if c.get("status") == "ok"),
            "top_risky_pages": [
                {"url": p["url"], "title": p.get("title", ""), "score": p["score"], "risk_level": p["risk_level"],
                 "malware_score": p.get("malware_score", 0), "malware_verdict": p.get("malware_verdict", "no_strong_malware_signal"),
                 "summary": p["summary"]} for p in top_pages
            ],
            "pages": page_reports,
            "recommendations": recs[:6],
        }


import asyncio
import hashlib
import ipaddress
import re
import socket
import ssl
import time
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from math import exp, sqrt
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlsplit
from urllib.request import Request, urlopen
from xml.etree import ElementTree
from datetime import datetime
import functools
import threading


# ─────────────────────────────────────────────
# TTL-aware thread-safe in-process cache
# ─────────────────────────────────────────────
class TTLCache:
    """Thread-safe LRU-style cache with per-entry TTL."""

    def __init__(self, maxsize: int = 4096, ttl: float = 3600.0) -> None:
        self._store: Dict[str, Tuple[Any, float]] = {}
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
                # Evict oldest 10%
                oldest = sorted(self._store.items(), key=lambda x: x[1][1])[: self._maxsize // 10]
                for k, _ in oldest:
                    del self._store[k]
            self._store[key] = (value, time.monotonic())

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        return len(self._store)


@dataclass(frozen=True)
class Signal:
    name: str
    score: float
    detail: str


# ─────────────────────────────────────────────
# Extended threat pattern library
# ─────────────────────────────────────────────
RULE_SETS: Dict[str, Dict[str, float]] = {
    "credential_theft": {
        r"\bverify (your )?(account|identity)\b": 0.18,
        r"\breset (your )?password\b": 0.16,
        r"\blogin immediately\b": 0.12,
        r"\bsecurity alert\b": 0.10,
        r"\baccount (suspended|locked|disabled)\b": 0.17,
        r"\bconfirm (your )?(credentials|login|email)\b": 0.15,
    },
    "financial_fraud": {
        r"\bwire transfer\b": 0.17,
        r"\bgift card\b": 0.18,
        r"\bcrypto( wallet| payment)?\b": 0.13,
        r"\bbank details\b": 0.14,
        r"\bpayment failed\b": 0.10,
        r"\bsend (the )?funds?\b": 0.16,
        r"\bbitcoin\b": 0.12,
        r"\bwestern union\b": 0.19,
        r"\bmoney gram\b": 0.18,
        r"\binvoice (overdue|past due)\b": 0.13,
    },
    "urgency_pressure": {
        r"\bwithin (\d+ )?(minutes?|hours?)\b": 0.10,
        r"\bact now\b": 0.14,
        r"\bfinal warning\b": 0.15,
        r"\bimmediate action required\b": 0.18,
        r"\bexpires? (today|tonight|in \d+)\b": 0.12,
        r"\blast chance\b": 0.13,
        r"\btime.sensitive\b": 0.11,
    },
    "social_engineering": {
        r"\bthis is (the )?ceo\b": 0.15,
        r"\bkeep this confidential\b": 0.17,
        r"\bdo not tell anyone\b": 0.16,
        r"\btrusted partner\b": 0.08,
        r"\bpersonal favor\b": 0.11,
        r"\bbetween (us|you and me)\b": 0.10,
        r"\bdon'?t (mention|share|discuss) this\b": 0.14,
    },
    "business_email_compromise": {
        r"\bkindly process\b": 0.13,
        r"\bapproved by management\b": 0.10,
        r"\bout of office\b": 0.08,
        r"\bvendor update\b": 0.12,
        r"\bnew (banking|payment) (details?|instructions?)\b": 0.19,
        r"\bchange (of )?account (details?|number)\b": 0.17,
        r"\bauthorized (by|from) (the )?(cfo|ceo|management)\b": 0.15,
    },
    "malware_delivery": {
        r"\bopen (the |this )?(attached?|file|document)\b": 0.13,
        r"\bdownload (and )?(install|run|execute)\b": 0.16,
        r"\benable (macro|content)\b": 0.18,
        r"\bclick (to |here to )?(view|access|download)\b": 0.12,
        r"\bupdate (required|needed|now)\b": 0.11,
    },
    "romance_scam": {
        r"\bsend (me )?money\b": 0.17,
        r"\bi (love|miss|need) you\b.*\b(send|transfer|help)\b": 0.16,
        r"\bstranded (abroad|overseas|at the airport)\b": 0.19,
        r"\bmedical emergency\b.*\bmoney\b": 0.18,
    },
    "lottery_scam": {
        r"\byou (have |'ve )?(won|been selected)\b": 0.16,
        r"\bclaim (your )?(prize|winnings?|reward)\b": 0.17,
        r"\blottery (winner|jackpot)\b": 0.18,
        r"\bunclaimed (funds?|prize)\b": 0.15,
    },
}

INTENT_PROTOTYPES: Dict[str, str] = {
    "phishing_credential_theft": "Your account is suspended. Verify identity and password now.",
    "invoice_or_wire_fraud": "Urgent transfer required to secure corporate payment channel.",
    "gift_card_scam": "Purchase gift cards immediately and send the claim codes.",
    "malicious_link_delivery": "Security warning: click link to avoid permanent account lock.",
    "executive_impersonation": "Confidential request from executive: process payment discreetly.",
    "bank_detail_tampering": "Update bank details now to prevent payroll disruption.",
    "malware_download": "Enable macros to view important document. Download and install update.",
    "romance_fraud": "I love you and need your help. Send money urgently.",
    "lottery_fraud": "You have won a prize. Claim your lottery winnings now.",
    "advance_fee_fraud": "Transfer fee required to release inheritance funds to your account.",
}


class RiskEngine:
    """
    Hybrid fraud detection engine — deterministic rules + NLP cosine similarity.
    v3: async-ready, parallel link tracing, TTL caches, extended rule library.
    """

    _global_link_cache = TTLCache(maxsize=8192, ttl=1800.0)
    _global_whois_cache = TTLCache(maxsize=2048, ttl=7200.0)
    _global_domain_cache = TTLCache(maxsize=4096, ttl=3600.0)
    _global_cert_cache = TTLCache(maxsize=1024, ttl=3600.0)
    _global_sitemap_cache = TTLCache(maxsize=512, ttl=1800.0)

    def __init__(self) -> None:
        self.rule_sets = RULE_SETS
        self.intent_prototypes = INTENT_PROTOTYPES
        self.prototype_vectors = {
            intent:         self._vectorize(self._normalize(text))
            for intent, text in self.intent_prototypes.items()
        }
        self.high_risk_terms = {
            "password", "otp", "bank", "transfer", "wallet", "payment", "urgent",
            "verify", "confidential", "gift", "card", "crypto", "pin", "credential",
            "click", "link", "bitcoin", "invoice", "wire", "lottery", "prize",
            "winner", "inheritance", "claim", "fund", "release",
        }
        self.shortener_domains = {
            "bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd", "goo.gl",
            "ow.ly", "shorturl.at", "cutt.ly", "rebrand.ly", "tiny.cc",
            "snip.ly", "bl.ink", "short.io",
        }
        self.suspicious_tlds = {
            "zip", "mov", "top", "gq", "tk", "work", "click", "cam", "rest",
            "country", "stream", "xyz", "pw", "cc", "biz", "info",
        }
        self.sensitive_query_keys = {"url", "redirect", "next", "target", "dest", "continue", "return", "goto"}
        self.suspicious_file_ext = {".exe", ".msi", ".bat", ".cmd", ".scr", ".js", ".vbs", ".jar", ".ps1", ".hta", ".pif"}
        self.link_risk_terms = {"login", "verify", "secure", "wallet", "bank", "password", "update", "payment", "signin", "account"}
        self.reputation_risky_terms = {
            "secure", "verify", "update", "wallet", "login", "account",
            "signin", "support", "billing", "payment", "confirm", "auth",
        }
        self.known_brands = {
            "google", "microsoft", "apple", "amazon", "paypal", "netflix",
            "facebook", "instagram", "whatsapp", "linkedin", "github",
            "dropbox", "twitter", "x", "bankofamerica", "chase", "wellsfargo",
            "citibank", "outlook", "office365", "youtube", "tiktok", "coinbase",
            "binance", "kraken", "robinhood", "stripe", "shopify",
        }
        self.brand_text_terms = {
            "google", "microsoft", "apple", "amazon", "paypal", "netflix",
            "facebook", "instagram", "linkedin", "github", "outlook", "office365",
            "bank of america", "wells fargo", "citi", "chase bank", "youtube",
            "tiktok", "coinbase", "binance",
        }
        self.typo_homograph_map = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})

        # Pre-compiled regex patterns
        self._re_url_scheme = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
        self._re_link_pattern = re.compile(r"(?:(?:https?|ftp)://|www\.)[^\s<>'\"()]+", flags=re.IGNORECASE)
        self._re_asset_ext = re.compile(r"\.(png|jpg|jpeg|gif|svg|ico|webp|woff2?|ttf|eot|css|js|map|mp4|mp3|pdf)$")
        self._re_title = re.compile(r"<title[^>]*>(.*?)</title>", flags=re.IGNORECASE | re.DOTALL)
        self._re_href = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', flags=re.IGNORECASE)
        self._re_tag_strip = re.compile(r"<[^>]+>")
        self._re_script_strip = re.compile(r"<script[\s\S]*?</script>", flags=re.IGNORECASE)
        self._re_style_strip = re.compile(r"<style[\s\S]*?</style>", flags=re.IGNORECASE)
        self._re_multi_ws = re.compile(r"\s+")
        self._re_obfuscated_link = re.compile(r"hxxps?://|\[\.\]|\(\.\)")
        self._re_repeated_chars = re.compile(r"(.)\1{5,}")
        self._re_currency = re.compile(r"\$\d+|\b\d{2,}(?:,\d{3})*(?:\.\d+)?\b")
        self._re_caps = re.compile(r"\b[A-Z]{3,}\b")
        self._re_exec_ext = re.compile(r"\.[a-zA-Z0-9]{2,5}$")
        self._re_whois_date = re.compile(r"(20\d{2})[-/](\d{1,2})[-/](\d{1,2})")

        # Compile rule sets once
        self._rule_sets_compiled: Dict[str, List[Tuple[re.Pattern, float, str]]] = {}
        for category, patterns in self.rule_sets.items():
            self._rule_sets_compiled[category] = [
                (re.compile(pat, re.IGNORECASE), weight, pat)
                for pat, weight in patterns.items()
            ]

        # Thread pool for parallel I/O (link tracing, cert checks, WHOIS)
        self._executor = ThreadPoolExecutor(max_workers=20, thread_name_prefix="riskintel")
        
    # ──────────────────────────────────────────
    # Core NLP helpers
    # ──────────────────────────────────────────
    def _normalize(self, text: str) -> str:
        return self._re_multi_ws.sub(" ", text.strip().lower())

    def _deobfuscate_links_text(self, text: str) -> str:
        return (
            text.replace("[.]", ".").replace("(.)", ".")
            .replace("hxxp://", "http://").replace("hxxps://", "https://")
        )

    def _tokenize(self, text: str) -> List[str]:
        return re.findall(r"[a-zA-Z0-9']+", text)

    def _vectorize(self, text: str) -> Counter:
        tokens = self._tokenize(text)
        if len(tokens) < 2:
            return Counter(tokens)
        bigrams = [f"{tokens[i]}_{tokens[i+1]}" for i in range(len(tokens) - 1)]
        return Counter(tokens + bigrams)

    def _cosine(self, a: Counter, b: Counter) -> float:
        if not a or not b:
            return 0.0
        dot = sum(a[k] * b.get(k, 0) for k in a)
        norm_a = sqrt(sum(v * v for v in a.values()))
        norm_b = sqrt(sum(v * v for v in b.values()))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def _extract_links(self, text: str) -> List[str]:
        candidate_text = self._deobfuscate_links_text(text)
        links = self._re_link_pattern.findall(candidate_text)
        seen: Set[str] = set()
        unique: List[str] = []
        for link in links:
            normalized = link.strip(".,);]}>\"'")
            low = normalized.lower()
            if normalized and low not in seen:
                seen.add(low)
                unique.append(normalized)
        return unique

    @staticmethod
    def _effective_domain(hostname: str) -> str:
        parts = [p for p in hostname.split(".") if p]
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname

    @staticmethod
    def _sld(hostname: str) -> str:
        parts = [p for p in hostname.split(".") if p]
        return parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")

    @staticmethod
    def _levenshtein(a: str, b: str) -> int:
        if a == b:
            return 0
        if not a:
            return len(b)
        if not b:
            return len(a)
        if len(a) < len(b):
            a, b = b, a
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, start=1):
            cur = [i]
            for j, cb in enumerate(b, start=1):
                cur.append(min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + (0 if ca == cb else 1)))
            prev = cur
        return prev[-1]

    # ──────────────────────────────────────────
    # Domain intelligence (with global TTL caches)
    # ──────────────────────────────────────────
    def _domain_reputation_profile(self, hostname: str) -> Dict[str, object]:
        host = (hostname or "").strip().lower()
        if not host:
            return {"score": 0.0, "flags": [], "category": "unknown"}
        cached = self._global_domain_cache.get(host)
        if cached is not None:
            return cached

        score = 0.0
        flags: List[str] = []
        sld = self._sld(host)
        digits = sum(ch.isdigit() for ch in sld)
        hyphens = sld.count("-")
        alpha = sum(ch.isalpha() for ch in sld)
        entropy_like = len(set(sld)) / max(len(sld), 1)
        risky_term_hits = [term for term in self.reputation_risky_terms if term in host]
        tld = host.rsplit(".", 1)[-1] if "." in host else ""

        if digits >= 3:
            score += 0.07; flags.append("Heavy numeric usage in domain")
        if hyphens >= 2:
            score += 0.08; flags.append("Multiple hyphens in domain")
        if len(sld) >= 22:
            score += 0.08; flags.append("Very long second-level domain")
        if entropy_like > 0.82 and len(sld) >= 10 and alpha >= 6:
            score += 0.06; flags.append("High-randomness domain label")
        if risky_term_hits:
            score += min(0.15, 0.04 * len(risky_term_hits))
            flags.append(f"Risky terms in domain: {', '.join(sorted(set(risky_term_hits)))}")
        if tld in self.suspicious_tlds:
            score += 0.10; flags.append(f"Suspicious TLD .{tld}")

        category = "poor" if score >= 0.45 else ("questionable" if score >= 0.25 else "neutral")
        out = {"score": round(min(1.0, score), 3), "flags": flags[:8], "category": category}
        self._global_domain_cache.set(host, out)
        return out

    def _brand_impersonation_profile(self, text: str, hostname: str) -> Dict[str, object]:
        norm = self._normalize(text)
        host = (hostname or "").lower()
        hits = [b for b in self.brand_text_terms if b in norm]
        if not hits:
            return {"score": 0.0, "flags": [], "brands": []}
        effective = self._effective_domain(host)
        flags: List[str] = []
        score = 0.0
        brands: List[str] = []
        for b in hits:
            token = re.sub(r"[^a-z0-9]", "", b.lower())
            if not token:
                continue
            brands.append(b)
            if token not in effective:
                score += 0.07
                flags.append(f"Brand '{b}' mismatches destination domain")
        if len(set(brands)) >= 2:
            score += 0.05; flags.append("Multiple brand references")
        return {"score": round(min(0.35, score), 3), "flags": flags[:8], "brands": sorted(set(brands))[:8]}

    def _typosquat_profile(self, hostname: str) -> Dict[str, object]:
        host = (hostname or "").strip().lower()
        if not host:
            return {"score": 0.0, "flags": [], "closest_brand": None}
        sld = self._sld(host)
        normalized = sld.translate(self.typo_homograph_map)
        if len(normalized) < 3:
            return {"score": 0.0, "flags": [], "closest_brand": None}

        best_brand: Optional[str] = None
        best_dist = 99
        for brand in self.known_brands:
            dist = self._levenshtein(normalized, brand)
            if dist < best_dist:
                best_dist = dist
                best_brand = brand

        score = 0.0
        flags: List[str] = []
        if best_brand and normalized != best_brand:
            if best_dist == 1:
                score += 0.26; flags.append(f"Likely typosquat of '{best_brand}' (edit distance 1)")
            elif best_dist == 2 and len(best_brand) >= 6:
                score += 0.17; flags.append(f"Possible typosquat of '{best_brand}' (edit distance 2)")
        if best_brand and best_brand in normalized and normalized != best_brand:
            extra = normalized.replace(best_brand, "")
            if len(extra) >= 3:
                score += 0.09; flags.append(f"Brand '{best_brand}' embedded with deceptive token")
        return {"score": round(min(0.4, score), 3), "flags": flags[:8], "closest_brand": best_brand}

    def _whois_domain_age_profile(self, hostname: str) -> Dict[str, object]:
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
        status = "unavailable"
        rdap_url = f"https://rdap.org/domain/{root}"
        try:
            req = Request(rdap_url, headers={"User-Agent": "RiskIntel/3.0", "Accept": "application/rdap+json"})
            with urlopen(req, timeout=2.5) as resp:
                payload = resp.read(240000).decode("utf-8", errors="ignore")
            m = self._re_whois_date.search(payload)
            if m:
                year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
                created = datetime(year=year, month=max(1, min(month, 12)), day=max(1, min(day, 28)))
                age_days = max(0, (datetime.utcnow() - created).days)
                status = "ok"
        except Exception:
            status = "unavailable"

        if age_days is not None:
            if age_days < 30:
                score += 0.23; flags.append("Very new domain (<30 days)")
            elif age_days < 90:
                score += 0.16; flags.append("Recently registered (<90 days)")
            elif age_days < 180:
                score += 0.10; flags.append("Young domain (<180 days)")

        out = {"score": round(min(0.3, score), 3), "flags": flags, "age_days": age_days, "status": status}
        self._global_whois_cache.set(host, out)
        return out

    # ──────────────────────────────────────────
    # Link tracing (parallel via thread pool)
    # ──────────────────────────────────────────
    def _trace_single_link(self, raw_link: str) -> Dict[str, object]:
        key = raw_link.strip().lower()
        cached = self._global_link_cache.get(key)
        if cached is not None:
            return cached

        working = raw_link if self._re_url_scheme.match(raw_link) else f"http://{raw_link}"
        parsed = urlsplit(working)
        hostname = (parsed.hostname or "").strip().lower()
        path = parsed.path or ""
        query = parsed.query or ""

        score = 0.0
        flags: List[str] = []

        if parsed.scheme == "http":
            score += 0.10; flags.append("Unencrypted HTTP scheme")
        if "@" in parsed.netloc:
            score += 0.15; flags.append("Credentials in URL (user-info)")
        if hostname in self.shortener_domains:
            score += 0.16; flags.append("Known URL shortener")
        if hostname.startswith("xn--") or ".xn--" in hostname:
            score += 0.12; flags.append("Punycode/IDN domain spoofing risk")
        if any(ord(ch) > 127 for ch in hostname):
            score += 0.10; flags.append("Non-ASCII domain characters")

        subdomain_depth = max(0, len(hostname.split(".")) - 2)
        if subdomain_depth >= 3:
            score += 0.08; flags.append("Deep subdomain chain")
        if len(working) > 140:
            score += 0.08; flags.append("Excessive URL length")
        if parsed.port and parsed.port not in {80, 443}:
            score += 0.08; flags.append(f"Non-standard port {parsed.port}")

        last_dot = hostname.rfind(".")
        tld = hostname[last_dot + 1:] if last_dot > -1 else ""
        if tld in self.suspicious_tlds:
            score += 0.14; flags.append(f"Suspicious TLD .{tld}")

        lower_full = f"{hostname}{path}?{query}".lower()
        keyword_hits = [k for k in self.link_risk_terms if k in lower_full]
        if keyword_hits:
            score += min(0.12, 0.03 * len(keyword_hits))
            flags.append(f"Risk keywords in URL: {', '.join(sorted(set(keyword_hits)))}")

        ext_match = self._re_exec_ext.search(path.lower())
        if ext_match and ext_match.group(0) in self.suspicious_file_ext:
            score += 0.20; flags.append(f"Executable/script extension {ext_match.group(0)}")

        encoded_ratio = working.count("%") / max(len(working), 1)
        if encoded_ratio > 0.03 or working.count("%") >= 4:
            score += 0.07; flags.append("Heavy URL percent-encoding")

        query_map = parse_qs(query, keep_blank_values=True)
        redirect_keys = [k for k in query_map if k.lower() in self.sensitive_query_keys]
        if redirect_keys:
            score += 0.12; flags.append(f"Open redirect parameters: {', '.join(sorted(redirect_keys))}")

        ip_label = ip_type = None
        if hostname:
            try:
                ip_obj = ipaddress.ip_address(hostname)
                ip_label = str(ip_obj)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    score += 0.10; ip_type = "private/local"; flags.append("Private/local IP host")
                else:
                    score += 0.07; ip_type = "public"; flags.append("Direct IP instead of domain")
            except ValueError:
                pass

        reputation = self._domain_reputation_profile(hostname)
        typo = self._typosquat_profile(hostname)
        whois_age = self._whois_domain_age_profile(hostname)
        score += min(0.18, float(reputation.get("score", 0.0)) * 0.7)
        flags.extend(list(reputation.get("flags", []))[:2])
        score += min(0.20, float(typo.get("score", 0.0)) * 0.9)
        flags.extend(list(typo.get("flags", []))[:2])
        score += min(0.12, float(whois_age.get("score", 0.0)) * 0.8)
        flags.extend(list(whois_age.get("flags", []))[:1])

        score = min(1.0, max(0.0, score))
        verdict = "critical" if score >= 0.65 else ("high" if score >= 0.45 else ("medium" if score >= 0.25 else "low"))

        out = {
            "raw": raw_link,
            "normalized": working,
            "scheme": parsed.scheme,
            "host": hostname,
            "port": parsed.port,
            "path": path,
            "query_keys": sorted(query_map.keys()),
            "ip": ip_label,
            "ip_type": ip_type,
            "score": round(score, 3),
            "verdict": verdict,
            "flags": self._dedupe_ordered(flags)[:12],
            "domain_intelligence": {
                "domain_reputation": reputation,
                "typosquatting": typo,
                "whois_age": whois_age,
            },
        }
        self._global_link_cache.set(key, out)
        return out

    def trace_links(self, text: str) -> Dict[str, object]:
        links = self._extract_links(text)
        if not links:
            return {"total_links": 0, "high_risk_links": 0, "medium_risk_links": 0, "aggregate_score": 0.0, "links": []}

        # Parallel link tracing
        futures = {self._executor.submit(self._trace_single_link, link): link for link in links}
        traced: List[Dict[str, object]] = []
        for future in as_completed(futures):
            try:
                traced.append(future.result(timeout=6.0))
            except Exception:
                pass

        high_count = sum(1 for x in traced if x["verdict"] in {"high", "critical"})
        med_count = sum(1 for x in traced if x["verdict"] == "medium")
        total_score = round(sum(float(x["score"]) for x in traced), 3)
        return {
            "total_links": len(traced),
            "high_risk_links": high_count,
            "medium_risk_links": med_count,
            "aggregate_score": total_score,
            "links": sorted(traced, key=lambda x: float(x["score"]), reverse=True),
        }

    # ──────────────────────────────────────────
    # Entity extraction
    # ──────────────────────────────────────────
    def _extract_entities(self, text: str) -> Dict[str, object]:
        emails = re.findall(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", text)
        phones = re.findall(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)\d{3,4}[-.\s]?\d{3,4}\b", text)
        ipv4s = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        crypto_wallets = re.findall(r"\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", text)
        long_numeric_ids = re.findall(r"\b\d{10,18}\b", text)
        cvv_pattern = re.findall(r"\b\d{3,4}\b", text)  # light card CVV indicator
        entities = {
            "emails": sorted(set(emails))[:12],
            "phones": sorted(set(phones))[:12],
            "ipv4s": sorted(set(ipv4s))[:12],
            "crypto_wallets": sorted(set(crypto_wallets))[:12],
            "numeric_ids": sorted(set(long_numeric_ids))[:12],
        }
        entities["counts"] = {k: len(v) for k, v in entities.items() if isinstance(v, list)}
        entities["total"] = sum(entities["counts"].values())
        return entities

    # ──────────────────────────────────────────
    # Intent profiling
    # ──────────────────────────────────────────
    def _intent_profile(self, text: str) -> Dict[str, object]:
        norm = self._normalize(text)
        query_vector =         self._vectorize(norm)
        intent_scores = [
            {"intent": intent, "similarity": round(self._cosine(query_vector, proto), 3)}
            for intent, proto in self.prototype_vectors.items()
        ]
        top_intents = sorted(intent_scores, key=lambda x: x["similarity"], reverse=True)[:3]
        return {"top_intents": top_intents, "max_similarity": top_intents[0]["similarity"] if top_intents else 0.0}

    # ──────────────────────────────────────────
    # Signal extraction
    # ──────────────────────────────────────────
    def _extract_rule_signals(self, text: str) -> List[Signal]:
        norm = self._normalize(text)
        signals: List[Signal] = []
        for category, patterns in self._rule_sets_compiled.items():
            cat_hits: List[Tuple[str, float]] = []
            for compiled, weight, raw_pattern in patterns:
                if compiled.search(norm):
                    cat_hits.append((raw_pattern, weight))
            if not cat_hits:
                continue
            cat_hits.sort(key=lambda x: x[1], reverse=True)
            cat_score = sum(w * (1.0 if i == 0 else (0.62 if i == 1 else 0.30)) for i, (_, w) in enumerate(cat_hits))
            cat_score = min(0.28, cat_score)
            signals.append(Signal(
                name=f"rule::{category}",
                score=cat_score,
                detail=f"Matched {len(cat_hits)} pattern(s) in {category}; strongest '{cat_hits[0][0]}'.",
            ))
        return signals

    def _nlp_signals(
        self,
        text: str,
        extracted_links: Optional[List[str]] = None,
        intent_profile: Optional[Dict[str, object]] = None,
    ) -> List[Signal]:
        norm = self._normalize(text)
        words = self._tokenize(norm)
        total_words = max(len(words), 1)
        high_risk_hits = sum(1 for w in words if w in self.high_risk_terms)
        risk_density = high_risk_hits / total_words
        exclamations = text.count("!")
        caps_words = self._re_caps.findall(text)
        link_hits = len(extracted_links) if extracted_links is not None else len(self._extract_links(text))
        currency_hits = len(self._re_currency.findall(text))
        obfuscated_hits = len(self._re_obfuscated_link.findall(text.lower()))
        profile = intent_profile if intent_profile is not None else self._intent_profile(text)
        sim = float(profile["max_similarity"])

        signals: List[Signal] = []
        if risk_density > 0.08:
            signals.append(Signal("nlp::risk_term_density", min(0.18, risk_density * 1.4), f"High-risk term density {risk_density:.2f}"))
        if sim > 0.25:
            signals.append(Signal("nlp::intent_similarity", min(0.25, sim * 0.55), f"Fraud intent similarity {sim:.2f}"))
        if exclamations >= 3:
            signals.append(Signal("nlp::pressure_tone", min(0.08, exclamations * 0.02), f"{exclamations} exclamation marks"))
        if len(caps_words) >= 2:
            signals.append(Signal("nlp::aggressive_caps", 0.07, "Multiple ALL-CAPS tokens"))
        if link_hits > 0:
            signals.append(Signal("nlp::external_link", min(0.10, 0.05 + 0.02 * link_hits), f"{link_hits} external link(s)"))
        if currency_hits > 0:
            signals.append(Signal("nlp::money_reference", min(0.09, 0.03 + currency_hits * 0.02), f"{currency_hits} currency indicator(s)"))
        if obfuscated_hits > 0:
            signals.append(Signal("nlp::link_obfuscation", min(0.16, 0.06 + obfuscated_hits * 0.03), f"{obfuscated_hits} obfuscated link(s)"))
        if self._re_repeated_chars.search(text):
            signals.append(Signal("nlp::pattern_anomaly", 0.06, "Repeated-character pattern anomaly"))
        return signals

    # ──────────────────────────────────────────
    # Score synthesis
    # ──────────────────────────────────────────
    def _score_from_evidence(self, signals: List[Signal], link_analysis: Dict[str, object]) -> Dict[str, float]:
        rule_sum = nlp_sum = intel_sum = 0.0
        signal_names = [s.name for s in signals]
        for s in signals:
            if s.name.startswith("rule::"):
                rule_sum += s.score
            elif s.name.startswith("nlp::"):
                nlp_sum += s.score
            else:
                intel_sum += s.score

        rule_capped = min(0.56, rule_sum)
        nlp_capped = min(0.34, nlp_sum)
        intel_capped = min(0.24, intel_sum)
        raw_capped = rule_capped + nlp_capped + intel_capped

        fusion_boost = 0.0
        if rule_capped > 0.25 and nlp_capped > 0.14:
            fusion_boost += 0.06
        if int(link_analysis.get("high_risk_links", 0)) > 0 and (
            "nlp::link_obfuscation" in signal_names or intel_capped > 0.08
        ):
            fusion_boost += 0.05
        if "rule::financial_fraud" in signal_names and "rule::social_engineering" in signal_names:
            fusion_boost += 0.04
        if "nlp::intent_similarity" in signal_names and nlp_capped > 0.18:
            fusion_boost += 0.03

        blended = min(1.0, raw_capped + fusion_boost)
        calibrated = min(0.96, max(0.0, 1.0 - exp(-1.45 * blended)))
        return {
            "rule": round(rule_capped, 3),
            "nlp": round(nlp_capped, 3),
            "intel": round(intel_capped, 3),
            "fusion": round(fusion_boost, 3),
            "raw": round(blended, 3),
            "calibrated": round(calibrated, 3),
        }

    def _dimension_scores(self, signals: List[Signal], link_analysis: Dict, entities: Dict) -> Dict[str, int]:
        dims = {k: 0.0 for k in ("credential_theft", "financial_fraud", "social_engineering", "coercion_pressure", "link_abuse", "data_exposure")}
        for s in signals:
            n = s.name
            if "credential" in n or "password" in s.detail.lower():
                dims["credential_theft"] += s.score * 120
            if "financial" in n or "money" in n or "payment" in s.detail.lower():
                dims["financial_fraud"] += s.score * 120
            if "social_engineering" in n or "impersonation" in n:
                dims["social_engineering"] += s.score * 120
            if "urgency" in n or "pressure" in n or "aggressive_caps" in n:
                dims["coercion_pressure"] += s.score * 110
            if "link" in n:
                dims["link_abuse"] += s.score * 140
        dims["link_abuse"] += float(link_analysis.get("aggregate_score", 0.0)) * 45
        dims["link_abuse"] += int(link_analysis.get("high_risk_links", 0)) * 10
        entity_counts = entities.get("counts", {})
        dims["data_exposure"] += entity_counts.get("emails", 0) * 8
        dims["data_exposure"] += entity_counts.get("phones", 0) * 6
        dims["data_exposure"] += entity_counts.get("numeric_ids", 0) * 5
        dims["financial_fraud"] += entity_counts.get("crypto_wallets", 0) * 10
        return {k: min(100, int(round(v))) for k, v in dims.items()}

    def _confidence_score(self, score_100: int, signal_count: int, text_length: int) -> int:
        confidence = (score_100 / 100) * 0.6 + min(0.25, signal_count * 0.03) + min(0.15, text_length / 1400)
        return min(99, max(10, int(round(confidence * 100))))

    def _recommendations(self, risk_level: str, link_analysis: Dict, entities: Dict) -> List[str]:
        recs: List[str] = []
        if risk_level in {"high", "critical"}:
            recs.append("Immediately isolate this message and trigger analyst review.")
            recs.append("Block detected URLs/domains at email gateway, DNS, and proxy controls.")
        if int(link_analysis.get("high_risk_links", 0)) > 0:
            recs.append("Perform safe detonation/sandboxing for all extracted links.")
        if entities.get("counts", {}).get("crypto_wallets", 0):
            recs.append("Escalate to financial fraud — cryptocurrency transfer indicators found.")
        if entities.get("counts", {}).get("numeric_ids", 0):
            recs.append("Mask sensitive numeric identifiers and open data-exposure case.")
        if risk_level in {"low", "medium"}:
            recs.append("Keep under monitoring; auto-recheck on repeated sender patterns.")
        recs.append("Preserve message headers and metadata for forensic correlation.")
        return recs[:6]

    @staticmethod
    def _dedupe_ordered(items: List[str]) -> List[str]:
        seen: Set[str] = set()
        return [item for item in items if item.strip() and not (item.strip() in seen or seen.add(item.strip()))]

    def _dedupe_signals(self, signals: List[Signal]) -> List[Signal]:
        best: Dict[Tuple[str, str], Signal] = {}
        for sig in signals:
            key = (sig.name, sig.detail)
            if key not in best or sig.score > best[key].score:
                best[key] = sig
        return list(best.values())

    def _benign_context_reduction(self, text: str, link_analysis: Dict) -> float:
        norm = self._normalize(text)
        benign_terms = {"meeting", "agenda", "minutes", "calendar", "schedule", "review", "draft", "notes", "thanks", "regards", "tomorrow", "team", "update"}
        tokens = set(self._tokenize(norm))
        benign_hits = len(tokens.intersection(benign_terms))
        risky_links = int(link_analysis.get("high_risk_links", 0)) + int(link_analysis.get("medium_risk_links", 0))
        if benign_hits < 3 or risky_links > 0:
            return 0.0
        return min(0.12, 0.02 * (benign_hits - 2))

    # ──────────────────────────────────────────
    # Main analyze entry point
    # ──────────────────────────────────────────
    def analyze(self, text: str) -> Dict[str, object]:
        if not text or not text.strip():
            return {
                "score": 0, "risk_level": "low", "plain_verdict": "No content to analyze.",
                "top_flags": [], "signals": [], "summary": "No content provided.",
                "link_analysis": {"total_links": 0, "high_risk_links": 0, "medium_risk_links": 0, "aggregate_score": 0.0, "links": []},
                "entities": {"emails": [], "phones": [], "ipv4s": [], "crypto_wallets": [], "numeric_ids": [], "counts": {}, "total": 0},
                "intent_profile": {"top_intents": [], "max_similarity": 0.0},
                "dimensions": {}, "confidence": 0,
                "domain_intelligence": {"brand_impersonation": {"score": 0.0, "flags": [], "brands": []}, "best_link_host": None},
                "recommendations": [], "threat_fingerprint": None,
            }

        # Parallel: link tracing + entity extraction + intent profiling simultaneously
        with ThreadPoolExecutor(max_workers=3) as pool:
            future_links = pool.submit(self.trace_links, text)
            future_entities = pool.submit(self._extract_entities, text)
            future_intent = pool.submit(self._intent_profile, text)
            link_analysis = future_links.result()
            entities = future_entities.result()
            intent_profile = future_intent.result()

        extracted_links = [str(item.get("raw", "")) for item in link_analysis.get("links", []) if item.get("raw")]
        signals = self._extract_rule_signals(text) + self._nlp_signals(text, extracted_links=extracted_links, intent_profile=intent_profile)

        best_link = max(link_analysis.get("links", []) or [{}], key=lambda x: float(x.get("score", 0.0)), default={})
        target_host = str((best_link or {}).get("host", "")).lower()
        brand_intel = self._brand_impersonation_profile(text, target_host)
        if float(brand_intel.get("score", 0.0)) > 0:
            signals.append(Signal("intel::brand_impersonation", min(0.20, float(brand_intel["score"])), "Brand impersonation content-domain mismatch"))
        signals = self._dedupe_signals(signals)
        if link_analysis["total_links"] > 0:
            signals.append(Signal("intel::link_trace", min(0.28, float(link_analysis["aggregate_score"]) * 0.22),
                                  f"Traced {link_analysis['total_links']} link(s), {link_analysis['high_risk_links']} high-risk."))
        if entities.get("total", 0) > 0:
            signals.append(Signal("intel::sensitive_entity_presence", min(0.14, 0.03 + entities["total"] * 0.015),
                                  f"Detected {entities['total']} sensitive entity indicator(s)."))

        score_breakdown = self._score_from_evidence(signals, link_analysis)
        benign_reduction = self._benign_context_reduction(text, link_analysis)
        calibrated = max(0.0, float(score_breakdown["calibrated"]) - benign_reduction)
        score_breakdown.update({"benign_reduction": round(benign_reduction, 3), "final": round(calibrated, 3)})
        score_100 = int(round(calibrated * 100))

        level = "critical" if score_100 >= 84 else ("high" if score_100 >= 66 else ("medium" if score_100 >= 42 else "low"))
        dimensions = self._dimension_scores(signals, link_analysis, entities)
        confidence = self._confidence_score(score_100, len(signals), len(text))
        if level == "critical" and confidence < 78:
            level = "high"
        if level == "high" and confidence < 48:
            level = "medium"

        summary = ("No explicit fraud indicators found." if not signals
                   else "Top indicators: " + "; ".join(f"{x.name} ({x.score:.2f})" for x in sorted(signals, key=lambda s: s.score, reverse=True)[:3]))
        top_flags = self._dedupe_ordered([s.detail for s in sorted(signals, key=lambda s: s.score, reverse=True)])[:5]
        plain_verdicts = {
            "critical": "High probability of scam or malicious content. Block immediately.",
            "high": "Strong risk indicators found. Requires analyst verification.",
            "medium": "Suspicious patterns detected. Proceed with caution.",
            "low": "No major fraud signals detected.",
        }

        return {
            "score": score_100,
            "risk_level": level,
            "confidence": confidence,
            "score_breakdown": score_breakdown,
            "plain_verdict": plain_verdicts[level],
            "top_flags": top_flags,
            "signals": [{"name": s.name, "score": round(s.score, 3), "detail": s.detail} for s in signals],
            "summary": summary,
            "intent_profile": intent_profile,
            "dimensions": dimensions,
            "entities": entities,
            "link_analysis": link_analysis,
            "domain_intelligence": {"brand_impersonation": brand_intel, "best_link_host": target_host or None},
            "recommendations": self._recommendations(level, link_analysis, entities),
            "threat_fingerprint": hashlib.sha256(self._normalize(text).encode()).hexdigest()[:24],
        }

    # ──────────────────────────────────────────
    # Async wrappers for FastAPI async endpoints
    # ──────────────────────────────────────────
    async def analyze_async(self, text: str) -> Dict[str, object]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self.analyze, text)

    async def analyze_batch_async(self, texts: List[str]) -> List[Dict[str, object]]:
        loop = asyncio.get_event_loop()
        tasks = [loop.run_in_executor(self._executor, self.analyze, t) for t in texts]
        return await asyncio.gather(*tasks)

    # ──────────────────────────────────────────
    # Website tracer (unchanged logic, optimized I/O)
    # ──────────────────────────────────────────
    def _normalize_site_url(self, website_url: str) -> str:
        cleaned = website_url.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
            cleaned = f"https://{cleaned}"
        parsed = urlsplit(cleaned)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Only http/https URLs are supported.")
        if not parsed.netloc:
            raise ValueError("Invalid website URL.")
        return cleaned

    def _same_site(self, root_host: str, host: str) -> bool:
        return bool(host) and (host == root_host or host.endswith(f".{root_host}"))

    def _extract_html_links(self, html: str, base_url: str) -> List[str]:
        seen: Set[str] = set()
        unique: List[str] = []
        for href in self._re_href.findall(html):
            if href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            abs_url = urljoin(base_url, href).split("#")[0].strip()
            if not abs_url:
                continue
            if urlsplit(abs_url).scheme not in {"http", "https"}:
                continue
            if abs_url not in seen:
                seen.add(abs_url)
                unique.append(abs_url)
        return unique

    def _html_to_text(self, html: str) -> str:
        return self._re_multi_ws.sub(" ", self._re_tag_strip.sub(" ", self._re_style_strip.sub(" ", self._re_script_strip.sub(" ", html)))).strip()

    def _extract_title(self, html: str) -> str:
        m = self._re_title.search(html)
        return re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""

    def _format_cert_time(self, value: str) -> str:
        try:
            return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").strftime("%d %b %Y %H:%M")
        except Exception:
            return value

    def _flatten_cert_name(self, cert_name: object) -> str:
        out: List[str] = []
        if isinstance(cert_name, tuple):
            for rdn in cert_name:
                if isinstance(rdn, tuple):
                    for item in rdn:
                        if isinstance(item, tuple) and len(item) == 2:
                            out.append(str(item[1]))
        return ", ".join([x for x in out if x]) or "Unknown"

    def _fetch_certificate(self, host: str, port: int = 443) -> Dict[str, object]:
        cached = self._global_cert_cache.get(host)
        if cached is not None:
            return cached
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=2.5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            out = {
                "host": host,
                "subject": self._flatten_cert_name(cert.get("subject", ())),
                "issuer": self._flatten_cert_name(cert.get("issuer", ())),
                "valid_from": self._format_cert_time(str(cert.get("notBefore", ""))),
                "valid_to": self._format_cert_time(str(cert.get("notAfter", ""))),
                "status": "ok",
            }
        except Exception as exc:
            out = {"host": host, "subject": "Unknown", "issuer": "Unknown", "valid_from": "", "valid_to": "", "status": "error", "error": str(exc)[:180]}
        self._global_cert_cache.set(host, out)
        return out

    def _is_probable_asset(self, content_type: str, url: str) -> bool:
        ct = (content_type or "").lower()
        if any(x in ct for x in ["image/", "font/", "audio/", "video/", "application/octet-stream", "javascript", "text/css"]):
            return True
        return bool(self._re_asset_ext.search((urlsplit(url).path or "").lower()))

    def _extract_sitemap_urls(self, seed: str, seed_host: str) -> List[str]:
        cache_key = f"{seed_host}|{seed.rstrip('/')}"
        cached = self._global_sitemap_cache.get(cache_key)
        if cached is not None:
            return cached
        found: List[str] = []
        for sm_url in [urljoin(seed, p) for p in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"]]:
            try:
                req = Request(sm_url, headers={"User-Agent": "RiskIntelCrawler/3.0"})
                with urlopen(req, timeout=4) as resp:
                    raw = resp.read(600000).decode("utf-8", errors="ignore")
                for node in ElementTree.fromstring(raw).findall(".//{*}loc"):
                    if node.text and self._same_site(seed_host, (urlsplit(node.text.strip()).hostname or "").lower()):
                        found.append(node.text.strip())
            except Exception:
                continue
        dedup: List[str] = []
        seen: Set[str] = set()
        for u in found:
            k = u.rstrip("/")
            if k not in seen:
                seen.add(k)
                dedup.append(u)
        out = dedup[:400]
        self._global_sitemap_cache.set(cache_key, out)
        return out

    def _malware_signals_from_html(self, html: str, page_url: str) -> Dict[str, object]:
        flags: List[str] = []
        score = 0.0
        lowered = html.lower()
        if re.search(r"eval\s*\(", lowered):
            score += 0.12; flags.append("JavaScript eval() usage")
        if "fromcharcode" in lowered:
            score += 0.10; flags.append("String.fromCharCode obfuscation")
        if re.search(r"\batob\s*\(", lowered):
            score += 0.08; flags.append("Base64 decode atob()")
        if re.search(r"\bunescape\s*\(", lowered):
            score += 0.08; flags.append("unescape() obfuscation primitive")
        if re.search(r"document\.write\s*\(", lowered):
            score += 0.05; flags.append("document.write dynamic injection")
        if re.findall(r"[A-Za-z0-9+/]{200,}={0,2}", html):
            score += 0.14; flags.append("Large base64-encoded blob")
        if re.search(r"<iframe[^>]*(display\s*:\s*none|width\s*=\s*[\"']?0|height\s*=\s*[\"']?0)", lowered):
            score += 0.15; flags.append("Hidden iframe behavior")
        if re.search(r"(download=|application/(x-msdownload|octet-stream))", lowered):
            score += 0.18; flags.append("Executable download vector")
        suspicious_downloads = [href for href in self._extract_html_links(html, page_url)
                                  if re.search(r"\.[a-z0-9]{2,5}$", urlsplit(href).path.lower()) and
                                  re.search(r"\.[a-z0-9]{2,5}$", urlsplit(href).path.lower()).group(0) in self.suspicious_file_ext]
        if suspicious_downloads:
            score += min(0.25, 0.09 + len(suspicious_downloads) * 0.03)
            flags.append(f"Suspicious download links: {len(suspicious_downloads)}")

        score = min(1.0, max(0.0, score))
        verdict = "likely_malicious" if score >= 0.62 else ("suspicious" if score >= 0.36 else "no_strong_malware_signal")
        return {"score": round(score, 3), "verdict": verdict, "flags": flags[:10], "suspicious_downloads": suspicious_downloads[:20]}

    def trace_website(
        self,
        website_url: str,
        max_pages: int = 120,
        max_depth: int = 4,
        include_external: bool = False,
        exhaustive: bool = True,
    ) -> Dict[str, object]:
        seed = self._normalize_site_url(website_url)
        seed_host = (urlsplit(seed).hostname or "").lower()
        if not seed_host:
            raise ValueError("Unable to parse website hostname.")

        max_pages = max(1, min(max_pages, 500))
        max_depth = max(0, min(max_depth, 8))

        queue: deque = deque([(seed, 0, None)])
        queued: Set[str] = {seed.rstrip("/")}
        visited: Set[str] = set()
        page_reports: List[Dict[str, object]] = []
        discovered_hosts: Set[str] = set()
        discovered_internal_urls: Set[str] = {seed.rstrip("/")}
        https_hosts_seen: Set[str] = set()

        if exhaustive:
            for sm_url in self._extract_sitemap_urls(seed, seed_host):
                key = sm_url.rstrip("/")
                if key not in discovered_internal_urls:
                    discovered_internal_urls.add(key)
                    if key not in queued and key not in visited:
                        queue.append((sm_url, 0, "sitemap"))
                        queued.add(key)

        while queue and len(page_reports) < max_pages:
            current, depth, parent = queue.popleft()
            canonical = current.rstrip("/")
            if canonical in visited:
                continue
            visited.add(canonical)

            page_result: Dict[str, object] = {
                "url": current, "depth": depth, "parent": parent,
                "status": "error", "status_code": None, "title": "",
                "risk_level": "low", "score": 0, "summary": "",
                "link_counts": {"internal": 0, "external": 0}, "error": None,
            }

            try:
                req = Request(current, headers={"User-Agent": "RiskIntelCrawler/3.0"})
                with urlopen(req, timeout=8) as resp:
                    status_code = int(getattr(resp, "status", resp.getcode()))
                    content_type = str(resp.headers.get("Content-Type", ""))
                    final_url = str(getattr(resp, "url", current))
                    payload = resp.read(1200000)
                final_parts = urlsplit(final_url)
                if final_parts.scheme == "https" and final_parts.hostname:
                    https_hosts_seen.add(final_parts.hostname.lower())
                html = payload.decode("utf-8", errors="ignore")
                page_text = self._html_to_text(html)[:14000]
                title = self._extract_title(html)
                malware = self._malware_signals_from_html(html, final_url)
                is_asset = self._is_probable_asset(content_type, final_url)
                ai = {"risk_level": "low", "score": 0, "summary": "Static asset.", "threat_fingerprint": None} if is_asset else self.analyze(page_text)
                extracted_links = self._extract_html_links(html, current)
                internal_links: List[str] = []
                external_links: List[str] = []
                for link in extracted_links:
                    host = (urlsplit(link).hostname or "").lower()
                    if host:
                        discovered_hosts.add(host)
                    if self._same_site(seed_host, host):
                        internal_links.append(link)
                        discovered_internal_urls.add(link.rstrip("/"))
                    else:
                        external_links.append(link)

                page_result.update({
                    "status": "ok", "status_code": status_code, "final_url": final_url,
                    "content_type": content_type, "is_asset": is_asset, "title": title,
                    "risk_level": ai["risk_level"], "score": ai["score"], "summary": ai["summary"],
                    "malware_score": int(round(float(malware["score"]) * 100)),
                    "malware_verdict": malware["verdict"], "malware_flags": malware["flags"],
                    "suspicious_downloads": malware["suspicious_downloads"],
                    "threat_fingerprint": ai["threat_fingerprint"],
                    "link_counts": {"internal": len(internal_links), "external": len(external_links)},
                    "link_preview": {"internal": internal_links[:12], "external": external_links[:12]},
                })

                if depth < max_depth:
                    for nxt in internal_links:
                        key = nxt.rstrip("/")
                        if key not in visited and key not in queued:
                            queue.append((nxt, depth + 1, current))
                            queued.add(key)
                    if include_external:
                        for nxt in external_links:
                            key = nxt.rstrip("/")
                            if key not in visited and key not in queued:
                                queue.append((nxt, depth + 1, current))
                                queued.add(key)
            except Exception as exc:
                page_result["error"] = str(exc)[:220]

            page_reports.append(page_result)

        ok_pages = [p for p in page_reports if p["status"] == "ok"]
        business_ok_pages = [p for p in ok_pages if not p.get("is_asset")]
        asset_ok_pages = [p for p in ok_pages if p.get("is_asset")]
        failed_pages = [p for p in page_reports if p["status"] != "ok"]
        high_pages = [p for p in business_ok_pages if p["risk_level"] in {"high", "critical"}]
        medium_pages = [p for p in business_ok_pages if p["risk_level"] == "medium"]
        malware_suspicious = [p for p in business_ok_pages if p.get("malware_verdict") in {"suspicious", "likely_malicious"}]
        malware_likely = [p for p in business_ok_pages if p.get("malware_verdict") == "likely_malicious"]
        top_pages = sorted(business_ok_pages, key=lambda x: int(x["score"]), reverse=True)[:8]
        avg_score = int(round(sum(int(p["score"]) for p in business_ok_pages) / max(len(business_ok_pages), 1)))
        highest = int(max((int(p["score"]) for p in business_ok_pages), default=0))
        avg_malware = int(round(sum(int(p.get("malware_score", 0)) for p in business_ok_pages) / max(len(business_ok_pages), 1)))
        highest_malware = int(max((int(p.get("malware_score", 0)) for p in business_ok_pages), default=0))

        overall = ("critical" if highest >= 80 or len(high_pages) >= 3 or len(malware_likely) >= 1
                   else ("high" if highest >= 60 or len(high_pages) >= 1 or len(malware_suspicious) >= 2
                         else ("medium" if avg_score >= 35 or len(medium_pages) >= 2 else "low")))
        coverage = int(round((len(visited) / max(len(discovered_internal_urls), 1)) * 100))
        scam_likelihood = int(min(100, round((avg_score * 0.55) + (len(high_pages) * 6) + (len(medium_pages) * 2) + (highest * 0.12))))
        malware_likelihood = int(min(100, round((avg_malware * 0.65) + (highest_malware * 0.2) + (len(malware_likely) * 15) + (len(malware_suspicious) * 4))))
        final_site_verdict = ("likely_malicious" if scam_likelihood >= 70 or malware_likelihood >= 65 or overall == "critical"
                              else ("suspicious" if scam_likelihood >= 45 or malware_likelihood >= 40 or overall in {"high", "medium"} else "likely_safe"))

        recs = []
        if high_pages: recs.append("Block/monitor high-risk pages and enforce user click protection.")
        if malware_likely: recs.append("Malware behavior detected; isolate domain and sandbox artifacts.")
        if malware_suspicious and not malware_likely: recs.append("Suspicious script patterns; perform dynamic analysis before allowing access.")
        if failed_pages: recs.append("Review failed crawl targets; hidden paths may contain suspicious content.")
        if len(discovered_hosts) > 8: recs.append("High host diversity; investigate redirect/chaining behavior.")
        if coverage < 60: recs.append("Coverage limited; increase max_pages/max_depth for full trace.")
        recs += ["Enable scheduled recrawls for threat drift detection.", "Store crawl snapshots for historical analysis."]

        cert_hosts = sorted(https_hosts_seen)[:40]
        if cert_hosts:
            with ThreadPoolExecutor(max_workers=min(10, len(cert_hosts))) as ex:
                certificates = list(ex.map(self._fetch_certificate, cert_hosts))
        else:
            certificates = []

        return {
            "seed_url": seed, "scope_host": seed_host,
            "pages_crawled": len(page_reports), "pages_ok": len(ok_pages),
            "business_pages_scanned": len(business_ok_pages), "asset_pages_skipped": len(asset_ok_pages),
            "pages_failed": len(failed_pages), "coverage_percent": coverage,
            "risk_level": overall, "average_score": avg_score, "highest_score": highest,
            "high_risk_pages": len(high_pages), "medium_risk_pages": len(medium_pages),
            "malware_suspicious_pages": len(malware_suspicious), "malware_likely_pages": len(malware_likely),
            "average_malware_score": avg_malware, "highest_malware_score": highest_malware,
            "scam_likelihood": scam_likelihood, "malware_likelihood": malware_likelihood,
            "site_verdict": final_site_verdict,
            "discovered_host_count": len(discovered_hosts), "discovered_internal_urls": len(discovered_internal_urls),
            "certificates": certificates, "certificate_hosts_scanned": len(certificates),
            "certificate_hosts_ok": sum(1 for c in certificates if c.get("status") == "ok"),
            "top_risky_pages": [
                {"url": p["url"], "title": p.get("title", ""), "score": p["score"], "risk_level": p["risk_level"],
                 "malware_score": p.get("malware_score", 0), "malware_verdict": p.get("malware_verdict", "no_strong_malware_signal"),
                 "summary": p["summary"]} for p in top_pages
            ],
            "pages": page_reports,
            "recommendations": recs[:6],
        }


import asyncio
import hashlib
import ipaddress
import re
import socket
import ssl
import time
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from math import exp, sqrt
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlsplit
from urllib.request import Request, urlopen
from xml.etree import ElementTree
from datetime import datetime
import functools
import threading


# ─────────────────────────────────────────────
# TTL-aware thread-safe in-process cache
# ─────────────────────────────────────────────
class TTLCache:
    """Thread-safe LRU-style cache with per-entry TTL."""

    def __init__(self, maxsize: int = 4096, ttl: float = 3600.0) -> None:
        self._store: Dict[str, Tuple[Any, float]] = {}
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
                # Evict oldest 10%
                oldest = sorted(self._store.items(), key=lambda x: x[1][1])[: self._maxsize // 10]
                for k, _ in oldest:
                    del self._store[k]
            self._store[key] = (value, time.monotonic())

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        return len(self._store)


@dataclass(frozen=True)
class Signal:
    name: str
    score: float
    detail: str


# ─────────────────────────────────────────────
# Extended threat pattern library
# ─────────────────────────────────────────────
RULE_SETS: Dict[str, Dict[str, float]] = {
    "credential_theft": {
        r"\bverify (your )?(account|identity)\b": 0.18,
        r"\breset (your )?password\b": 0.16,
        r"\blogin immediately\b": 0.12,
        r"\bsecurity alert\b": 0.10,
        r"\baccount (suspended|locked|disabled)\b": 0.17,
        r"\bconfirm (your )?(credentials|login|email)\b": 0.15,
    },
    "financial_fraud": {
        r"\bwire transfer\b": 0.17,
        r"\bgift card\b": 0.18,
        r"\bcrypto( wallet| payment)?\b": 0.13,
        r"\bbank details\b": 0.14,
        r"\bpayment failed\b": 0.10,
        r"\bsend (the )?funds?\b": 0.16,
        r"\bbitcoin\b": 0.12,
        r"\bwestern union\b": 0.19,
        r"\bmoney gram\b": 0.18,
        r"\binvoice (overdue|past due)\b": 0.13,
    },
    "urgency_pressure": {
        r"\bwithin (\d+ )?(minutes?|hours?)\b": 0.10,
        r"\bact now\b": 0.14,
        r"\bfinal warning\b": 0.15,
        r"\bimmediate action required\b": 0.18,
        r"\bexpires? (today|tonight|in \d+)\b": 0.12,
        r"\blast chance\b": 0.13,
        r"\btime.sensitive\b": 0.11,
    },
    "social_engineering": {
        r"\bthis is (the )?ceo\b": 0.15,
        r"\bkeep this confidential\b": 0.17,
        r"\bdo not tell anyone\b": 0.16,
        r"\btrusted partner\b": 0.08,
        r"\bpersonal favor\b": 0.11,
        r"\bbetween (us|you and me)\b": 0.10,
        r"\bdon'?t (mention|share|discuss) this\b": 0.14,
    },
    "business_email_compromise": {
        r"\bkindly process\b": 0.13,
        r"\bapproved by management\b": 0.10,
        r"\bout of office\b": 0.08,
        r"\bvendor update\b": 0.12,
        r"\bnew (banking|payment) (details?|instructions?)\b": 0.19,
        r"\bchange (of )?account (details?|number)\b": 0.17,
        r"\bauthorized (by|from) (the )?(cfo|ceo|management)\b": 0.15,
    },
    "malware_delivery": {
        r"\bopen (the |this )?(attached?|file|document)\b": 0.13,
        r"\bdownload (and )?(install|run|execute)\b": 0.16,
        r"\benable (macro|content)\b": 0.18,
        r"\bclick (to |here to )?(view|access|download)\b": 0.12,
        r"\bupdate (required|needed|now)\b": 0.11,
    },
    "romance_scam": {
        r"\bsend (me )?money\b": 0.17,
        r"\bi (love|miss|need) you\b.*\b(send|transfer|help)\b": 0.16,
        r"\bstranded (abroad|overseas|at the airport)\b": 0.19,
        r"\bmedical emergency\b.*\bmoney\b": 0.18,
    },
    "lottery_scam": {
        r"\byou (have |'ve )?(won|been selected)\b": 0.16,
        r"\bclaim (your )?(prize|winnings?|reward)\b": 0.17,
        r"\blottery (winner|jackpot)\b": 0.18,
        r"\bunclaimed (funds?|prize)\b": 0.15,
    },
}

INTENT_PROTOTYPES: Dict[str, str] = {
    "phishing_credential_theft": "Your account is suspended. Verify identity and password now.",
    "invoice_or_wire_fraud": "Urgent transfer required to secure corporate payment channel.",
    "gift_card_scam": "Purchase gift cards immediately and send the claim codes.",
    "malicious_link_delivery": "Security warning: click link to avoid permanent account lock.",
    "executive_impersonation": "Confidential request from executive: process payment discreetly.",
    "bank_detail_tampering": "Update bank details now to prevent payroll disruption.",
    "malware_download": "Enable macros to view important document. Download and install update.",
    "romance_fraud": "I love you and need your help. Send money urgently.",
    "lottery_fraud": "You have won a prize. Claim your lottery winnings now.",
    "advance_fee_fraud": "Transfer fee required to release inheritance funds to your account.",
}


class RiskEngine:
    """
    Hybrid fraud detection engine — deterministic rules + NLP cosine similarity.
    v3: async-ready, parallel link tracing, TTL caches, extended rule library.
    """

    _global_link_cache = TTLCache(maxsize=8192, ttl=1800.0)
    _global_whois_cache = TTLCache(maxsize=2048, ttl=7200.0)
    _global_domain_cache = TTLCache(maxsize=4096, ttl=3600.0)
    _global_cert_cache = TTLCache(maxsize=1024, ttl=3600.0)
    _global_sitemap_cache = TTLCache(maxsize=512, ttl=1800.0)

    def __init__(self) -> None:
        self.rule_sets = RULE_SETS
        self.intent_prototypes = INTENT_PROTOTYPES
        self._re_multi_ws = re.compile(r'\s+')
        self.prototype_vectors = {
            intent:         self._vectorize(self._normalize(text))
            for intent, text in self.intent_prototypes.items()
        }
        self.high_risk_terms = {
            "password", "otp", "bank", "transfer", "wallet", "payment", "urgent",
            "verify", "confidential", "gift", "card", "crypto", "pin", "credential",
            "click", "link", "bitcoin", "invoice", "wire", "lottery", "prize",
            "winner", "inheritance", "claim", "fund", "release",
        }
        self.shortener_domains = {
            "bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd", "goo.gl",
            "ow.ly", "shorturl.at", "cutt.ly", "rebrand.ly", "tiny.cc",
            "snip.ly", "bl.ink", "short.io",
        }
        self.suspicious_tlds = {
            "zip", "mov", "top", "gq", "tk", "work", "click", "cam", "rest",
            "country", "stream", "xyz", "pw", "cc", "biz", "info",
        }
        self.sensitive_query_keys = {"url", "redirect", "next", "target", "dest", "continue", "return", "goto"}
        self.suspicious_file_ext = {".exe", ".msi", ".bat", ".cmd", ".scr", ".js", ".vbs", ".jar", ".ps1", ".hta", ".pif"}
        self.link_risk_terms = {"login", "verify", "secure", "wallet", "bank", "password", "update", "payment", "signin", "account"}
        self.reputation_risky_terms = {
            "secure", "verify", "update", "wallet", "login", "account",
            "signin", "support", "billing", "payment", "confirm", "auth",
        }
        self.known_brands = {
            "google", "microsoft", "apple", "amazon", "paypal", "netflix",
            "facebook", "instagram", "whatsapp", "linkedin", "github",
            "dropbox", "twitter", "x", "bankofamerica", "chase", "wellsfargo",
            "citibank", "outlook", "office365", "youtube", "tiktok", "coinbase",
            "binance", "kraken", "robinhood", "stripe", "shopify",
        }
        self.brand_text_terms = {
            "google", "microsoft", "apple", "amazon", "paypal", "netflix",
            "facebook", "instagram", "linkedin", "github", "outlook", "office365",
            "bank of america", "wells fargo", "citi", "chase bank", "youtube",
            "tiktok", "coinbase", "binance",
        }
        self.typo_homograph_map = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})

        # Pre-compiled regex patterns
        self._re_url_scheme = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
        self._re_link_pattern = re.compile(r"(?:(?:https?|ftp)://|www\.)[^\s<>'\"()]+", flags=re.IGNORECASE)
        self._re_asset_ext = re.compile(r"\.(png|jpg|jpeg|gif|svg|ico|webp|woff2?|ttf|eot|css|js|map|mp4|mp3|pdf)$")
        self._re_title = re.compile(r"<title[^>]*>(.*?)</title>", flags=re.IGNORECASE | re.DOTALL)
        self._re_href = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', flags=re.IGNORECASE)
        self._re_tag_strip = re.compile(r"<[^>]+>")
        self._re_script_strip = re.compile(r"<script[\s\S]*?</script>", flags=re.IGNORECASE)
        self._re_style_strip = re.compile(r"<style[\s\S]*?</style>", flags=re.IGNORECASE)
        self._re_multi_ws = re.compile(r"\s+")
        self._re_obfuscated_link = re.compile(r"hxxps?://|\[\.\]|\(\.\)")
        self._re_repeated_chars = re.compile(r"(.)\1{5,}")
        self._re_currency = re.compile(r"\$\d+|\b\d{2,}(?:,\d{3})*(?:\.\d+)?\b")
        self._re_caps = re.compile(r"\b[A-Z]{3,}\b")
        self._re_exec_ext = re.compile(r"\.[a-zA-Z0-9]{2,5}$")
        self._re_whois_date = re.compile(r"(20\d{2})[-/](\d{1,2})[-/](\d{1,2})")

        # Compile rule sets once
        self._rule_sets_compiled: Dict[str, List[Tuple[re.Pattern, float, str]]] = {}
        for category, patterns in self.rule_sets.items():
            self._rule_sets_compiled[category] = [
                (re.compile(pat, re.IGNORECASE), weight, pat)
                for pat, weight in patterns.items()
            ]

        # Thread pool for parallel I/O (link tracing, cert checks, WHOIS)
        self._executor = ThreadPoolExecutor(max_workers=20, thread_name_prefix="riskintel")
        
    # ──────────────────────────────────────────
    # Core NLP helpers
    # ──────────────────────────────────────────
    def _normalize(self, text: str) -> str:
        return self._re_multi_ws.sub(" ", text.strip().lower())

    def _deobfuscate_links_text(self, text: str) -> str:
        return (
            text.replace("[.]", ".").replace("(.)", ".")
            .replace("hxxp://", "http://").replace("hxxps://", "https://")
        )

    def _tokenize(self, text: str) -> List[str]:
        return re.findall(r"[a-zA-Z0-9']+", text)

    def _vectorize(self, text: str) -> Counter:
        tokens = self._tokenize(text)
        if len(tokens) < 2:
            return Counter(tokens)
        bigrams = [f"{tokens[i]}_{tokens[i+1]}" for i in range(len(tokens) - 1)]
        return Counter(tokens + bigrams)

    def _cosine(self, a: Counter, b: Counter) -> float:
        if not a or not b:
            return 0.0
        dot = sum(a[k] * b.get(k, 0) for k in a)
        norm_a = sqrt(sum(v * v for v in a.values()))
        norm_b = sqrt(sum(v * v for v in b.values()))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def _extract_links(self, text: str) -> List[str]:
        candidate_text = self._deobfuscate_links_text(text)
        links = self._re_link_pattern.findall(candidate_text)
        seen: Set[str] = set()
        unique: List[str] = []
        for link in links:
            normalized = link.strip(".,);]}>\"'")
            low = normalized.lower()
            if normalized and low not in seen:
                seen.add(low)
                unique.append(normalized)
        return unique

    @staticmethod
    def _effective_domain(hostname: str) -> str:
        parts = [p for p in hostname.split(".") if p]
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname

    @staticmethod
    def _sld(hostname: str) -> str:
        parts = [p for p in hostname.split(".") if p]
        return parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")

    @staticmethod
    def _levenshtein(a: str, b: str) -> int:
        if a == b:
            return 0
        if not a:
            return len(b)
        if not b:
            return len(a)
        if len(a) < len(b):
            a, b = b, a
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, start=1):
            cur = [i]
            for j, cb in enumerate(b, start=1):
                cur.append(min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + (0 if ca == cb else 1)))
            prev = cur
        return prev[-1]

    # ──────────────────────────────────────────
    # Domain intelligence (with global TTL caches)
    # ──────────────────────────────────────────
    def _domain_reputation_profile(self, hostname: str) -> Dict[str, object]:
        host = (hostname or "").strip().lower()
        if not host:
            return {"score": 0.0, "flags": [], "category": "unknown"}
        cached = self._global_domain_cache.get(host)
        if cached is not None:
            return cached

        score = 0.0
        flags: List[str] = []
        sld = self._sld(host)
        digits = sum(ch.isdigit() for ch in sld)
        hyphens = sld.count("-")
        alpha = sum(ch.isalpha() for ch in sld)
        entropy_like = len(set(sld)) / max(len(sld), 1)
        risky_term_hits = [term for term in self.reputation_risky_terms if term in host]
        tld = host.rsplit(".", 1)[-1] if "." in host else ""

        if digits >= 3:
            score += 0.07; flags.append("Heavy numeric usage in domain")
        if hyphens >= 2:
            score += 0.08; flags.append("Multiple hyphens in domain")
        if len(sld) >= 22:
            score += 0.08; flags.append("Very long second-level domain")
        if entropy_like > 0.82 and len(sld) >= 10 and alpha >= 6:
            score += 0.06; flags.append("High-randomness domain label")
        if risky_term_hits:
            score += min(0.15, 0.04 * len(risky_term_hits))
            flags.append(f"Risky terms in domain: {', '.join(sorted(set(risky_term_hits)))}")
        if tld in self.suspicious_tlds:
            score += 0.10; flags.append(f"Suspicious TLD .{tld}")

        category = "poor" if score >= 0.45 else ("questionable" if score >= 0.25 else "neutral")
        out = {"score": round(min(1.0, score), 3), "flags": flags[:8], "category": category}
        self._global_domain_cache.set(host, out)
        return out

    def _brand_impersonation_profile(self, text: str, hostname: str) -> Dict[str, object]:
        norm = self._normalize(text)
        host = (hostname or "").lower()
        hits = [b for b in self.brand_text_terms if b in norm]
        if not hits:
            return {"score": 0.0, "flags": [], "brands": []}
        effective = self._effective_domain(host)
        flags: List[str] = []
        score = 0.0
        brands: List[str] = []
        for b in hits:
            token = re.sub(r"[^a-z0-9]", "", b.lower())
            if not token:
                continue
            brands.append(b)
            if token not in effective:
                score += 0.07
                flags.append(f"Brand '{b}' mismatches destination domain")
        if len(set(brands)) >= 2:
            score += 0.05; flags.append("Multiple brand references")
        return {"score": round(min(0.35, score), 3), "flags": flags[:8], "brands": sorted(set(brands))[:8]}

    def _typosquat_profile(self, hostname: str) -> Dict[str, object]:
        host = (hostname or "").strip().lower()
        if not host:
            return {"score": 0.0, "flags": [], "closest_brand": None}
        sld = self._sld(host)
        normalized = sld.translate(self.typo_homograph_map)
        if len(normalized) < 3:
            return {"score": 0.0, "flags": [], "closest_brand": None}

        best_brand: Optional[str] = None
        best_dist = 99
        for brand in self.known_brands:
            dist = self._levenshtein(normalized, brand)
            if dist < best_dist:
                best_dist = dist
                best_brand = brand

        score = 0.0
        flags: List[str] = []
        if best_brand and normalized != best_brand:
            if best_dist == 1:
                score += 0.26; flags.append(f"Likely typosquat of '{best_brand}' (edit distance 1)")
            elif best_dist == 2 and len(best_brand) >= 6:
                score += 0.17; flags.append(f"Possible typosquat of '{best_brand}' (edit distance 2)")
        if best_brand and best_brand in normalized and normalized != best_brand:
            extra = normalized.replace(best_brand, "")
            if len(extra) >= 3:
                score += 0.09; flags.append(f"Brand '{best_brand}' embedded with deceptive token")
        return {"score": round(min(0.4, score), 3), "flags": flags[:8], "closest_brand": best_brand}

    def _whois_domain_age_profile(self, hostname: str) -> Dict[str, object]:
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
        status = "unavailable"
        rdap_url = f"https://rdap.org/domain/{root}"
        try:
            req = Request(rdap_url, headers={"User-Agent": "RiskIntel/3.0", "Accept": "application/rdap+json"})
            with urlopen(req, timeout=2.5) as resp:
                payload = resp.read(240000).decode("utf-8", errors="ignore")
            m = self._re_whois_date.search(payload)
            if m:
                year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
                created = datetime(year=year, month=max(1, min(month, 12)), day=max(1, min(day, 28)))
                age_days = max(0, (datetime.utcnow() - created).days)
                status = "ok"
        except Exception:
            status = "unavailable"

        if age_days is not None:
            if age_days < 30:
                score += 0.23; flags.append("Very new domain (<30 days)")
            elif age_days < 90:
                score += 0.16; flags.append("Recently registered (<90 days)")
            elif age_days < 180:
                score += 0.10; flags.append("Young domain (<180 days)")

        out = {"score": round(min(0.3, score), 3), "flags": flags, "age_days": age_days, "status": status}
        self._global_whois_cache.set(host, out)
        return out

    # ──────────────────────────────────────────
    # Link tracing (parallel via thread pool)
    # ──────────────────────────────────────────
    def _trace_single_link(self, raw_link: str) -> Dict[str, object]:
        key = raw_link.strip().lower()
        cached = self._global_link_cache.get(key)
        if cached is not None:
            return cached

        working = raw_link if self._re_url_scheme.match(raw_link) else f"http://{raw_link}"
        parsed = urlsplit(working)
        hostname = (parsed.hostname or "").strip().lower()
        path = parsed.path or ""
        query = parsed.query or ""

        score = 0.0
        flags: List[str] = []

        if parsed.scheme == "http":
            score += 0.10; flags.append("Unencrypted HTTP scheme")
        if "@" in parsed.netloc:
            score += 0.15; flags.append("Credentials in URL (user-info)")
        if hostname in self.shortener_domains:
            score += 0.16; flags.append("Known URL shortener")
        if hostname.startswith("xn--") or ".xn--" in hostname:
            score += 0.12; flags.append("Punycode/IDN domain spoofing risk")
        if any(ord(ch) > 127 for ch in hostname):
            score += 0.10; flags.append("Non-ASCII domain characters")

        subdomain_depth = max(0, len(hostname.split(".")) - 2)
        if subdomain_depth >= 3:
            score += 0.08; flags.append("Deep subdomain chain")
        if len(working) > 140:
            score += 0.08; flags.append("Excessive URL length")
        if parsed.port and parsed.port not in {80, 443}:
            score += 0.08; flags.append(f"Non-standard port {parsed.port}")

        last_dot = hostname.rfind(".")
        tld = hostname[last_dot + 1:] if last_dot > -1 else ""
        if tld in self.suspicious_tlds:
            score += 0.14; flags.append(f"Suspicious TLD .{tld}")

        lower_full = f"{hostname}{path}?{query}".lower()
        keyword_hits = [k for k in self.link_risk_terms if k in lower_full]
        if keyword_hits:
            score += min(0.12, 0.03 * len(keyword_hits))
            flags.append(f"Risk keywords in URL: {', '.join(sorted(set(keyword_hits)))}")

        ext_match = self._re_exec_ext.search(path.lower())
        if ext_match and ext_match.group(0) in self.suspicious_file_ext:
            score += 0.20; flags.append(f"Executable/script extension {ext_match.group(0)}")

        encoded_ratio = working.count("%") / max(len(working), 1)
        if encoded_ratio > 0.03 or working.count("%") >= 4:
            score += 0.07; flags.append("Heavy URL percent-encoding")

        query_map = parse_qs(query, keep_blank_values=True)
        redirect_keys = [k for k in query_map if k.lower() in self.sensitive_query_keys]
        if redirect_keys:
            score += 0.12; flags.append(f"Open redirect parameters: {', '.join(sorted(redirect_keys))}")

        ip_label = ip_type = None
        if hostname:
            try:
                ip_obj = ipaddress.ip_address(hostname)
                ip_label = str(ip_obj)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    score += 0.10; ip_type = "private/local"; flags.append("Private/local IP host")
                else:
                    score += 0.07; ip_type = "public"; flags.append("Direct IP instead of domain")
            except ValueError:
                pass

        reputation = self._domain_reputation_profile(hostname)
        typo = self._typosquat_profile(hostname)
        whois_age = self._whois_domain_age_profile(hostname)
        score += min(0.18, float(reputation.get("score", 0.0)) * 0.7)
        flags.extend(list(reputation.get("flags", []))[:2])
        score += min(0.20, float(typo.get("score", 0.0)) * 0.9)
        flags.extend(list(typo.get("flags", []))[:2])
        score += min(0.12, float(whois_age.get("score", 0.0)) * 0.8)
        flags.extend(list(whois_age.get("flags", []))[:1])

        score = min(1.0, max(0.0, score))
        verdict = "critical" if score >= 0.65 else ("high" if score >= 0.45 else ("medium" if score >= 0.25 else "low"))

        out = {
            "raw": raw_link,
            "normalized": working,
            "scheme": parsed.scheme,
            "host": hostname,
            "port": parsed.port,
            "path": path,
            "query_keys": sorted(query_map.keys()),
            "ip": ip_label,
            "ip_type": ip_type,
            "score": round(score, 3),
            "verdict": verdict,
            "flags": self._dedupe_ordered(flags)[:12],
            "domain_intelligence": {
                "domain_reputation": reputation,
                "typosquatting": typo,
                "whois_age": whois_age,
            },
        }
        self._global_link_cache.set(key, out)
        return out

    def trace_links(self, text: str) -> Dict[str, object]:
        links = self._extract_links(text)
        if not links:
            return {"total_links": 0, "high_risk_links": 0, "medium_risk_links": 0, "aggregate_score": 0.0, "links": []}

        # Parallel link tracing
        futures = {self._executor.submit(self._trace_single_link, link): link for link in links}
        traced: List[Dict[str, object]] = []
        for future in as_completed(futures):
            try:
                traced.append(future.result(timeout=6.0))
            except Exception:
                pass

        high_count = sum(1 for x in traced if x["verdict"] in {"high", "critical"})
        med_count = sum(1 for x in traced if x["verdict"] == "medium")
        total_score = round(sum(float(x["score"]) for x in traced), 3)
        return {
            "total_links": len(traced),
            "high_risk_links": high_count,
            "medium_risk_links": med_count,
            "aggregate_score": total_score,
            "links": sorted(traced, key=lambda x: float(x["score"]), reverse=True),
        }

    # ──────────────────────────────────────────
    # Entity extraction
    # ──────────────────────────────────────────
    def _extract_entities(self, text: str) -> Dict[str, object]:
        emails = re.findall(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", text)
        phones = re.findall(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)\d{3,4}[-.\s]?\d{3,4}\b", text)
        ipv4s = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        crypto_wallets = re.findall(r"\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", text)
        long_numeric_ids = re.findall(r"\b\d{10,18}\b", text)
        cvv_pattern = re.findall(r"\b\d{3,4}\b", text)  # light card CVV indicator
        entities = {
            "emails": sorted(set(emails))[:12],
            "phones": sorted(set(phones))[:12],
            "ipv4s": sorted(set(ipv4s))[:12],
            "crypto_wallets": sorted(set(crypto_wallets))[:12],
            "numeric_ids": sorted(set(long_numeric_ids))[:12],
        }
        entities["counts"] = {k: len(v) for k, v in entities.items() if isinstance(v, list)}
        entities["total"] = sum(entities["counts"].values())
        return entities

    # ──────────────────────────────────────────
    # Intent profiling
    # ──────────────────────────────────────────
    def _intent_profile(self, text: str) -> Dict[str, object]:
        norm = self._normalize(text)
        query_vector =         self._vectorize(norm)
        intent_scores = [
            {"intent": intent, "similarity": round(self._cosine(query_vector, proto), 3)}
            for intent, proto in self.prototype_vectors.items()
        ]
        top_intents = sorted(intent_scores, key=lambda x: x["similarity"], reverse=True)[:3]
        return {"top_intents": top_intents, "max_similarity": top_intents[0]["similarity"] if top_intents else 0.0}

    # ──────────────────────────────────────────
    # Signal extraction
    # ──────────────────────────────────────────
    def _extract_rule_signals(self, text: str) -> List[Signal]:
        norm = self._normalize(text)
        signals: List[Signal] = []
        for category, patterns in self._rule_sets_compiled.items():
            cat_hits: List[Tuple[str, float]] = []
            for compiled, weight, raw_pattern in patterns:
                if compiled.search(norm):
                    cat_hits.append((raw_pattern, weight))
            if not cat_hits:
                continue
            cat_hits.sort(key=lambda x: x[1], reverse=True)
            cat_score = sum(w * (1.0 if i == 0 else (0.62 if i == 1 else 0.30)) for i, (_, w) in enumerate(cat_hits))
            cat_score = min(0.28, cat_score)
            signals.append(Signal(
                name=f"rule::{category}",
                score=cat_score,
                detail=f"Matched {len(cat_hits)} pattern(s) in {category}; strongest '{cat_hits[0][0]}'.",
            ))
        return signals

    def _nlp_signals(
        self,
        text: str,
        extracted_links: Optional[List[str]] = None,
        intent_profile: Optional[Dict[str, object]] = None,
    ) -> List[Signal]:
        norm = self._normalize(text)
        words = self._tokenize(norm)
        total_words = max(len(words), 1)
        high_risk_hits = sum(1 for w in words if w in self.high_risk_terms)
        risk_density = high_risk_hits / total_words
        exclamations = text.count("!")
        caps_words = self._re_caps.findall(text)
        link_hits = len(extracted_links) if extracted_links is not None else len(self._extract_links(text))
        currency_hits = len(self._re_currency.findall(text))
        obfuscated_hits = len(self._re_obfuscated_link.findall(text.lower()))
        profile = intent_profile if intent_profile is not None else self._intent_profile(text)
        sim = float(profile["max_similarity"])

        signals: List[Signal] = []
        if risk_density > 0.08:
            signals.append(Signal("nlp::risk_term_density", min(0.18, risk_density * 1.4), f"High-risk term density {risk_density:.2f}"))
        if sim > 0.25:
            signals.append(Signal("nlp::intent_similarity", min(0.25, sim * 0.55), f"Fraud intent similarity {sim:.2f}"))
        if exclamations >= 3:
            signals.append(Signal("nlp::pressure_tone", min(0.08, exclamations * 0.02), f"{exclamations} exclamation marks"))
        if len(caps_words) >= 2:
            signals.append(Signal("nlp::aggressive_caps", 0.07, "Multiple ALL-CAPS tokens"))
        if link_hits > 0:
            signals.append(Signal("nlp::external_link", min(0.10, 0.05 + 0.02 * link_hits), f"{link_hits} external link(s)"))
        if currency_hits > 0:
            signals.append(Signal("nlp::money_reference", min(0.09, 0.03 + currency_hits * 0.02), f"{currency_hits} currency indicator(s)"))
        if obfuscated_hits > 0:
            signals.append(Signal("nlp::link_obfuscation", min(0.16, 0.06 + obfuscated_hits * 0.03), f"{obfuscated_hits} obfuscated link(s)"))
        if self._re_repeated_chars.search(text):
            signals.append(Signal("nlp::pattern_anomaly", 0.06, "Repeated-character pattern anomaly"))
        return signals

    # ──────────────────────────────────────────
    # Score synthesis
    # ──────────────────────────────────────────
    def _score_from_evidence(self, signals: List[Signal], link_analysis: Dict[str, object]) -> Dict[str, float]:
        rule_sum = nlp_sum = intel_sum = 0.0
        signal_names = [s.name for s in signals]
        for s in signals:
            if s.name.startswith("rule::"):
                rule_sum += s.score
            elif s.name.startswith("nlp::"):
                nlp_sum += s.score
            else:
                intel_sum += s.score

        rule_capped = min(0.56, rule_sum)
        nlp_capped = min(0.34, nlp_sum)
        intel_capped = min(0.24, intel_sum)
        raw_capped = rule_capped + nlp_capped + intel_capped

        fusion_boost = 0.0
        if rule_capped > 0.25 and nlp_capped > 0.14:
            fusion_boost += 0.06
        if int(link_analysis.get("high_risk_links", 0)) > 0 and (
            "nlp::link_obfuscation" in signal_names or intel_capped > 0.08
        ):
            fusion_boost += 0.05
        if "rule::financial_fraud" in signal_names and "rule::social_engineering" in signal_names:
            fusion_boost += 0.04
        if "nlp::intent_similarity" in signal_names and nlp_capped > 0.18:
            fusion_boost += 0.03

        blended = min(1.0, raw_capped + fusion_boost)
        calibrated = min(0.96, max(0.0, 1.0 - exp(-1.45 * blended)))
        return {
            "rule": round(rule_capped, 3),
            "nlp": round(nlp_capped, 3),
            "intel": round(intel_capped, 3),
            "fusion": round(fusion_boost, 3),
            "raw": round(blended, 3),
            "calibrated": round(calibrated, 3),
        }

    def _dimension_scores(self, signals: List[Signal], link_analysis: Dict, entities: Dict) -> Dict[str, int]:
        dims = {k: 0.0 for k in ("credential_theft", "financial_fraud", "social_engineering", "coercion_pressure", "link_abuse", "data_exposure")}
        for s in signals:
            n = s.name
            if "credential" in n or "password" in s.detail.lower():
                dims["credential_theft"] += s.score * 120
            if "financial" in n or "money" in n or "payment" in s.detail.lower():
                dims["financial_fraud"] += s.score * 120
            if "social_engineering" in n or "impersonation" in n:
                dims["social_engineering"] += s.score * 120
            if "urgency" in n or "pressure" in n or "aggressive_caps" in n:
                dims["coercion_pressure"] += s.score * 110
            if "link" in n:
                dims["link_abuse"] += s.score * 140
        dims["link_abuse"] += float(link_analysis.get("aggregate_score", 0.0)) * 45
        dims["link_abuse"] += int(link_analysis.get("high_risk_links", 0)) * 10
        entity_counts = entities.get("counts", {})
        dims["data_exposure"] += entity_counts.get("emails", 0) * 8
        dims["data_exposure"] += entity_counts.get("phones", 0) * 6
        dims["data_exposure"] += entity_counts.get("numeric_ids", 0) * 5
        dims["financial_fraud"] += entity_counts.get("crypto_wallets", 0) * 10
        return {k: min(100, int(round(v))) for k, v in dims.items()}

    def _confidence_score(self, score_100: int, signal_count: int, text_length: int) -> int:
        confidence = (score_100 / 100) * 0.6 + min(0.25, signal_count * 0.03) + min(0.15, text_length / 1400)
        return min(99, max(10, int(round(confidence * 100))))

    def _recommendations(self, risk_level: str, link_analysis: Dict, entities: Dict) -> List[str]:
        recs: List[str] = []
        if risk_level in {"high", "critical"}:
            recs.append("Immediately isolate this message and trigger analyst review.")
            recs.append("Block detected URLs/domains at email gateway, DNS, and proxy controls.")
        if int(link_analysis.get("high_risk_links", 0)) > 0:
            recs.append("Perform safe detonation/sandboxing for all extracted links.")
        if entities.get("counts", {}).get("crypto_wallets", 0):
            recs.append("Escalate to financial fraud — cryptocurrency transfer indicators found.")
        if entities.get("counts", {}).get("numeric_ids", 0):
            recs.append("Mask sensitive numeric identifiers and open data-exposure case.")
        if risk_level in {"low", "medium"}:
            recs.append("Keep under monitoring; auto-recheck on repeated sender patterns.")
        recs.append("Preserve message headers and metadata for forensic correlation.")
        return recs[:6]

    @staticmethod
    def _dedupe_ordered(items: List[str]) -> List[str]:
        seen: Set[str] = set()
        return [item for item in items if item.strip() and not (item.strip() in seen or seen.add(item.strip()))]

    def _dedupe_signals(self, signals: List[Signal]) -> List[Signal]:
        best: Dict[Tuple[str, str], Signal] = {}
        for sig in signals:
            key = (sig.name, sig.detail)
            if key not in best or sig.score > best[key].score:
                best[key] = sig
        return list(best.values())

    def _benign_context_reduction(self, text: str, link_analysis: Dict) -> float:
        norm = self._normalize(text)
        benign_terms = {"meeting", "agenda", "minutes", "calendar", "schedule", "review", "draft", "notes", "thanks", "regards", "tomorrow", "team", "update"}
        tokens = set(self._tokenize(norm))
        benign_hits = len(tokens.intersection(benign_terms))
        risky_links = int(link_analysis.get("high_risk_links", 0)) + int(link_analysis.get("medium_risk_links", 0))
        if benign_hits < 3 or risky_links > 0:
            return 0.0
        return min(0.12, 0.02 * (benign_hits - 2))

    # ──────────────────────────────────────────
    # Main analyze entry point
    # ──────────────────────────────────────────
    def analyze(self, text: str) -> Dict[str, object]:
        if not text or not text.strip():
            return {
                "score": 0, "risk_level": "low", "plain_verdict": "No content to analyze.",
                "top_flags": [], "signals": [], "summary": "No content provided.",
                "link_analysis": {"total_links": 0, "high_risk_links": 0, "medium_risk_links": 0, "aggregate_score": 0.0, "links": []},
                "entities": {"emails": [], "phones": [], "ipv4s": [], "crypto_wallets": [], "numeric_ids": [], "counts": {}, "total": 0},
                "intent_profile": {"top_intents": [], "max_similarity": 0.0},
                "dimensions": {}, "confidence": 0,
                "domain_intelligence": {"brand_impersonation": {"score": 0.0, "flags": [], "brands": []}, "best_link_host": None},
                "recommendations": [], "threat_fingerprint": None,
            }

        # Parallel: link tracing + entity extraction + intent profiling simultaneously
        with ThreadPoolExecutor(max_workers=3) as pool:
            future_links = pool.submit(self.trace_links, text)
            future_entities = pool.submit(self._extract_entities, text)
            future_intent = pool.submit(self._intent_profile, text)
            link_analysis = future_links.result()
            entities = future_entities.result()
            intent_profile = future_intent.result()

        extracted_links = [str(item.get("raw", "")) for item in link_analysis.get("links", []) if item.get("raw")]
        signals = self._extract_rule_signals(text) + self._nlp_signals(text, extracted_links=extracted_links, intent_profile=intent_profile)

        best_link = max(link_analysis.get("links", []) or [{}], key=lambda x: float(x.get("score", 0.0)), default={})
        target_host = str((best_link or {}).get("host", "")).lower()
        brand_intel = self._brand_impersonation_profile(text, target_host)
        if float(brand_intel.get("score", 0.0)) > 0:
            signals.append(Signal("intel::brand_impersonation", min(0.20, float(brand_intel["score"])), "Brand impersonation content-domain mismatch"))
        signals = self._dedupe_signals(signals)
        if link_analysis["total_links"] > 0:
            signals.append(Signal("intel::link_trace", min(0.28, float(link_analysis["aggregate_score"]) * 0.22),
                                  f"Traced {link_analysis['total_links']} link(s), {link_analysis['high_risk_links']} high-risk."))
        if entities.get("total", 0) > 0:
            signals.append(Signal("intel::sensitive_entity_presence", min(0.14, 0.03 + entities["total"] * 0.015),
                                  f"Detected {entities['total']} sensitive entity indicator(s)."))

        score_breakdown = self._score_from_evidence(signals, link_analysis)
        benign_reduction = self._benign_context_reduction(text, link_analysis)
        calibrated = max(0.0, float(score_breakdown["calibrated"]) - benign_reduction)
        score_breakdown.update({"benign_reduction": round(benign_reduction, 3), "final": round(calibrated, 3)})
        score_100 = int(round(calibrated * 100))

        level = "critical" if score_100 >= 84 else ("high" if score_100 >= 66 else ("medium" if score_100 >= 42 else "low"))
        dimensions = self._dimension_scores(signals, link_analysis, entities)
        confidence = self._confidence_score(score_100, len(signals), len(text))
        if level == "critical" and confidence < 78:
            level = "high"
        if level == "high" and confidence < 48:
            level = "medium"

        summary = ("No explicit fraud indicators found." if not signals
                   else "Top indicators: " + "; ".join(f"{x.name} ({x.score:.2f})" for x in sorted(signals, key=lambda s: s.score, reverse=True)[:3]))
        top_flags = self._dedupe_ordered([s.detail for s in sorted(signals, key=lambda s: s.score, reverse=True)])[:5]
        plain_verdicts = {
            "critical": "High probability of scam or malicious content. Block immediately.",
            "high": "Strong risk indicators found. Requires analyst verification.",
            "medium": "Suspicious patterns detected. Proceed with caution.",
            "low": "No major fraud signals detected.",
        }

        return {
            "score": score_100,
            "risk_level": level,
            "confidence": confidence,
            "score_breakdown": score_breakdown,
            "plain_verdict": plain_verdicts[level],
            "top_flags": top_flags,
            "signals": [{"name": s.name, "score": round(s.score, 3), "detail": s.detail} for s in signals],
            "summary": summary,
            "intent_profile": intent_profile,
            "dimensions": dimensions,
            "entities": entities,
            "link_analysis": link_analysis,
            "domain_intelligence": {"brand_impersonation": brand_intel, "best_link_host": target_host or None},
            "recommendations": self._recommendations(level, link_analysis, entities),
            "threat_fingerprint": hashlib.sha256(self._normalize(text).encode()).hexdigest()[:24],
        }

    # ──────────────────────────────────────────
    # Async wrappers for FastAPI async endpoints
    # ──────────────────────────────────────────
    async def analyze_async(self, text: str) -> Dict[str, object]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self.analyze, text)

    async def analyze_batch_async(self, texts: List[str]) -> List[Dict[str, object]]:
        loop = asyncio.get_event_loop()
        tasks = [loop.run_in_executor(self._executor, self.analyze, t) for t in texts]
        return await asyncio.gather(*tasks)

    # ──────────────────────────────────────────
    # Website tracer (unchanged logic, optimized I/O)
    # ──────────────────────────────────────────
    def _normalize_site_url(self, website_url: str) -> str:
        cleaned = website_url.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
            cleaned = f"https://{cleaned}"
        parsed = urlsplit(cleaned)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Only http/https URLs are supported.")
        if not parsed.netloc:
            raise ValueError("Invalid website URL.")
        return cleaned

    def _same_site(self, root_host: str, host: str) -> bool:
        return bool(host) and (host == root_host or host.endswith(f".{root_host}"))

    def _extract_html_links(self, html: str, base_url: str) -> List[str]:
        seen: Set[str] = set()
        unique: List[str] = []
        for href in self._re_href.findall(html):
            if href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            abs_url = urljoin(base_url, href).split("#")[0].strip()
            if not abs_url:
                continue
            if urlsplit(abs_url).scheme not in {"http", "https"}:
                continue
            if abs_url not in seen:
                seen.add(abs_url)
                unique.append(abs_url)
        return unique

    def _html_to_text(self, html: str) -> str:
        return self._re_multi_ws.sub(" ", self._re_tag_strip.sub(" ", self._re_style_strip.sub(" ", self._re_script_strip.sub(" ", html)))).strip()

    def _extract_title(self, html: str) -> str:
        m = self._re_title.search(html)
        return re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""

    def _format_cert_time(self, value: str) -> str:
        try:
            return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").strftime("%d %b %Y %H:%M")
        except Exception:
            return value

    def _flatten_cert_name(self, cert_name: object) -> str:
        out: List[str] = []
        if isinstance(cert_name, tuple):
            for rdn in cert_name:
                if isinstance(rdn, tuple):
                    for item in rdn:
                        if isinstance(item, tuple) and len(item) == 2:
                            out.append(str(item[1]))
        return ", ".join([x for x in out if x]) or "Unknown"

    def _fetch_certificate(self, host: str, port: int = 443) -> Dict[str, object]:
        cached = self._global_cert_cache.get(host)
        if cached is not None:
            return cached
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=2.5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            out = {
                "host": host,
                "subject": self._flatten_cert_name(cert.get("subject", ())),
                "issuer": self._flatten_cert_name(cert.get("issuer", ())),
                "valid_from": self._format_cert_time(str(cert.get("notBefore", ""))),
                "valid_to": self._format_cert_time(str(cert.get("notAfter", ""))),
                "status": "ok",
            }
        except Exception as exc:
            out = {"host": host, "subject": "Unknown", "issuer": "Unknown", "valid_from": "", "valid_to": "", "status": "error", "error": str(exc)[:180]}
        self._global_cert_cache.set(host, out)
        return out

    def _is_probable_asset(self, content_type: str, url: str) -> bool:
        ct = (content_type or "").lower()
        if any(x in ct for x in ["image/", "font/", "audio/", "video/", "application/octet-stream", "javascript", "text/css"]):
            return True
        return bool(self._re_asset_ext.search((urlsplit(url).path or "").lower()))

    def _extract_sitemap_urls(self, seed: str, seed_host: str) -> List[str]:
        cache_key = f"{seed_host}|{seed.rstrip('/')}"
        cached = self._global_sitemap_cache.get(cache_key)
        if cached is not None:
            return cached
        found: List[str] = []
        for sm_url in [urljoin(seed, p) for p in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"]]:
            try:
                req = Request(sm_url, headers={"User-Agent": "RiskIntelCrawler/3.0"})
                with urlopen(req, timeout=4) as resp:
                    raw = resp.read(600000).decode("utf-8", errors="ignore")
                for node in ElementTree.fromstring(raw).findall(".//{*}loc"):
                    if node.text and self._same_site(seed_host, (urlsplit(node.text.strip()).hostname or "").lower()):
                        found.append(node.text.strip())
            except Exception:
                continue
        dedup: List[str] = []
        seen: Set[str] = set()
        for u in found:
            k = u.rstrip("/")
            if k not in seen:
                seen.add(k)
                dedup.append(u)
        out = dedup[:400]
        self._global_sitemap_cache.set(cache_key, out)
        return out

    def _malware_signals_from_html(self, html: str, page_url: str) -> Dict[str, object]:
        flags: List[str] = []
        score = 0.0
        lowered = html.lower()
        if re.search(r"eval\s*\(", lowered):
            score += 0.12; flags.append("JavaScript eval() usage")
        if "fromcharcode" in lowered:
            score += 0.10; flags.append("String.fromCharCode obfuscation")
        if re.search(r"\batob\s*\(", lowered):
            score += 0.08; flags.append("Base64 decode atob()")
        if re.search(r"\bunescape\s*\(", lowered):
            score += 0.08; flags.append("unescape() obfuscation primitive")
        if re.search(r"document\.write\s*\(", lowered):
            score += 0.05; flags.append("document.write dynamic injection")
        if re.findall(r"[A-Za-z0-9+/]{200,}={0,2}", html):
            score += 0.14; flags.append("Large base64-encoded blob")
        if re.search(r"<iframe[^>]*(display\s*:\s*none|width\s*=\s*[\"']?0|height\s*=\s*[\"']?0)", lowered):
            score += 0.15; flags.append("Hidden iframe behavior")
        if re.search(r"(download=|application/(x-msdownload|octet-stream))", lowered):
            score += 0.18; flags.append("Executable download vector")
        suspicious_downloads = [href for href in self._extract_html_links(html, page_url)
                                  if re.search(r"\.[a-z0-9]{2,5}$", urlsplit(href).path.lower()) and
                                  re.search(r"\.[a-z0-9]{2,5}$", urlsplit(href).path.lower()).group(0) in self.suspicious_file_ext]
        if suspicious_downloads:
            score += min(0.25, 0.09 + len(suspicious_downloads) * 0.03)
            flags.append(f"Suspicious download links: {len(suspicious_downloads)}")

        score = min(1.0, max(0.0, score))
        verdict = "likely_malicious" if score >= 0.62 else ("suspicious" if score >= 0.36 else "no_strong_malware_signal")
        return {"score": round(score, 3), "verdict": verdict, "flags": flags[:10], "suspicious_downloads": suspicious_downloads[:20]}

    def trace_website(
        self,
        website_url: str,
        max_pages: int = 120,
        max_depth: int = 4,
        include_external: bool = False,
        exhaustive: bool = True,
    ) -> Dict[str, object]:
        seed = self._normalize_site_url(website_url)
        seed_host = (urlsplit(seed).hostname or "").lower()
        if not seed_host:
            raise ValueError("Unable to parse website hostname.")

        max_pages = max(1, min(max_pages, 500))
        max_depth = max(0, min(max_depth, 8))

        queue: deque = deque([(seed, 0, None)])
        queued: Set[str] = {seed.rstrip("/")}
        visited: Set[str] = set()
        page_reports: List[Dict[str, object]] = []
        discovered_hosts: Set[str] = set()
        discovered_internal_urls: Set[str] = {seed.rstrip("/")}
        https_hosts_seen: Set[str] = set()

        if exhaustive:
            for sm_url in self._extract_sitemap_urls(seed, seed_host):
                key = sm_url.rstrip("/")
                if key not in discovered_internal_urls:
                    discovered_internal_urls.add(key)
                    if key not in queued and key not in visited:
                        queue.append((sm_url, 0, "sitemap"))
                        queued.add(key)

        while queue and len(page_reports) < max_pages:
            current, depth, parent = queue.popleft()
            canonical = current.rstrip("/")
            if canonical in visited:
                continue
            visited.add(canonical)

            page_result: Dict[str, object] = {
                "url": current, "depth": depth, "parent": parent,
                "status": "error", "status_code": None, "title": "",
                "risk_level": "low", "score": 0, "summary": "",
                "link_counts": {"internal": 0, "external": 0}, "error": None,
            }

            try:
                req = Request(current, headers={"User-Agent": "RiskIntelCrawler/3.0"})
                with urlopen(req, timeout=8) as resp:
                    status_code = int(getattr(resp, "status", resp.getcode()))
                    content_type = str(resp.headers.get("Content-Type", ""))
                    final_url = str(getattr(resp, "url", current))
                    payload = resp.read(1200000)
                final_parts = urlsplit(final_url)
                if final_parts.scheme == "https" and final_parts.hostname:
                    https_hosts_seen.add(final_parts.hostname.lower())
                html = payload.decode("utf-8", errors="ignore")
                page_text = self._html_to_text(html)[:14000]
                title = self._extract_title(html)
                malware = self._malware_signals_from_html(html, final_url)
                is_asset = self._is_probable_asset(content_type, final_url)
                ai = {"risk_level": "low", "score": 0, "summary": "Static asset.", "threat_fingerprint": None} if is_asset else self.analyze(page_text)
                extracted_links = self._extract_html_links(html, current)
                internal_links: List[str] = []
                external_links: List[str] = []
                for link in extracted_links:
                    host = (urlsplit(link).hostname or "").lower()
                    if host:
                        discovered_hosts.add(host)
                    if self._same_site(seed_host, host):
                        internal_links.append(link)
                        discovered_internal_urls.add(link.rstrip("/"))
                    else:
                        external_links.append(link)

                page_result.update({
                    "status": "ok", "status_code": status_code, "final_url": final_url,
                    "content_type": content_type, "is_asset": is_asset, "title": title,
                    "risk_level": ai["risk_level"], "score": ai["score"], "summary": ai["summary"],
                    "malware_score": int(round(float(malware["score"]) * 100)),
                    "malware_verdict": malware["verdict"], "malware_flags": malware["flags"],
                    "suspicious_downloads": malware["suspicious_downloads"],
                    "threat_fingerprint": ai["threat_fingerprint"],
                    "link_counts": {"internal": len(internal_links), "external": len(external_links)},
                    "link_preview": {"internal": internal_links[:12], "external": external_links[:12]},
                })

                if depth < max_depth:
                    for nxt in internal_links:
                        key = nxt.rstrip("/")
                        if key not in visited and key not in queued:
                            queue.append((nxt, depth + 1, current))
                            queued.add(key)
                    if include_external:
                        for nxt in external_links:
                            key = nxt.rstrip("/")
                            if key not in visited and key not in queued:
                                queue.append((nxt, depth + 1, current))
                                queued.add(key)
            except Exception as exc:
                page_result["error"] = str(exc)[:220]

            page_reports.append(page_result)

        ok_pages = [p for p in page_reports if p["status"] == "ok"]
        business_ok_pages = [p for p in ok_pages if not p.get("is_asset")]
        asset_ok_pages = [p for p in ok_pages if p.get("is_asset")]
        failed_pages = [p for p in page_reports if p["status"] != "ok"]
        high_pages = [p for p in business_ok_pages if p["risk_level"] in {"high", "critical"}]
        medium_pages = [p for p in business_ok_pages if p["risk_level"] == "medium"]
        malware_suspicious = [p for p in business_ok_pages if p.get("malware_verdict") in {"suspicious", "likely_malicious"}]
        malware_likely = [p for p in business_ok_pages if p.get("malware_verdict") == "likely_malicious"]
        top_pages = sorted(business_ok_pages, key=lambda x: int(x["score"]), reverse=True)[:8]
        avg_score = int(round(sum(int(p["score"]) for p in business_ok_pages) / max(len(business_ok_pages), 1)))
        highest = int(max((int(p["score"]) for p in business_ok_pages), default=0))
        avg_malware = int(round(sum(int(p.get("malware_score", 0)) for p in business_ok_pages) / max(len(business_ok_pages), 1)))
        highest_malware = int(max((int(p.get("malware_score", 0)) for p in business_ok_pages), default=0))

        overall = ("critical" if highest >= 80 or len(high_pages) >= 3 or len(malware_likely) >= 1
                   else ("high" if highest >= 60 or len(high_pages) >= 1 or len(malware_suspicious) >= 2
                         else ("medium" if avg_score >= 35 or len(medium_pages) >= 2 else "low")))
        coverage = int(round((len(visited) / max(len(discovered_internal_urls), 1)) * 100))
        scam_likelihood = int(min(100, round((avg_score * 0.55) + (len(high_pages) * 6) + (len(medium_pages) * 2) + (highest * 0.12))))
        malware_likelihood = int(min(100, round((avg_malware * 0.65) + (highest_malware * 0.2) + (len(malware_likely) * 15) + (len(malware_suspicious) * 4))))
        final_site_verdict = ("likely_malicious" if scam_likelihood >= 70 or malware_likelihood >= 65 or overall == "critical"
                              else ("suspicious" if scam_likelihood >= 45 or malware_likelihood >= 40 or overall in {"high", "medium"} else "likely_safe"))

        recs = []
        if high_pages: recs.append("Block/monitor high-risk pages and enforce user click protection.")
        if malware_likely: recs.append("Malware behavior detected; isolate domain and sandbox artifacts.")
        if malware_suspicious and not malware_likely: recs.append("Suspicious script patterns; perform dynamic analysis before allowing access.")
        if failed_pages: recs.append("Review failed crawl targets; hidden paths may contain suspicious content.")
        if len(discovered_hosts) > 8: recs.append("High host diversity; investigate redirect/chaining behavior.")
        if coverage < 60: recs.append("Coverage limited; increase max_pages/max_depth for full trace.")
        recs += ["Enable scheduled recrawls for threat drift detection.", "Store crawl snapshots for historical analysis."]

        cert_hosts = sorted(https_hosts_seen)[:40]
        if cert_hosts:
            with ThreadPoolExecutor(max_workers=min(10, len(cert_hosts))) as ex:
                certificates = list(ex.map(self._fetch_certificate, cert_hosts))
        else:
            certificates = []

        return {
            "seed_url": seed, "scope_host": seed_host,
            "pages_crawled": len(page_reports), "pages_ok": len(ok_pages),
            "business_pages_scanned": len(business_ok_pages), "asset_pages_skipped": len(asset_ok_pages),
            "pages_failed": len(failed_pages), "coverage_percent": coverage,
            "risk_level": overall, "average_score": avg_score, "highest_score": highest,
            "high_risk_pages": len(high_pages), "medium_risk_pages": len(medium_pages),
            "malware_suspicious_pages": len(malware_suspicious), "malware_likely_pages": len(malware_likely),
            "average_malware_score": avg_malware, "highest_malware_score": highest_malware,
            "scam_likelihood": scam_likelihood, "malware_likelihood": malware_likelihood,
            "site_verdict": final_site_verdict,
            "discovered_host_count": len(discovered_hosts), "discovered_internal_urls": len(discovered_internal_urls),
            "certificates": certificates, "certificate_hosts_scanned": len(certificates),
            "certificate_hosts_ok": sum(1 for c in certificates if c.get("status") == "ok"),
            "top_risky_pages": [
                {"url": p["url"], "title": p.get("title", ""), "score": p["score"], "risk_level": p["risk_level"],
                 "malware_score": p.get("malware_score", 0), "malware_verdict": p.get("malware_verdict", "no_strong_malware_signal"),
                 "summary": p["summary"]} for p in top_pages
            ],
            "pages": page_reports,
            "recommendations": recs[:6],
        }
        
_riskintel_original_trace_website_final = RiskEngine.trace_website


def _patched_trace_website_final(
    self: RiskEngine,
    seed_url: str,
    max_pages: int = 80,
    max_depth: int = 3,
    include_external: bool = False,
    exhaustive: bool = True,
) -> Dict[str, object]:
    result = _riskintel_original_trace_website_final(
        self,
        seed_url,
        max_pages=max_pages,
        max_depth=max_depth,
        include_external=include_external,
        exhaustive=exhaustive,
    )
    if not isinstance(result, dict):
        return result

    pages_ok = int(result.get("pages_ok") or 0)
    pages_failed = int(result.get("pages_failed") or 0)
    coverage = int(result.get("coverage_percent") or 0)
    recommendations = list(result.get("recommendations") or [])

    if pages_failed and pages_ok == 0:
        result["risk_level"] = "medium"
        result["site_verdict"] = "suspicious"
        result["scam_likelihood"] = max(int(result.get("scam_likelihood") or 0), 35)
        result["malware_likelihood"] = max(int(result.get("malware_likelihood") or 0), 20)
        message = "Crawler could not retrieve any pages; treat the scan as incomplete and verify network or host controls."
        if message not in recommendations:
            recommendations.insert(0, message)
    elif pages_failed and coverage < 60 and str(result.get("risk_level") or "low") == "low":
        result["risk_level"] = "medium"
        result["site_verdict"] = "suspicious"
        result["scam_likelihood"] = max(int(result.get("scam_likelihood") or 0), 25)

    result["recommendations"] = recommendations[:6]
    return result


RiskEngine.trace_website = _patched_trace_website_final
