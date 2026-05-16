"""
ARIA - AI Risk Intelligence Analyst
Core AI engine powered by Groq for threat analysis, chat, and reporting.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Dict, List

from groq import Groq

logger = logging.getLogger("aria.ai")


def _groq(system: str, messages: list, max_tokens: int) -> str:
    client = Groq(api_key=os.getenv("GROQ_API_KEY", ""))
    resp = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "system", "content": system}] + messages,
        max_tokens=max_tokens,
        temperature=0.2,
    )
    return resp.choices[0].message.content


ANALYST_SYSTEM = """You are ARIA (Automated Risk Intelligence Analyst), an expert AI cybersecurity analyst embedded in a real-time threat monitoring platform.

You have access to live threat intelligence data from VirusTotal, AbuseIPDB, AlienVault OTX, and web crawling systems. Your job is to analyze threats with expert precision and communicate clearly.

Rules:
- Be direct, confident, and specific. No vague hedging.
- Use expert cybersecurity terminology but explain when needed.
- Prioritize actionability - tell users what to DO, not just what's wrong.
- When asked about monitored assets, reference the context data provided.
- Respond conversationally for chat, formally for reports.
"""

REPORT_SYSTEM = """You are an expert cybersecurity analyst writing daily threat intelligence briefings for a security operations team. Write comprehensive, professional reports with clear sections. Use markdown. Be specific, cite actual findings, and prioritize by severity."""


async def analyze_threat(target: str, scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Use Groq to intelligently analyze raw threat intel scan results.
    Returns structured risk assessment.
    """
    prompt = f"""Analyze this threat intelligence data for target: {target}

RAW SCAN DATA:
{json.dumps(scan_data, indent=2)}

Return ONLY a JSON object with this exact structure (no markdown, no preamble):
{{
  "risk_level": "Critical|High|Medium|Low|Clean",
  "risk_score": <integer 0-100>,
  "summary": "<2-3 sentence expert assessment>",
  "key_findings": ["<specific finding>", ...],
  "threat_indicators": ["<IOC or indicator>", ...],
  "recommendations": ["<specific action>", ...],
  "threat_categories": ["<category like Malware/Phishing/C2/Clean>", ...]
}}"""

    try:
        raw = await asyncio.to_thread(
            _groq,
            ANALYST_SYSTEM,
            [{"role": "user", "content": prompt}],
            1000,
        )
        raw = raw.strip()
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw.strip())
    except json.JSONDecodeError as e:
        logger.error(f"AI returned non-JSON for {target}: {e}")
    except Exception as e:
        logger.error(f"AI analysis failed for {target}: {e}")

    return {
        "risk_level": "Unknown",
        "risk_score": 0,
        "summary": "AI analysis temporarily unavailable. Raw scan data still collected.",
        "key_findings": [],
        "threat_indicators": [],
        "recommendations": ["Retry analysis manually"],
        "threat_categories": [],
    }


async def chat(
    messages: List[Dict[str, str]],
    system_context: str = "",
) -> str:
    """
    Multi-turn conversation with ARIA about threats, assets, and risk intelligence.
    messages: list of {"role": "user"|"assistant", "content": "..."}
    system_context: live data injected as system context (assets, alerts, etc.)
    """
    system = ANALYST_SYSTEM
    if system_context:
        system += f"\n\nLIVE SYSTEM STATE:\n{system_context}"

    try:
        return await asyncio.to_thread(_groq, system, messages, 1000)
    except Exception as e:
        logger.error(f"Chat failed: {e}")
        return "AI engine temporarily unavailable. Please check your GROQ_API_KEY and try again."


async def generate_daily_report(
    assets: List[Dict],
    recent_scans: List[Dict],
    alerts: List[Dict],
) -> str:
    """
    Auto-generate a comprehensive daily threat intelligence briefing.
    Called automatically by the scheduler every 24 hours.
    """
    critical = [a for a in assets if a.get("last_risk_level") in ("Critical", "High")]
    clean = [a for a in assets if a.get("last_risk_level") == "Clean"]
    unknown = [a for a in assets if not a.get("last_risk_level")]

    prompt = f"""Generate a daily threat intelligence briefing based on this monitoring data.

MONITORED ASSETS: {len(assets)} total
- Critical/High risk: {len(critical)} assets
- Clean: {len(clean)} assets
- Not yet scanned: {len(unknown)} assets

HIGH RISK ASSETS:
{json.dumps([{"asset": a.get("value"), "risk": a.get("last_risk_level"), "summary": a.get("last_summary", "")} for a in critical], indent=2)}

SCANS IN LAST 24H ({len(recent_scans)} total):
{json.dumps([{"asset": s.get("asset_value"), "risk": s.get("risk_level"), "score": s.get("risk_score"), "findings": json.loads(s.get("key_findings") or "[]")[:2]} for s in recent_scans[:20]], indent=2)}

ACTIVE ALERTS ({len(alerts)}):
{json.dumps([{"asset": a.get("asset_value"), "level": a.get("risk_level"), "title": a.get("title")} for a in alerts[:10]], indent=2)}

Write a professional daily threat briefing with:
# Daily Threat Intelligence Briefing
## Executive Summary
## Critical Findings (if any - be specific)
## Asset Risk Overview
## Top Threats Detected
## Recommended Actions (prioritized by severity)
## Trend Notes

Use markdown. Be specific - name actual assets and findings. Do not be generic."""

    try:
        return await asyncio.to_thread(
            _groq,
            REPORT_SYSTEM,
            [{"role": "user", "content": prompt}],
            2000,
        )
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return f"# Daily Threat Intelligence Briefing\n\n**Report generation failed:** {e}\n\nPlease check your API key and try again."


async def summarize_asset(asset_value: str, history: List[Dict]) -> str:
    """Generate a quick AI summary for a single asset based on its scan history."""
    if not history:
        return "No scan history yet. Asset will be analyzed on the next scheduled scan."

    prompt = f"""Summarize the threat history for: {asset_value}

SCAN HISTORY (most recent first):
{json.dumps([{"date": h.get("scanned_at"), "risk": h.get("risk_level"), "score": h.get("risk_score"), "summary": h.get("summary")} for h in history[:10]], indent=2)}

Write 2-3 sentences covering: current risk status, any concerning trends, and what to watch for. Be specific."""

    try:
        return await asyncio.to_thread(
            _groq,
            ANALYST_SYSTEM,
            [{"role": "user", "content": prompt}],
            300,
        )
    except Exception as e:
        logger.error(f"Asset summary failed: {e}")
        return "Summary temporarily unavailable."
