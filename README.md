# Risk Intelligence System

Professional Python-based rule + NLP fraud detection platform with a futuristic dark UI.

## Features
- Hybrid detection engine: deterministic rules + NLP-style token/bigram similarity + behavioral text signals
- Advanced link intelligence: traces normal and obfuscated links (`hxxp`, `[.]`), inspects domain/IP/port/query-risk markers
- Plain-language verdict and top red-flag explanations
- Confidence scoring for analyst trust level
- Automated response playbook recommendations with deterministic threat fingerprinting
- Full website crawler and tracer: scans pages recursively, scores each page, and highlights top risky paths
- One-click fusion scan endpoint that combines message and website telemetry into unified module posture
- Deep website verdicting: scam likelihood + malware likelihood + coverage score + likely_malicious/suspicious/likely_safe verdict
- Risk scoring model from 0-100 with levels: `low`, `medium`, `high`, `critical`
- Explainable detections via weighted signal evidence
- Analyst features: copy summary, report export, file analysis, and recent scan history
- REST API endpoints for single and batch analysis
- Company-ready backbone: API-key auth, RBAC, persistent case management, and audit logging
- Futuristic, SOC-style dark interface for analysts

## Tech Stack
- FastAPI
- Vanilla HTML/CSS/JS frontend

## Quick Start
```bash
cd "C:\git\risk_intellignce_system"
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python -m uvicorn app.main:app --reload
```

Open: http://127.0.0.1:8000

If you are inside the `app` folder, use this instead:
```bash
python -m uvicorn main:app --reload
```

## API
- `GET /api/v1/health`
- `GET /api/v1/auth/whoami`
- `POST /api/v1/analyze`
```json
{ "text": "Urgent! buy gift cards and send codes now" }
```
- `POST /api/v1/analyze/batch`
```json
{ "texts": ["text 1", "text 2"] }
```

- `POST /api/v1/trace-website`
```json
{
  "url": "https://example.com",
  "max_pages": 120,
  "max_depth": 4,
  "include_external": false,
  "exhaustive": true
}
```

- `POST /api/v1/fusion-scan`
```json
{
  "text": "Optional suspicious message to score",
  "website_url": "https://example.com",
  "max_pages": 80,
  "max_depth": 3,
  "include_external": false,
  "exhaustive": true
}
```

- `POST /api/v1/threat-intel`
```json
{
  "text": "Optional text containing URLs/IPs/domains/hashes",
  "urls": ["https://example.com/login"],
  "domains": ["example.com"],
  "ips": ["8.8.8.8"],
  "hashes": ["44d88612fea8a8f36de82e1278abb02f"],
  "live_feeds": true
}
```

- `POST /api/v1/malware/analyze-file`
```json
{
  "filename": "invoice.pdf",
  "content_base64": "<base64-bytes>"
}
```

Optional live feed keys:
- `RISKINTEL_OTX_API_KEY`
- `RISKINTEL_ABUSEIPDB_API_KEY`
- `RISKINTEL_VT_API_KEY`

### Enterprise Endpoints
- `POST /api/v1/cases`
- `POST /api/v1/cases/from-analysis`
- `GET /api/v1/cases`
- `GET /api/v1/cases/{case_id}`
- `PATCH /api/v1/cases/{case_id}`
- `POST /api/v1/cases/{case_id}/comments`
- `GET /api/v1/audit` (admin only)

### Auth / RBAC
- Header: `X-API-Key: <key>`
- Authentication is enforced by default.
- Configure keys using:
  - `RISKINTEL_API_KEYS=key1:admin:alice,key2:analyst:bob,key3:viewer:eve`
- Optional backend default key (for trusted internal UI calls without header):
  - `RISKINTEL_DEFAULT_API_KEY=key2`
- Optional live feed default:
  - `RISKINTEL_USE_LIVE_FEEDS=true`
- Optional:
  - set `RISKINTEL_ENFORCE_AUTH=false` only for isolated local testing

## Notes
For production hardening, add:
- Model calibration with labeled domain data
- AuthN/AuthZ and audit logging
- Prompt/attack-resilient preprocessing pipeline
- Persistent storage and workflow queues
