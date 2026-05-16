# Risk Intelligence System API

This repository is backend-only. All frontend/UI files have been removed, and the project now runs as a FastAPI API service.

## Launch

```bash
cd C:\git\Risk_Intelligence_System
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/docs`

## Entry Points

- `app/main.py`: primary FastAPI application
- `app.py`: thin compatibility launcher that imports `app.main:app`

## Common API Routes

- `GET /`: service status
- `GET /api/v1/health`: health and configuration summary
- `POST /api/v1/analyze`: text analysis
- `POST /api/v1/threat-intel`: IOC enrichment
- `POST /api/v1/website-intel`: website intelligence
- `POST /api/aria/chat`: ARIA analyst chat API
- `GET /api/aria/assets`: monitored assets

## Notes

- Swagger UI remains available at `/docs`.
- The root route `/` now returns JSON instead of serving a web page.
