# Risk Intelligence System

CRIE v3.0 provides a FastAPI backend at `http://127.0.0.1:8000`.

## Backend Launch

```bash
cd C:\git\Risk_Intelligence_System
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open backend docs at `http://127.0.0.1:8000/docs`.

## Entry Points

- `app/main.py`: primary FastAPI application
- `app.py`: thin compatibility launcher that imports `app.main:app`

## API Highlights

- `GET /api/v1/auth/whoami`
- `GET /api/v1/health`
- `POST /api/v1/analyze`
- `POST /api/v1/analyze/batch`
- `POST /api/v1/scamcheck`
- `POST /api/v1/fusion-scan`
- `POST /api/v1/threat-intel`
- `POST /api/v1/website-intel`
- `POST /api/v1/trace-website`
- `POST /api/v1/malware/analyze-file`
- `GET /api/v1/cases`
- `POST /api/aria/chat`
- `GET /api/aria/assets`

## Notes

- Swagger UI remains available at `/docs`.
