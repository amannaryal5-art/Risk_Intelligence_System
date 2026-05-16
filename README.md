# Risk Intelligence System

CRIE v3.0 now includes both:

- A FastAPI backend at `http://127.0.0.1:8000`
- A Vite + React command-and-control dashboard for analysts

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

## Frontend Launch

```bash
# Install
npm install

# Development
npm run dev

# Build
npm run build

# Preview
npm run preview
```

The frontend reads:

```env
VITE_API_BASE=http://127.0.0.1:8000
```

## Frontend Stack

- React 18
- Vite
- Tailwind CSS
- Zustand
- TanStack Query v5
- React Router v6
- Recharts
- Framer Motion
- Axios
- Lucide React

## Entry Points

- `app/main.py`: primary FastAPI application
- `app.py`: thin compatibility launcher that imports `app.main:app`
- `src/App.jsx`: SPA routing and protected app shell
- `src/components/layout/Shell.jsx`: sidebar, topbar, command palette, live feed strip

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
- The frontend does not use mock data; views are wired to live API endpoints.
- Vite proxies `/api` to the local FastAPI server in development.
