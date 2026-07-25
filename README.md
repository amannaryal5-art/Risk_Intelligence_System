# Risk Intelligence System

CRIE checks suspicious links, IPs, hashes, messages, and files with local scoring and live threat intelligence.

## Run the API

~~~powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
~~~

API documentation is at http://127.0.0.1:8000/docs.

## Run the console

In a second terminal:

~~~powershell
npm install
npm run dev
~~~

Open http://127.0.0.1:3000. The Next.js server proxies requests to http://127.0.0.1:8000 and passes RISKINTEL_API_KEY to the API server-side, so keys are never copied into the browser. Set RISKINTEL_BACKEND_URL only when the API is hosted elsewhere.

## Live endpoints

- GET /api/v1/health
- POST /api/v1/analyze
- POST /api/v1/scamcheck
- POST /api/v1/threat-intel
- POST /api/v1/website-intel
- POST /api/v1/trace-website
- POST /api/v1/fusion-scan
- POST /api/v1/malware/analyze-file
