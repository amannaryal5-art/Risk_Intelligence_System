from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"


def _load_backend_app():
    app_dir = BASE_DIR / "app"
    app_dir_str = str(app_dir)
    if app_dir_str not in sys.path:
        sys.path.insert(0, app_dir_str)
    backend_path = BASE_DIR / "app" / "main.py"
    spec = importlib.util.spec_from_file_location("riskintel_backend_main", backend_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load backend app from {backend_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


backend_app = _load_backend_app()

app = FastAPI(
    title="RiskIntel v3.0 UI",
    version="3.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data: https://tile.openstreetmap.org; "
        "style-src 'self'; "
        "font-src 'self' data:; "
        "script-src 'self'; "
        "connect-src 'self' ws: wss:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    return response


def render_page(request: Request, template_name: str, title: str, view: str) -> HTMLResponse:
    return templates.TemplateResponse(
        name=template_name,
        request=request,
        context={
            "page_title": title,
            "page_view": view,
            "app_version": "v3.0",
            "ws_path": "",
            "ioc_stream_path": "/api/v1/ioc/stream",
        },
    )


@app.get("/", response_class=HTMLResponse)
async def root(request: Request) -> HTMLResponse:
    return render_page(request, "command.html", "Command Center", "command")


@app.get("/login", response_class=HTMLResponse)
async def login(request: Request) -> HTMLResponse:
    return render_page(request, "login.html", "Login", "login")


@app.get("/cases", response_class=HTMLResponse)
async def cases(request: Request) -> HTMLResponse:
    return render_page(request, "cases.html", "Operations Center", "cases")


@app.get("/feeds", response_class=HTMLResponse)
async def feeds(request: Request) -> HTMLResponse:
    return render_page(request, "feeds.html", "Feed Orchestration", "feeds")


@app.get("/campaigns", response_class=HTMLResponse)
async def campaigns(request: Request) -> HTMLResponse:
    return render_page(request, "campaigns.html", "Campaign Tracker", "campaigns")


@app.get("/actors", response_class=HTMLResponse)
async def actors(request: Request) -> HTMLResponse:
    return render_page(request, "actors.html", "Threat Actors", "actors")


@app.get("/assets", response_class=HTMLResponse)
async def assets(request: Request) -> HTMLResponse:
    return render_page(request, "assets.html", "Asset Inventory", "assets")


@app.get("/reports", response_class=HTMLResponse)
async def reports(request: Request) -> HTMLResponse:
    return render_page(request, "reports.html", "Reports Center", "reports")


@app.get("/workbench", response_class=HTMLResponse)
async def workbench(request: Request) -> HTMLResponse:
    return render_page(request, "workbench.html", "Analyst Workbench", "workbench")


@app.get("/settings", response_class=HTMLResponse)
async def settings(request: Request) -> HTMLResponse:
    return render_page(request, "settings.html", "Automation Rules", "settings")


@app.get("/command", include_in_schema=False)
async def command_alias() -> RedirectResponse:
    return RedirectResponse(url="/", status_code=307)


app.mount("/", backend_app)


if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("app:app", host=host, port=port, reload=False)
