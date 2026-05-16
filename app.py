from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import uvicorn


BASE_DIR = Path(__file__).resolve().parent
APP_DIR = BASE_DIR / "app"
MAIN_PATH = APP_DIR / "main.py"


def _load_app():
    # On Vercel, the top-level app.py module name can shadow the app/ package.
    # Load the FastAPI module by path and add app/ to sys.path so its local
    # sibling imports continue to work.
    sys.path.insert(0, str(APP_DIR))
    spec = importlib.util.spec_from_file_location("riskintel_main", MAIN_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load FastAPI entrypoint from {MAIN_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


app = _load_app()


if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host=host, port=port, reload=False)
