from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
APP_DIR = BASE_DIR / "app"
MAIN_PATH = APP_DIR / "main.py"

sys.path.insert(0, str(APP_DIR))
spec = importlib.util.spec_from_file_location("riskintel_main", MAIN_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Could not load FastAPI entrypoint from {MAIN_PATH}")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
app = module.app
