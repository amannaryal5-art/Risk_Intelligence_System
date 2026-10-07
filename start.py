"""
One-click launcher for the Risk Intelligence System (CRIE).
Runs both the FastAPI backend and Next.js frontend with automated dependency checks.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".venv"
IS_WIN = sys.platform.startswith("win")

VENV_PY = VENV_DIR / ("Scripts/python.exe" if IS_WIN else "bin/python")
VENV_PIP = VENV_DIR / ("Scripts/pip.exe" if IS_WIN else "bin/pip")


def log(msg: str) -> None:
    print(f"\033[96m[CRIE Launcher]\033[0m {msg}", flush=True)


def check_and_prepare_env() -> None:
    env_file = ROOT / ".env"
    env_example = ROOT / ".env.example"
    if not env_file.exists() and env_example.exists():
        log("Creating .env from .env.example...")
        shutil.copyfile(env_example, env_file)


def ensure_python_venv() -> None:
    if not VENV_PY.exists():
        log("Creating Python virtual environment (.venv)...")
        subprocess.check_call([sys.executable, "-m", "venv", str(VENV_DIR)], cwd=ROOT)

    req_file = ROOT / "requirements.txt"
    if req_file.exists():
        log("Ensuring Python backend dependencies are installed...")
        subprocess.check_call(
            [str(VENV_PY), "-m", "pip", "install", "-q", "-r", str(req_file)],
            cwd=ROOT,
        )


def ensure_node_modules() -> None:
    node_modules = ROOT / "node_modules"
    if not node_modules.exists():
        log("Installing frontend dependencies (npm install)...")
        npm_cmd = "npm.cmd" if IS_WIN else "npm"
        subprocess.check_call([npm_cmd, "install"], cwd=ROOT, shell=IS_WIN)


def kill_proc_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        if IS_WIN:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            proc.terminate()
            proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def wait_for_backend(url: str = "http://127.0.0.1:8000/api/v1/health", max_wait: float = 15.0) -> bool:
    start = time.time()
    while time.time() - start < max_wait:
        try:
            with urllib.request.urlopen(url, timeout=1.5) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.4)
    return False


def main() -> None:
    os.chdir(ROOT)
    print("\n" + "=" * 60)
    print("   RISK INTELLIGENCE SYSTEM (CRIE) - UNIFIED LAUNCHER")
    print("=" * 60 + "\n")

    check_and_prepare_env()
    ensure_python_venv()
    ensure_node_modules()

    log("Starting FastAPI Backend on http://127.0.0.1:8000 ...")
    backend_cmd = [
        str(VENV_PY),
        "-m",
        "uvicorn",
        "app.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        "8000",
    ]
    backend_proc = subprocess.Popen(backend_cmd, cwd=ROOT)

    if not wait_for_backend():
        log("Warning: Backend health check took longer than expected. Continuing...")
    else:
        log("Backend is UP and healthy (http://127.0.0.1:8000/docs)")

    log("Starting Next.js Frontend Console on http://localhost:3000 ...")
    npm_cmd = "npm.cmd" if IS_WIN else "npm"
    frontend_proc = subprocess.Popen([npm_cmd, "run", "dev"], cwd=ROOT, shell=IS_WIN)

    # Open browser once services are active
    time.sleep(2)
    log("Opening browser at http://localhost:3000 ...")
    try:
        webbrowser.open("http://localhost:3000")
    except Exception:
        pass

    log("\nEverything is running! Press Ctrl+C in this window to stop both servers.\n")

    try:
        while True:
            time.sleep(1)
            if backend_proc.poll() is not None:
                log("Backend process stopped unexpectedly.")
                break
            if frontend_proc.poll() is not None:
                log("Frontend process stopped unexpectedly.")
                break
    except KeyboardInterrupt:
        log("\nStopping servers...")
    finally:
        kill_proc_tree(backend_proc)
        kill_proc_tree(frontend_proc)
        log("All services stopped cleanly. Goodbye!\n")


if __name__ == "__main__":
    main()

