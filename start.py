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
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".venv"
IS_WIN = sys.platform.startswith("win")

VENV_PY  = VENV_DIR / ("Scripts/python.exe" if IS_WIN else "bin/python")
VENV_PIP = VENV_DIR / ("Scripts/pip.exe"    if IS_WIN else "bin/pip")

BACKEND_PORT  = 8000
FRONTEND_PORT = 3000


def log(msg: str) -> None:
    print(f"\033[96m[CRIE Launcher]\033[0m {msg}", flush=True)


def check_and_prepare_env() -> None:
    env_file    = ROOT / ".env"
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


def kill_port(port: int) -> None:
    """Kill every process listening on `port`. Waits until the port is free."""
    if not IS_WIN:
        try:
            subprocess.run(f"fuser -k {port}/tcp", shell=True, capture_output=True)
        except Exception:
            pass
        return

    for attempt in range(3):
        res = subprocess.run(
            f"netstat -ano | findstr :{port}",
            shell=True, capture_output=True, text=True,
        )
        killed_any = False
        for line in res.stdout.splitlines():
            if f":{port}" not in line:
                continue
            if "LISTENING" not in line.upper() and "ESTABLISHED" not in line.upper():
                continue
            parts = line.strip().split()
            if not parts:
                continue
            pid = parts[-1]
            if pid in ("0", str(os.getpid())):
                continue
            log(f"  Stopping process PID {pid} holding port {port}...")
            subprocess.run(
                f"taskkill /F /T /PID {pid}",
                shell=True, capture_output=True,
            )
            killed_any = True

        if not killed_any:
            break
        time.sleep(0.8)   # give OS time to release the port

    # Final confirmation wait
    for _ in range(10):
        res = subprocess.run(
            f"netstat -ano | findstr :{port} | findstr LISTENING",
            shell=True, capture_output=True, text=True,
        )
        if not res.stdout.strip():
            return          # port is free
        time.sleep(0.5)

    log(f"  Warning: port {port} may still be in use. Trying to continue anyway...")


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
            proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def wait_for_backend(
    url: str = f"http://127.0.0.1:{BACKEND_PORT}/api/v1/health",
    max_wait: float = 30.0,
) -> bool:
    start = time.time()
    while time.time() - start < max_wait:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def main() -> None:
    os.chdir(ROOT)
    print("\n" + "=" * 60)
    print("   SAFECHECK / CRIE — STARTING UP")
    print("=" * 60 + "\n")

    check_and_prepare_env()
    ensure_python_venv()
    ensure_node_modules()

    # ── Free ports BEFORE starting anything ──────────────────────
    log(f"Freeing port {BACKEND_PORT} (backend)...")
    kill_port(BACKEND_PORT)
    log(f"Freeing port {FRONTEND_PORT} (frontend)...")
    kill_port(FRONTEND_PORT)
    log("Ports cleared.\n")

    # ── Start FastAPI backend ─────────────────────────────────────
    log(f"Starting FastAPI Backend on http://127.0.0.1:{BACKEND_PORT} ...")
    backend_cmd = [
        str(VENV_PY), "-m", "uvicorn", "app.main:app",
        "--host", "127.0.0.1",
        "--port", str(BACKEND_PORT),
    ]
    backend_proc = subprocess.Popen(
        backend_cmd,
        cwd=ROOT,
    )

    if not wait_for_backend():
        log("ERROR: Backend failed to start.")
        sys.exit(1)

    log(f"✓ Backend is UP — http://127.0.0.1:{BACKEND_PORT}/docs\n")

    # ── Start Next.js frontend ────────────────────────────────────
    log(f"Starting Next.js Frontend on http://localhost:{FRONTEND_PORT} ...")
    npm_cmd = "npm.cmd" if IS_WIN else "npm"
    frontend_proc = subprocess.Popen(
        [npm_cmd, "run", "dev"],
        cwd=ROOT,
        shell=IS_WIN,
    )

    # Wait for frontend to be ready before opening browser
    log("Waiting for frontend to compile (up to 30s)...")
    for i in range(30):
        time.sleep(1)
        try:
            with urllib.request.urlopen(f"http://localhost:{FRONTEND_PORT}", timeout=2) as r:
                if r.status == 200:
                    break
        except Exception:
            pass

    import webbrowser
    log("Opening browser at http://localhost:3000 ...")
    try:
        webbrowser.open("http://localhost:3000")
    except Exception:
        pass

    print()
    print("=" * 60)
    print("  ✓  SAFECHECK is running!")
    print(f"     Frontend → http://localhost:{FRONTEND_PORT}")
    print(f"     Backend  → http://127.0.0.1:{BACKEND_PORT}/docs")
    print()
    print("     Press Ctrl+C in this window to stop everything.")
    print("=" * 60 + "\n")

    # ── Monitor both processes ────────────────────────────────────
    try:
        while True:
            time.sleep(1)
            if backend_proc.poll() is not None:
                log("Backend stopped unexpectedly. Shutting down...")
                break
            if frontend_proc.poll() is not None:
                log("Frontend stopped unexpectedly. Shutting down...")
                break

    except KeyboardInterrupt:
        log("\nStopping servers...")
    finally:
        kill_proc_tree(backend_proc)
        kill_proc_tree(frontend_proc)
        # Also kill anything still on the ports
        kill_port(BACKEND_PORT)
        kill_port(FRONTEND_PORT)
        log("All services stopped cleanly. Goodbye!\n")


if __name__ == "__main__":
    main()
