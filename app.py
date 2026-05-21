"""Thin launcher that avoids the `app.py` vs `app/` import collision on Vercel."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_app():
    package_name = "riskintel_app"
    package_dir = Path(__file__).resolve().parent / "app"
    init_file = package_dir / "__init__.py"

    package = sys.modules.get(package_name)
    if package is None:
        spec = importlib.util.spec_from_file_location(
            package_name,
            init_file,
            submodule_search_locations=[str(package_dir)],
        )
        if spec is None or spec.loader is None:
            raise ImportError(f"Unable to load package from {init_file}")
        package = importlib.util.module_from_spec(spec)
        sys.modules[package_name] = package
        spec.loader.exec_module(package)

    return package.app


app = _load_app()
