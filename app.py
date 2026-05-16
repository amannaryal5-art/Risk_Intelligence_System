"""Thin launcher - lets `uvicorn app:app` work from the project root."""
from app.main import app  # noqa: F401
