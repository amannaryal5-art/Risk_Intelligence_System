from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable, Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger("riskintel.scheduler")


class SchedulerService:
    def __init__(self, settings_loader: Callable[[str, dict], dict], settings_saver: Callable[[str, dict], Awaitable[None]], runner: Callable[[], Awaitable[str]]) -> None:
        self._settings_loader = settings_loader
        self._settings_saver = settings_saver
        self._runner = runner
        self._scheduler = AsyncIOScheduler()
        self._job_id = "autopilot_pipeline"

    @property
    def running(self) -> bool:
        return self._scheduler.running

    def start(self) -> None:
        if not self._scheduler.running:
            self._scheduler.start()

    def shutdown(self) -> None:
        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)

    def load(self) -> dict:
        return self._settings_loader("autopilot_schedule", {"enabled": False, "interval_hours": 6, "last_run": None, "next_run": None})

    async def restore(self) -> dict:
        config = self.load()
        self.start()
        if config.get("enabled"):
            await self.configure(True, int(config.get("interval_hours") or 6))
        return config

    async def configure(self, enabled: bool, interval_hours: int) -> dict:
        self.start()
        if self._scheduler.get_job(self._job_id):
            self._scheduler.remove_job(self._job_id)
        next_run = None
        if enabled:
            self._scheduler.add_job(self._fire, IntervalTrigger(hours=interval_hours), id=self._job_id, replace_existing=True)
            job = self._scheduler.get_job(self._job_id)
            next_run = job.next_run_time.isoformat() if job and job.next_run_time else None
            logger.info("Scheduler: next run at %s", next_run)
        config = {"enabled": enabled, "interval_hours": interval_hours, "last_run": None, "next_run": next_run}
        await self._settings_saver("autopilot_schedule", config)
        return config

    async def _fire(self) -> None:
        run_id = await self._runner()
        config = self.load()
        job = self._scheduler.get_job(self._job_id)
        config["last_run"] = run_id
        config["next_run"] = job.next_run_time.isoformat() if job and job.next_run_time else None
        await self._settings_saver("autopilot_schedule", config)
