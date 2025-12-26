from __future__ import annotations

from celery import Celery

from ..config import get_settings

settings = get_settings()

celery_app = Celery(
    "scanguard_ai",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery = celery_app
app = celery_app

