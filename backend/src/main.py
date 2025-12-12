import asyncio

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import socketio

from .api.routes.health import router as health_router
from .api.routes.incidents import router as incidents_router
from .api.routes.bugs import router as bugs_router
from .api.routes.correlations import router as correlations_router
from .api.routes.predictions import router as predictions_router
from .api.routes.chat import router as chat_router
from .api.routes.demo import router as demo_router
from .api.routes.webhooks import router as webhooks_router
from .config import get_settings
from .integrations.github_backfill import backfill_github_issues
from .realtime import sio

settings = get_settings()

app = FastAPI(title="DataBug AI API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router, prefix=settings.api_prefix)
app.include_router(incidents_router, prefix=settings.api_prefix)
app.include_router(bugs_router, prefix=settings.api_prefix)
app.include_router(correlations_router, prefix=settings.api_prefix)
app.include_router(predictions_router, prefix=settings.api_prefix)
app.include_router(chat_router, prefix=settings.api_prefix)
app.include_router(demo_router, prefix=settings.api_prefix)
app.include_router(webhooks_router, prefix=settings.api_prefix)

asgi_app = socketio.ASGIApp(
    sio,
    other_asgi_app=app,
    socketio_path="ws",
)


@app.get("/")
async def root() -> dict:
    return {"name": "DataBug AI", "status": "ok"}


@app.on_event("startup")
async def maybe_backfill_github() -> None:
    if not settings.github_backfill_on_start:
        return
    try:
        await asyncio.to_thread(backfill_github_issues)
    except Exception as exc:  # pragma: no cover
        print(f"[github_backfill] skipped: {type(exc).__name__}: {exc}")
