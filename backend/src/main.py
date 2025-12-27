import asyncio

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import socketio

from .api.routes.health import router as health_router
from .api.routes.bugs import router as bugs_router
from .api.routes.chat import router as chat_router
from .api.routes.demo import router as demo_router
from .api.routes.profile import router as profile_router
from .api.routes.repositories import router as repositories_router
from .api.routes.scans import findings_router, router as scans_router
from .api.routes.webhooks import router as webhooks_router
from .config import get_settings
from .integrations.github_backfill import backfill_github_issues
from .realtime import sio

settings = get_settings()

app = FastAPI(title="ScanGuard AI API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router, prefix=settings.api_prefix)
app.include_router(bugs_router, prefix=settings.api_prefix)
app.include_router(chat_router, prefix=settings.api_prefix)
app.include_router(demo_router, prefix=settings.api_prefix)
app.include_router(profile_router, prefix=settings.api_prefix)
app.include_router(repositories_router, prefix=settings.api_prefix)
app.include_router(scans_router, prefix=settings.api_prefix)
app.include_router(findings_router, prefix=settings.api_prefix)
app.include_router(webhooks_router, prefix=settings.api_prefix)

@app.get("/")
async def root() -> dict:
    return {"name": "ScanGuard AI", "status": "ok"}


@app.on_event("startup")
async def maybe_backfill_github() -> None:
    if not settings.github_backfill_on_start:
        return
    try:
        await asyncio.to_thread(backfill_github_issues)
    except Exception as exc:  # pragma: no cover
        print(f"[github_backfill] skipped: {type(exc).__name__}: {exc}")


asgi_app = socketio.ASGIApp(
    sio,
    other_asgi_app=app,
    socketio_path="ws",
)


class _CombinedApp:
    def __init__(self, fastapi_app: FastAPI, socketio_app: socketio.ASGIApp) -> None:
        self._fastapi_app = fastapi_app
        self._socketio_app = socketio_app

    async def __call__(self, scope, receive, send):
        await self._socketio_app(scope, receive, send)

    def __getattr__(self, name: str):
        return getattr(self._fastapi_app, name)


app = _CombinedApp(app, asgi_app)
