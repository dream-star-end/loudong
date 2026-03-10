"""FastAPI application entry point."""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from vulnhunter import __version__
from vulnhunter.api import reports, targets, tasks
from vulnhunter.api.schemas import HealthResponse
from vulnhunter.config import settings

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("VulnHunter v%s starting up…", __version__)
    try:
        from vulnhunter.db.session import init_db
        await init_db()
        logger.info("Database tables initialized")
    except Exception as e:
        logger.warning("Database not available (will work without persistence): %s", e)
    yield
    logger.info("VulnHunter shutting down…")


app = FastAPI(
    title="VulnHunter",
    description="Web Application Security Testing AI Agent",
    version=__version__,
    lifespan=lifespan,
)

app.include_router(targets.router, prefix="/api/v1")
app.include_router(tasks.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")


@app.get("/health", response_model=HealthResponse)
async def health_check() -> dict[str, object]:
    svc: dict[str, str] = {}
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.redis_url)
        await r.ping()
        svc["redis"] = "ok"
        await r.aclose()
    except Exception:
        svc["redis"] = "unavailable"

    try:
        from sqlalchemy import text

        from vulnhunter.db.session import engine
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        svc["postgres"] = "ok"
    except Exception:
        svc["postgres"] = "unavailable"

    return {"status": "ok", "version": __version__, "services": svc}
