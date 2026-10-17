from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.v1 import router as v1_router
from app.api.v1.sync import ws_router
from app.config import get_settings
from app.database import SessionLocal, engine, redis_client


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    await redis_client.aclose()
    await engine.dispose()


settings = get_settings()
app = FastAPI(title="SAS Threat Intelligence & Centralized WAF Security Platform", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Content-Type"],
)
app.include_router(v1_router)
app.include_router(ws_router)


@app.get("/healthz", include_in_schema=False)
async def healthz() -> JSONResponse:
    """Load-balancer health check: PostgreSQL and Redis reachable. Unauthenticated, reveals nothing else."""
    try:
        async with SessionLocal() as session:
            await session.execute(text("SELECT 1"))
        await redis_client.ping()
    except Exception:
        return JSONResponse({"status": "unavailable"}, status_code=503)
    return JSONResponse({"status": "ok"})
