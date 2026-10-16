# FastAPI control plane image for ECS Fargate (infra/central_account/app.yaml).
# Runs with a read-only root filesystem as a non-root user. Same image serves:
#   default command                     -> API (uvicorn)
#   python -m app.workers.ttl_expiry    -> TTL expiry (scheduled task)
#   alembic upgrade head                -> one-off migration task
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml alembic.ini ./
COPY app ./app
COPY alembic ./alembic
RUN pip install . && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin sas

USER 10001
EXPOSE 8000
# Only the ALB can reach the task (security group), so its X-Forwarded-* headers are trusted.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
