# Self-hosted sync worker (staging): the pipeline Lambdas run in one long-lived process (selfhosted_worker).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY . .
RUN pip install . && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin sas

USER 10001
CMD ["python", "-m", "selfhosted_worker"]
