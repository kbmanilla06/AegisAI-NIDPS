FROM python:3.12-slim@sha256:64695412729fbe8cf054511723820c82bbe5a077d4a6b4070cd4a7225d3422ce

# The pinned Debian slim base currently carries a vulnerable perl-base runtime,
# which is not required by the Celery worker or its Python dependencies.
RUN apt-get update \
    && apt-get purge -y --allow-remove-essential --auto-remove perl-base \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --system aegis && useradd --system --gid aegis --no-create-home --shell /usr/sbin/nologin aegis
RUN install -d -o aegis -g aegis -m 0700 \
    /var/lib/aegis/artifacts/uploads \
    /var/lib/aegis/artifacts/features \
    /var/lib/aegis/artifacts/synthetic
RUN install -d -o aegis -g aegis -m 0700 /var/lib/aegis/artifacts/models

COPY pyproject.toml ./
COPY apps/api ./apps/api
COPY apps/worker ./apps/worker
COPY services ./services
RUN python -m pip install --upgrade pip && python -m pip install '.[ml]'

USER aegis

CMD ["celery", "--app", "aegis_worker.celery_app:celery_app", "worker", "--loglevel=INFO", "--concurrency=1", "--queues=ingestion,detection,features,synthetic,ml,celery"]
