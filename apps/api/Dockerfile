FROM python:3.12-slim@sha256:64695412729fbe8cf054511723820c82bbe5a077d4a6b4070cd4a7225d3422ce

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN addgroup --system aegis && adduser --system --ingroup aegis aegis

COPY pyproject.toml ./
COPY apps/api ./apps/api
COPY apps/worker ./apps/worker
COPY services ./services
RUN python -m pip install --upgrade pip && python -m pip install .

USER aegis
EXPOSE 8000

CMD ["uvicorn", "aegis_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
