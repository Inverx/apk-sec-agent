# backend/Dockerfile — APK-SecAgent API service
FROM python:3.14-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend /app/backend
COPY mcp_server /app/mcp_server
COPY scripts /app/scripts
COPY pytest.ini /app/pytest.ini

RUN mkdir -p /app/data
ENV APKSEC_DATA_DIR_UNUSED=1

EXPOSE 8000

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
