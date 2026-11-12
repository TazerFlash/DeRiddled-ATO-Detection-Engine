# De-Riddled scoring API: uvicorn serving deriddled.api on port 8000.
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir uv

ENV PYTHONUNBUFFERED=1 \
    MLFLOW_DISABLE_AGENT_HINT=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH

WORKDIR /app
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --frozen --no-dev --no-install-project

COPY config.yaml ./
COPY sql ./sql
COPY deriddled ./deriddled
COPY replay ./replay
RUN uv sync --frozen --no-dev

EXPOSE 8000
CMD ["uvicorn", "deriddled.api:app", "--host", "0.0.0.0", "--port", "8000"]
