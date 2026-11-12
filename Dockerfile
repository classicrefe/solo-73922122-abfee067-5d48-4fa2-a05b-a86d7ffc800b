FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN addgroup --system app && adduser --system --ingroup app --no-create-home app \
    && chown -R app:app /app

USER app

EXPOSE 8000

# Exactly one web process.  Scan work happens in short-lived worker
# subprocesses spawned by the app, not in additional uvicorn workers.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
