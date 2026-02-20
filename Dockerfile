FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

RUN useradd -m -s /bin/bash appuser && \
    mkdir -p /data && \
    chown appuser:appuser /data

USER appuser

ENV SHIELDVIEW_DATA_DIR=/data
ENV PYTHONPATH=/app
ENV PORT=5000

EXPOSE 5000

CMD gunicorn --bind "0.0.0.0:${PORT}" --workers 2 --timeout 30 --access-logfile - "app.app:create_app()"
