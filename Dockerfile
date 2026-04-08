FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md openenv.yaml requirements.txt /app/
COPY wallet_rescue_ops /app/wallet_rescue_ops
COPY inference.py /app/inference.py

RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir .

ENV PORT=7860
EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:7860/health || exit 1

CMD ["sh", "-c", "uvicorn wallet_rescue_ops.server.app:app --host 0.0.0.0 --port $PORT"]
