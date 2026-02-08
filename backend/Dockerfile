FROM python:3.10-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl unzip \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
ENV HF_HOME=/root/.cache/huggingface
ENV TRANSFORMERS_CACHE=/root/.cache/huggingface/hub
RUN python - <<'PY'
from sentence_transformers import SentenceTransformer

# Preload embeddings model used by Pinecone semantic retrieval to avoid
# first-request download stalls in chat endpoints.
SentenceTransformer("all-MiniLM-L6-v2")
PY
ENV HF_HUB_OFFLINE=1
ENV TRANSFORMERS_OFFLINE=1

RUN curl -sSL https://github.com/aquasecurity/trivy/releases/download/v0.56.2/trivy_0.56.2_Linux-64bit.tar.gz -o /tmp/trivy.tar.gz \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz \
    && chmod +x /usr/local/bin/trivy

COPY src ./src
COPY alembic ./alembic
COPY alembic.ini ./

EXPOSE 8000

CMD ["uvicorn", "src.main:asgi_app", "--host", "0.0.0.0", "--port", "8000"]
