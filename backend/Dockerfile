FROM python:3.10-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl unzip \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

RUN curl -sSL https://github.com/aquasecurity/trivy/releases/download/v0.56.2/trivy_0.56.2_Linux-64bit.tar.gz -o /tmp/trivy.tar.gz \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz \
    && chmod +x /usr/local/bin/trivy

COPY src ./src
COPY alembic ./alembic
COPY alembic.ini ./

EXPOSE 8000

CMD ["uvicorn", "src.main:asgi_app", "--host", "0.0.0.0", "--port", "8000"]
