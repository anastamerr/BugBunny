FROM python:3.10-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl unzip \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.1/nuclei_3.3.1_linux_amd64.zip -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei

RUN curl -sSL https://github.com/aquasecurity/trivy/releases/download/v0.56.2/trivy_0.56.2_Linux-64bit.tar.gz -o /tmp/trivy.tar.gz \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz \
    && chmod +x /usr/local/bin/trivy

COPY src ./src

EXPOSE 8000

CMD ["uvicorn", "src.main:asgi_app", "--host", "0.0.0.0", "--port", "8000"]
