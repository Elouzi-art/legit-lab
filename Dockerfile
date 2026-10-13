FROM python:3.12-slim

LABEL maintainer="legit-lab"
LABEL description="Lab pedagogique de triage de legitimite (PDF/URL) : heuristiques statiques + VirusTotal + URLhaus + Safe Browsing + ML + rapport multilingue (FR/EN/AR) genere par IA."

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production

WORKDIR /app

# Apply Debian security updates
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

# Install and update Python dependencies
COPY requirements.txt .
RUN python -m pip install --no-cache-dir --upgrade pip==26.2.1 \
    && python -m pip install --no-cache-dir -r requirements.txt

COPY app/ /app/
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Build the ML dataset and model at image build time
RUN python generate_dataset.py && python ml_model.py

RUN mkdir -p /app/uploads

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/')" || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
