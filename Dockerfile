FROM python:3.12-slim

LABEL maintainer="legit-lab"
LABEL description="Lab pedagogique de triage de legitimite (PDF/URL) : heuristiques statiques + VirusTotal + URLhaus + Safe Browsing + ML + rapport multilingue (FR/EN/AR) genere par IA."

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /app/
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Build the ML dataset + model at image build time so the container
# starts instantly (no training delay on first run).
RUN python generate_dataset.py && python ml_model.py

RUN mkdir -p /app/uploads

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/')" || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
