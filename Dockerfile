FROM python:3.13-slim

# System deps for LibreOffice + Ghostscript + fonts
RUN apt-get update && apt-get install -y \
    libreoffice \
    ghostscript \
    fonts-dejavu \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

ENV PYTHONUNBUFFERED=1
ENV PORT=8000

# Railway provides PORT env var automatically
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]