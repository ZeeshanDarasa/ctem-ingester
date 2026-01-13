FROM python:3.12-slim

LABEL maintainer="CTEM Team"
LABEL description="Exposure Ingestion Service"

WORKDIR /app

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy source
COPY ingest.py .
COPY src/ ./src/

# Create data directory
RUN mkdir -p /app/data

# Set environment
ENV PYTHONUNBUFFERED=1
ENV DB_PATH=/app/data/exposures.duckdb

# Make script executable
RUN chmod +x ingest.py

# Default: initialize database on first run
CMD ["python", "ingest.py", "--init-db", "--help"]
