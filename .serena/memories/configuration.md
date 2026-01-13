# Configuration & Environment

## Environment Variables

### Database Configuration
- **DB_TYPE**: Database type (default: "duckdb", also supports: "postgres")
- **DB_PATH**: Path to DuckDB file (default: "/app/data/exposures.duckdb")
- **DATABASE_URL**: Full connection string (overrides DB_TYPE/DB_PATH if set)
  - Example: "postgresql://user:pass@host:5432/dbname"
- **DB_POOL_SIZE**: Connection pool size for Postgres (default: 5)
- **DB_MAX_OVERFLOW**: Max overflow connections (default: 10)

### Script Configuration
- **DB_PATH**: Database file location (default: "/app/data/exposures.duckdb")

### Service Configuration
- **LOG_LEVEL**: Logging level (default: "INFO", options: DEBUG, INFO, WARNING, ERROR)
- **HTTP_PORT**: Port for health/metrics HTTP server (default: 8000)

## Docker Configuration

### Dockerfile (ingestion/docker/Dockerfile)
- Base: python:3.12-slim
- Installs system deps: gcc (for compilation)
- Copies requirements.txt, installs Python packages
- Copies src/ directory
- Creates data directories: /data/{scan_results,processed,quarantine}, /app/data
- Sets PYTHONUNBUFFERED=1 for immediate log output
- CMD: ["python", "-m", "src.main"]
- Health check: Simple Python command every 30s

### Docker Deployment
**Container**: ctem-ingestion
- Base: python:3.12-slim
- Working dir: /app
- Volumes:
  - scan_data:/data/scans:ro (shared with n8n)
  - duckdb_data:/app/data (database storage, shared with Metabase)
- Environment: DB_PATH=/app/data/exposures.duckdb
- Usage: Call script via docker exec

**n8n Integration**:
```bash
docker exec ctem-ingestion python ingest.py /data/scans/scan.xml --office-id=X --scanner-id=Y --json
```

**Volume Setup**:
- scan_data: Shared between n8n (write) and ingestion (read)
- duckdb_data: Shared between ingestion (write) and Metabase (read-only)

## n8n Workflow Integration
n8n workflows call the ingestion API after scan completes with file path and metadata.

**Example HTTP Request Node**:
```json
{
  "method": "POST",
  "url": "http://ingestion:8000/ingest",
  "body": {
    "file_path": "/data/scans/scan_{{ $now }}.xml",
    "office_id": "{{ $json.office_id }}",
    "scanner_id": "{{ $json.scanner_id }}"
  }
}
```

**Example Execute Command Node** (CLI alternative):
```bash
python -m src.cli process-file /data/scans/scan.xml \
  --office-id=office-1 --scanner-id=scanner-1 --json-output
```

## Development Setup (Local)
```bash
cd ingestion
pip install -r requirements.txt

# Set environment
export DB_PATH=/tmp/exposures.duckdb
export WATCH_DIR=/tmp/scan_results
export PROCESSED_DIR=/tmp/processed
export QUARANTINE_DIR=/tmp/quarantine
export DEFAULT_OFFICE_ID=office-1
export LOG_LEVEL=DEBUG

# Initialize database
python -c "from src.storage.connection import DatabaseManager; db = DatabaseManager(); db.create_tables()"

# Run service
python -m src.main
```



## Metabase Connection
- Database type: DuckDB
- Database path: /app/data/exposures.duckdb (read-only mount)
- Query tables: exposures_current (for dashboards), exposure_events (for time series)
