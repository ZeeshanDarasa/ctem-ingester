# Exposure Ingestion Service

**Minimal footprint Python script** for processing network scan outputs and storing exposures in DuckDB. Designed to be called directly by n8n Execute Command nodes.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Initialize database (first time only)
python ingest.py dummy.xml --office-id=test --scanner-id=test --init-db

# Process a scan file
python ingest.py /path/to/scan.xml --office-id=office-1 --scanner-id=scanner-1

# JSON output (for n8n parsing)
python ingest.py /path/to/scan.xml --office-id=office-1 --scanner-id=scanner-1 --json
```

## Usage

```bash
python ingest.py <file_path> --office-id=<id> --scanner-id=<id> [options]

Arguments:
  file_path              Path to scan file (required)
  --office-id            Office identifier (required)
  --scanner-id           Scanner identifier (required)
  --scanner-type         Scanner type (default: nmap)
  --json                 Output JSON format
  --init-db              Initialize database before processing

Exit Codes:
  0  Success
  1  Error (file not found, parsing error, validation error)
```

### JSON Output

```json
{
  "status": "success",
  "file": "/path/to/scan.xml",
  "events": 15,
  "exposures_new": 10,
  "exposures_updated": 5,
  "processing_ms": 234
}
```

## n8n Integration

### Execute Command Node

```javascript
{
  "command": "python /app/ingest.py",
  "arguments": [
    "/data/scans/{{ $json.filename }}",
    "--office-id={{ $json.office_id }}",
    "--scanner-id={{ $json.scanner_id }}",
    "--json"
  ]
}
```

### With Docker

```bash
docker exec ctem-ingestion python ingest.py \
  /data/scans/scan.xml \
  --office-id=office-1 \
  --scanner-id=scanner-1 \
  --json
```

### Example n8n Workflow

```
┌─────────────────┐
│ Execute Command │  nmap -sV -oX /data/scans/scan.xml 192.168.1.0/24
└────────┬────────┘
         │
┌────────▼────────┐
│ Execute Command │  python ingest.py /data/scans/scan.xml --office-id=london --scanner-id=nmap1 --json
└────────┬────────┘
         │
┌────────▼────────┐
│ Parse JSON      │  {{ JSON.parse($json.stdout) }}
└────────┬────────┘
         │
    ┌────▼────┐
    │ Success? │
    └─┬─────┬─┘
  Yes │     │ No
      │     │
   Move     Alert
   File     Team
```

## Minimal Dependencies

**Only 6 core packages:**

```txt
pydantic==2.9.2          # Data validation
sqlalchemy==2.0.35        # ORM
duckdb==1.1.3            # Database
duckdb-engine==0.13.2    # SQLAlchemy dialect
defusedxml==0.7.1        # Secure XML parsing
uuid-utils==0.9.0        # UUIDv7 ID generation
```

No web frameworks, no async, no heavyweight dependencies. Just pure Python processing.

## Project Structure

```
ingestion/
├── ingest.py                    # Main script (~300 lines)
├── requirements.txt             # 6 dependencies
└── src/
    ├── models/
    │   ├── canonical.py         # Pydantic validation models
    │   └── storage.py           # SQLAlchemy ORM models
    ├── transformers/
    │   ├── base.py              # BaseTransformer interface
    │   ├── registry.py          # Simple transformer registry
    │   └── nmap_transformer.py  # nmap XML → canonical
    ├── storage/
    │   ├── database.py          # Connection management
    │   └── repository.py        # Batch insert/upsert
    └── utils/
        ├── id_generation.py     # Deterministic IDs
        └── security.py          # XML security
```

## Extensibility: Adding New Scanners

The transformer pattern makes it trivial to add support for new scanner types:

### 1. Create Transformer Class

```python
# src/transformers/masscan_transformer.py
from pathlib import Path
from typing import List
from src.transformers.base import BaseTransformer
from src.models.canonical import ExposureEventModel

class MasscanTransformer(BaseTransformer):
    def transform(
        self,
        file_path: Path,
        office_id: str,
        scanner_id: str
    ) -> List[ExposureEventModel]:
        # Parse masscan JSON/XML
        # Map to canonical ExposureEventModel
        # Return list of events
        pass
```

### 2. Register in Registry

```python
# src/transformers/registry.py
from src.transformers.masscan_transformer import MasscanTransformer

_TRANSFORMERS = {
    'nmap': NmapTransformer(),
    'masscan': MasscanTransformer()  # Add new transformer
}
```

### 3. Use It

```bash
python ingest.py scan.json --scanner-type=masscan --office-id=office-1 --scanner-id=scanner-1
```

## Configuration

### Environment Variables

```bash
DB_PATH=/app/data/exposures.duckdb  # Database file location
```

### Database Schema

**exposure_events** (append-only audit log):
- Primary key: `event_id`
- Stores: timestamps, office_id, asset_id, exposure_id, severity, network details, full payload
- Purpose: Time series, audit trail

**exposures_current** (upserted state):
- Unique key: `(office_id, exposure_id)`
- Stores: latest status, first_seen, last_seen, severity, asset details, service info
- Purpose: Fast queries for dashboards

**quarantined_files**:
- Tracks failed processing attempts with error details

## Docker Deployment

### Build

```bash
cd ingestion
docker build -f docker/Dockerfile -t ctem-ingestion .
```

### Run

```bash
docker run -v /path/to/data:/app/data \
           -v /path/to/scans:/data/scans \
           ctem-ingestion \
           python ingest.py /data/scans/scan.xml \
           --office-id=office-1 --scanner-id=scanner-1
```

### With Docker Compose

```yaml
services:
  ingestion:
    image: ctem-ingestion
    volumes:
      - scan_data:/data/scans:ro
      - duckdb_data:/app/data
    environment:
      - DB_PATH=/app/data/exposures.duckdb
```

## Testing

```bash
# Run unit tests
pytest tests/unit/ -v

# Run integration tests
pytest tests/integration/ -v

# Test with sample file
python ingest.py tests/fixtures/nmap_sample.xml \
  --office-id=test --scanner-id=test --json
```

## Core Features

### Security
- **Secure XML parsing** with defusedxml (prevents XXE, entity expansion)
- **Size limits**: 10MB max file size, 50-level max depth
- **Data minimization**: Stores only metadata, uses evidence hashes for sensitive data

### Validation
- **Strict Pydantic v2 models** with `extra="forbid"` and `strict=True`
- **Enum enforcement** for all categorical fields
- **Field validators**: severity [0-100], confidence [0-1], port [0-65535]
- **Invariant checks**: last_seen ≥ first_seen, status/action alignment

### Storage
- **Dual-table design**: append-only events + upserted current state
- **Smart upsert**: preserves first_seen and non-null fields
- **Batch processing**: 500-event chunks for optimal performance
- **Deterministic IDs**: SHA256-based exposure IDs for deduplication

## Exposure Classifications

| Class | Description | Severity |
|-------|-------------|----------|
| `db_exposed` | MySQL, PostgreSQL, MongoDB, Redis | 90 |
| `container_api_exposed` | Docker, Kubernetes APIs | 85 |
| `remote_admin_exposed` | SSH, RDP, VNC | 70 |
| `fileshare_exposed` | SMB, AFP file shares | 65 |
| `debug_port_exposed` | Chrome DevTools, IDE servers | 60 |
| `vcs_protocol_exposed` | Git daemon | 55 |
| `http_content_leak` | Web servers | 50 |
| `unknown_service_exposed` | Unidentified ports | 30 |

## Troubleshooting

### File Not Found
Ensure the file path is absolute and accessible from the container/environment.

### Validation Errors
Check that the XML is valid nmap output. Use `--json` flag to see detailed error messages.

### Database Errors
Ensure the database directory is writable. Use `--init-db` flag to create tables.

### Exit Code 1
Run with `--json` flag to get structured error output:
```json
{
  "status": "error",
  "error": "File not found: /path/to/scan.xml",
  "file": "/path/to/scan.xml"
}
```

## Performance

- **Typical scan** (10-20 exposures): ~200-500ms
- **Large scan** (100+ exposures): ~1-2s
- **Batch processing**: 500 events/chunk for optimal DuckDB performance

## License

Internal use only - CTEM Team
