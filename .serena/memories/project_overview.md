# Project Overview - Exposure Ingestion Service

## Purpose
Minimal Python script that processes network scan outputs (nmap XML), validates them using strict Pydantic models, and stores exposures in DuckDB. Designed to be called directly by n8n Execute Command nodes.

## Architecture (Minimal Footprint)
```
n8n Execute Command → python ingest.py /path/to/scan.xml → Transforms → Validates → DuckDB
```

**Key principle**: Single Python script, no web frameworks, no daemons, just on-demand processing.

## Quick Usage
```bash
python ingest.py /path/to/scan.xml --office-id=office-1 --scanner-id=scanner-1 --json
```

**Exit codes**: 0 (success), 1 (error)

**JSON output**:
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

## Technology Stack (Minimal)
- Python 3.12+ with argparse (built-in CLI)
- Pydantic v2.9.2 (strict validation)
- SQLAlchemy 2.0.35 + DuckDB 1.1.3 (database)
- defusedxml 0.7.1 (secure XML parsing)
- uuid-utils 0.9.0 (ID generation)

**Total dependencies: 6 core packages** (no web frameworks, no heavyweight libraries)

## Project Structure (Minimal)
```
ingestion/
├── ingest.py                # Main script (~300 lines)
├── requirements.txt         # 6 dependencies
└── src/
    ├── models/              # canonical.py + storage.py
    ├── transformers/        # base.py + registry.py + nmap_transformer.py
    ├── storage/             # database.py + repository.py
    └── utils/               # id_generation.py + security.py
```

## Key Design Principles
1. **Minimal footprint**: No unnecessary dependencies or frameworks
2. **Strict validation**: Pydantic v2 with `extra="forbid"` and `strict=True`
3. **Secure parsing**: defusedxml for XXE/entity expansion protection
4. **Deterministic IDs**: SHA256-based exposure IDs for deduplication
5. **Dual-table storage**: append-only events + upserted current state
6. **Extensible**: Simple BaseTransformer interface for adding new scanners

## n8n Integration
Execute Command node:
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

Parse output: `{{ JSON.parse($json.stdout) }}`
Check success: `{{ $json.exitCode === 0 }}`

## Performance
- Typical scan (10-20 exposures): ~200-500ms
- Large scan (100+ exposures): ~1-2s
- Batch processing: 500 events/chunk
