# Storage Interface - Database Layer

## Simple Connection Management (src/storage/database.py)

### Core Functions

**get_engine()** - Get or create SQLAlchemy engine
- Singleton pattern for efficiency
- Creates DuckDB connection string from DB_PATH env var
- Ensures parent directory exists

**get_session_factory()** - Get or create session factory
- Uses sessionmaker bound to engine
- Cached globally

**get_db_session()** - Context manager for database sessions
```python
with get_db_session() as session:
    # Use session
    session.add(obj)
    # Auto-commits on success, rolls back on error
```

**init_database()** - Initialize database tables
- Idempotent (safe to call multiple times)
- Creates all tables from Base.metadata

### Environment Variables
- `DB_PATH`: Database file location (default: "/app/data/exposures.duckdb")

## Repository Layer (src/storage/repository.py)

### Main Function

**ingest_events(session, events)** - Batch ingest exposure events

**Parameters**:
- `session`: SQLAlchemy session
- `events`: List[ExposureEventModel]

**Returns**:
```python
{
    'events_inserted': 15,
    'exposures_inserted': 10,
    'exposures_updated': 5
}
```

**Process**:
1. Batch insert into `exposure_events` (append-only)
2. Batch upsert into `exposures_current` (latest state)
3. Transaction committed by context manager

### Internal Details

**ExposureRepository** class handles:
- `batch_insert_events()`: Insert into append-only events table
- `batch_upsert_current()`: Upsert into current state table
  - Preserves `first_seen` (never overwritten)
  - Updates `last_seen` to latest observation
  - Preserves non-null optional fields (uses COALESCE pattern)
  - Updates: status, severity, event_action, risk_score

**Batch Size**: 500 events per chunk (optimal for DuckDB)

## Database Tables (src/models/storage.py)

### exposure_events (Append-Only)
- Primary key: event_id
- Purpose: Time series audit log
- Key columns: timestamp, office_id, asset_id, exposure_id, severity, dst_ip, dst_port, protocol, raw_payload_json
- Indexes: (office_id, timestamp), (asset_id, timestamp), scan_run_id

### exposures_current (Upserted)
- Unique key: (office_id, exposure_id)
- Purpose: Fast queries for dashboards
- Key columns: exposure_id, exposure_class, status, first_seen, last_seen, severity, asset details, service info
- Indexes: (office_id, exposure_class), (status, severity), last_seen

### quarantined_files
- Purpose: Track failed processing attempts
- Key columns: filename, error_type, error_message, error_details_json, quarantined_at

## Usage in ingest.py

```python
from src.storage.database import get_db_session, init_database
from src.storage.repository import ingest_events

# Initialize (first time)
init_database()

# Ingest events
with get_db_session() as session:
    stats = ingest_events(session, events)
    # Transaction auto-commits on success
```

## Design Philosophy
- **Simple**: Context managers, clear function names
- **Safe**: Auto-commit/rollback, idempotent initialization
- **Efficient**: Batch processing, connection pooling
- **Minimal**: No connection pool complexity, no metrics overhead
