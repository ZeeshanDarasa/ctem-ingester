# Storage Layer (src/models/storage.py + src/storage/)

## Database Tables (SQLAlchemy ORM)

### 1. exposure_events (Append-Only Audit Log)
- **Primary key**: event_id (string)
- **Purpose**: Time series, "what changed when?" audit trail
- **Key columns**: event_id, timestamp, office_id, asset_id, exposure_id, exposure_class, exposure_status, event_action, severity, dst_ip, dst_port, protocol, raw_payload_json
- **Indexes**: (office_id, timestamp), (asset_id, timestamp), (exposure_class, exposure_status), scan_run_id, dedupe_key
- **Data retention**: Never deleted, grows indefinitely

### 2. exposures_current (Upserted Latest State)
- **Unique key**: (office_id, exposure_id)
- **Purpose**: Fast queries for current exposure state, Metabase dashboards
- **Key columns**: office_id, exposure_id, exposure_class, status, dst_ip, dst_port, protocol, severity, risk_score, first_seen, last_seen, asset_id, service_*, resource_json
- **Indexes**: (office_id, exposure_class), (status, severity), asset_id, last_seen
- **Upsert behavior**: ON CONFLICT DO UPDATE

### 3. quarantined_files (Dead-Letter Queue)
- **Purpose**: Track files that failed processing with error details
- **Key columns**: filename, file_size, file_hash, error_type, error_message, error_details_json, scanner_type, office_id, quarantined_at

## Upsert Logic (src/storage/repository.py)

### Critical Rules
1. **Preserve first_seen**: NEVER overwrite first_seen on update
2. **Update last_seen**: ALWAYS update last_seen to latest observation
3. **Null preservation**: Optional fields with existing non-null values are NOT overwritten by null in new events (uses COALESCE pattern)
4. **Always update**: status, severity, event_action, event_kind
5. **Conditionally update**: risk_score, confidence, service_*, resource_*, asset_*, disposition_*

### Batch Processing
- **Chunk size**: 500 events per transaction (optimal for DuckDB)
- **Function**: `batch_ingest_exposures(events, session)` in repository.py
- **Returns**: Dict with events_inserted, exposures_inserted, exposures_updated, total_processed

### DuckDB Specifics
- Uses `StaticPool` for connection pooling (single-writer constraint)
- INSERT ... ON CONFLICT DO UPDATE syntax supported
- Fallback to manual upsert if dialect doesn't support native upsert
- Write access must be serialized (one ingestion container)

## Connection Management (src/storage/connection.py)
- **DatabaseManager**: Singleton pattern for engine/session management
- **get_session_context()**: Context manager for transactions (auto-commit/rollback)
- **Environment vars**: DB_TYPE (duckdb/postgres), DB_PATH, DATABASE_URL
- **create_tables()**: Idempotent table creation from Base.metadata
