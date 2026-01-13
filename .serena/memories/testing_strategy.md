# Testing Strategy (tests/)

## Test Organization

### Unit Tests (tests/unit/)
Fast, isolated tests with no external dependencies.

**test_models.py**: Pydantic validation
- Valid minimal exposure event passes
- Invalid enum values rejected
- Extra fields rejected (forbid mode)
- Severity/confidence bounds enforced
- Timestamp ordering (last_seen >= first_seen)
- Status/action alignment validation
- Port required for TCP transports

**test_id_generation.py**: Deterministic IDs
- Same inputs → same exposure_id (SHA256 determinism)
- Different port → different exposure_id
- None port handled consistently
- UUIDv7 uniqueness and time-ordering
- Dedupe key with/without service_product

**test_xml_security.py**: Security hardening
- Valid XML parses successfully
- XXE attacks rejected (defusedxml)
- Entity expansion bombs rejected
- Oversized files rejected (>10MB)
- Deep nesting rejected (>50 levels)
- Normal nmap output parses correctly
- Payload sanitization (truncates long strings)
- Evidence hash computation

**test_nmap_transformer.py**: Service classification
- Parse valid nmap XML with multiple ports
- Service classification for all major classes (SSH, RDP, SMB, MySQL, Docker, K8s, git, HTTP, debug ports)
- Severity calculation by exposure class
- Deterministic exposure IDs (same scan → same IDs)
- Invalid XML rejected
- Non-nmap XML rejected
- Closed ports skipped

### Integration Tests (tests/integration/)

**test_storage_duckdb.py**: Database operations
- Insert event into exposure_events
- First event creates exposures_current row
- Second event updates last_seen but preserves first_seen
- Resolved event updates status
- Null in new event doesn't overwrite existing non-null
- Multiple offices with same exposure_id are separate
- Batch insert handles 100+ events efficiently

**test_script.py**: Script integration testing
- Valid nmap file processed successfully
- Events verified in exposure_events table
- Current exposures verified in exposures_current table
- --json flag outputs valid JSON
- Invalid XML exits with code 1
- Non-nmap XML exits with code 1
- File not found exits with code 1
- Empty scan succeeds with 0 events
- --init-db flag creates tables

### Performance Tests (tests/performance/)

**test_batch_ingest.py**: Load testing
- **10k events test**: Generate 10k synthetic events, ingest, verify <30s
  - Success criteria: total_processed=10000, elapsed<30s, memory_growth<500MB
  - Verifies throughput (events/sec) and memory stability
- **Updates test**: 5k initial + 5k overlapping events (tests upsert efficiency)
- **Query performance**: Test group by, filters, joins on 5k dataset (<1s)

Uses `generate_synthetic_events(count)` helper to create realistic diversity:
- 10 offices, 100 assets, various ports (8000-9000)
- Deterministic exposure IDs ensure overlap in update tests

## Test Fixtures (tests/fixtures/)
- **nmap_sample.xml**: Complete nmap scan with 6 open ports (SSH, HTTP, HTTPS, MySQL, PostgreSQL, Redis)
- **expected_canonical.json**: Example of canonical exposure event JSON

## Running Tests
```bash
# Unit tests (fast)
pytest tests/unit/ -v

# Integration tests (requires DB)
pytest tests/integration/ -v

# Performance tests (slow)
pytest tests/performance/ -v -s

# Coverage report
pytest --cov=src --cov-report=html
```

## Test Environment Setup
Integration/performance tests use temporary directories and in-memory/temp DuckDB databases:
- Uses pytest fixtures for setup/teardown
- Sets env vars: DB_PATH, DB_TYPE, WATCH_DIR, etc.
- Creates DatabaseManager, initializes tables with create_tables()
- Cleans up with db_manager.close()
