# Changelog

## [Unreleased]

### Added
- **Automatic Database Initialization**: Database tables are now automatically detected and created on first run
  - `check_tables_exist()`: Validates presence of required tables using SQLAlchemy inspection
  - `ensure_database_initialized()`: Idempotent table creation with optional verbose mode
  - Auto-invoked in `get_db_session()` context manager for transparent operation
  - Zero-config deployment: no manual `--init-db` flag required

### Changed
- `get_db_session()`: Now automatically initializes database before creating sessions
- `--init-db` flag in `ingest.py`: Now optional (auto-detection works by default)
- Updated README.md with auto-initialization documentation
- Updated SRS.md to document auto-initialization requirements

### Technical Details
- Uses `sqlalchemy.inspect()` to check for existing tables
- Creates only missing tables via `Base.metadata.create_all()`
- Safe for concurrent operations and restarts
- Required tables: `exposure_events`, `exposures_current`, `quarantined_files`

## Benefits
- **Zero-config**: No manual database setup required
- **Idempotent**: Safe to run multiple times
- **Production-ready**: Tables created automatically on first deployment
- **Developer-friendly**: Works out of the box for local development
