"""
Simple database connection management with auto-initialization.
"""

import os
from contextlib import contextmanager
from pathlib import Path
from sqlalchemy import create_engine, Integer, inspect
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.compiler import compiles

from src.models.storage import Base


# Fix for DuckDB: prevent SERIAL generation
@compiles(Integer, 'duckdb')
def compile_integer_duckdb(type_, compiler, **kw):
    """Compile INTEGER type for DuckDB (avoid SERIAL)."""
    return "INTEGER"


# Global engine and session factory
_engine = None
_SessionFactory = None


def get_engine():
    """Get or create database engine."""
    global _engine
    
    if _engine is None:
        db_path = os.getenv('DB_PATH', './data/exposures.duckdb')
        
        # Ensure parent directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        connection_string = f"duckdb:///{db_path}"
        _engine = create_engine(connection_string, echo=False)
    
    return _engine


def get_session_factory():
    """Get or create session factory."""
    global _SessionFactory
    
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(bind=get_engine())
    
    return _SessionFactory


@contextmanager
def get_db_session() -> Session:
    """
    Get database session context manager with auto-initialization.
    Automatically ensures database tables exist before creating session.
    
    Usage:
        with get_db_session() as session:
            # Use session
            session.add(obj)
            # Auto-commits on success, rolls back on error
    """
    # Ensure database is initialized (auto-detection)
    ensure_database_initialized(verbose=False)
    
    factory = get_session_factory()
    session = factory()
    
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def check_tables_exist(engine=None) -> bool:
    """
    Check if all required tables exist in the database.
    
    Args:
        engine: SQLAlchemy engine (uses default if None)
    
    Returns:
        True if all required tables exist, False otherwise
    """
    if engine is None:
        engine = get_engine()
    
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    
    # Required tables from storage models
    required_tables = {'exposure_events', 'exposures_current', 'quarantined_files'}
    
    return required_tables.issubset(existing_tables)


def ensure_database_initialized(verbose: bool = False):
    """
    Ensure database is initialized with automatic detection.
    Creates tables if they don't exist (idempotent).
    
    Args:
        verbose: If True, print initialization messages
    
    Returns:
        SQLAlchemy engine
    """
    engine = get_engine()
    
    if not check_tables_exist(engine):
        if verbose:
            print("Initializing database tables...")
        Base.metadata.create_all(engine)
        if verbose:
            print("✓ Database initialized successfully")
    
    return engine


def init_database():
    """
    Initialize database tables (idempotent).
    Legacy function - prefer ensure_database_initialized().
    """
    engine = get_engine()
    Base.metadata.create_all(engine)
