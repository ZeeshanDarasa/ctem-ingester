"""
Simple database connection management.
"""

import os
from contextlib import contextmanager
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from src.models.storage import Base


# Global engine and session factory
_engine = None
_SessionFactory = None


def get_engine():
    """Get or create database engine."""
    global _engine
    
    if _engine is None:
        db_path = os.getenv('DB_PATH', '/app/data/exposures.duckdb')
        
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
    Get database session context manager.
    
    Usage:
        with get_db_session() as session:
            # Use session
            session.add(obj)
            # Auto-commits on success, rolls back on error
    """
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


def init_database():
    """Initialize database tables (idempotent)."""
    engine = get_engine()
    Base.metadata.create_all(engine)
