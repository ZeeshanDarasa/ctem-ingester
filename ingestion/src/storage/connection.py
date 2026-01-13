"""
Database connection management.
Supports DuckDB initially, designed for easy swap to Postgres.
"""

import os
from pathlib import Path
from typing import Generator
from sqlalchemy import create_engine, Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from src.models.storage import Base


class DatabaseConfig:
    """Database configuration from environment."""
    
    def __init__(self):
        self.db_type = os.getenv('DB_TYPE', 'duckdb')
        self.db_path = os.getenv('DB_PATH', '/app/data/exposures.duckdb')
        self.db_url = os.getenv('DATABASE_URL', '')
        
        # Connection pool settings
        self.pool_size = int(os.getenv('DB_POOL_SIZE', '5'))
        self.max_overflow = int(os.getenv('DB_MAX_OVERFLOW', '10'))
    
    def get_connection_string(self) -> str:
        """Get SQLAlchemy connection string."""
        if self.db_url:
            return self.db_url
        
        if self.db_type == 'duckdb':
            # Ensure parent directory exists
            db_path = Path(self.db_path)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            return f"duckdb:///{self.db_path}"
        
        elif self.db_type == 'postgres':
            # Construct from env vars
            host = os.getenv('DB_HOST', 'localhost')
            port = os.getenv('DB_PORT', '5432')
            user = os.getenv('DB_USER', 'postgres')
            password = os.getenv('DB_PASSWORD', '')
            database = os.getenv('DB_NAME', 'exposures')
            return f"postgresql://{user}:{password}@{host}:{port}/{database}"
        
        else:
            raise ValueError(f"Unsupported DB_TYPE: {self.db_type}")


class DatabaseManager:
    """Manages database engine and sessions."""
    
    def __init__(self, config: DatabaseConfig | None = None):
        self.config = config or DatabaseConfig()
        self._engine: Engine | None = None
        self._session_factory: sessionmaker | None = None
    
    def get_engine(self) -> Engine:
        """Get or create SQLAlchemy engine."""
        if self._engine is None:
            connection_string = self.config.get_connection_string()
            
            # DuckDB-specific settings
            if self.config.db_type == 'duckdb':
                # Use StaticPool for single-writer DuckDB
                self._engine = create_engine(
                    connection_string,
                    poolclass=StaticPool,
                    connect_args={'read_only': False}
                )
            else:
                # Standard pool for Postgres
                self._engine = create_engine(
                    connection_string,
                    pool_size=self.config.pool_size,
                    max_overflow=self.config.max_overflow
                )
        
        return self._engine
    
    def get_session_factory(self) -> sessionmaker:
        """Get or create session factory."""
        if self._session_factory is None:
            self._session_factory = sessionmaker(
                bind=self.get_engine(),
                autocommit=False,
                autoflush=False
            )
        return self._session_factory
    
    def get_session(self) -> Session:
        """Create a new database session."""
        factory = self.get_session_factory()
        return factory()
    
    def create_tables(self):
        """Create all tables in the database."""
        engine = self.get_engine()
        Base.metadata.create_all(engine)
    
    def drop_tables(self):
        """Drop all tables (for testing)."""
        engine = self.get_engine()
        Base.metadata.drop_all(engine)
    
    def close(self):
        """Close database connections."""
        if self._engine:
            self._engine.dispose()
            self._engine = None
            self._session_factory = None


def get_session_context(db_manager: DatabaseManager | None = None) -> Generator[Session, None, None]:
    """
    Context manager for database sessions.
    
    Usage:
        with get_session_context() as session:
            # Use session
            session.add(obj)
            session.commit()
    
    Args:
        db_manager: Optional DatabaseManager instance
    
    Yields:
        Database session
    """
    manager = db_manager or DatabaseManager()
    session = manager.get_session()
    
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
