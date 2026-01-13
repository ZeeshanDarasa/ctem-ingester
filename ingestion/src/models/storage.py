"""
SQLAlchemy ORM models for database storage.
Defines two tables: exposure_events (append-only) and exposures_current (upserted).
"""

from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, DateTime, Boolean, JSON, Text,
    UniqueConstraint, Index, func
)
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class ExposureEvent(Base):
    """
    Append-only audit log of all exposure events.
    Stores time series data for "what changed when?" analysis.
    """
    __tablename__ = "exposure_events"
    
    # Primary key
    event_id = Column(String, primary_key=True)
    
    # Core timestamps and identifiers
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    office_id = Column(String, nullable=False, index=True)
    asset_id = Column(String, nullable=False, index=True)
    exposure_id = Column(String, nullable=False, index=True)
    
    # Exposure details
    exposure_class = Column(String, nullable=False)
    exposure_status = Column(String, nullable=False)
    event_action = Column(String, nullable=False)
    event_kind = Column(String, nullable=False)
    
    # Severity and risk
    severity = Column(Integer, nullable=False)
    risk_score = Column(Float, nullable=True)
    confidence = Column(Float, nullable=True)
    
    # Network vector details
    dst_ip = Column(String, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    transport = Column(String, nullable=True)
    network_direction = Column(String, nullable=True)
    
    # Service details (JSON for flexibility)
    service_json = Column(JSON, nullable=True)
    resource_json = Column(JSON, nullable=True)
    
    # Scanner and correlation
    scanner_id = Column(String, nullable=False, index=True)
    scanner_type = Column(String, nullable=False)
    scan_run_id = Column(String, nullable=True, index=True)
    dedupe_key = Column(String, nullable=True, index=True)
    
    # Full canonical payload (sanitized)
    raw_payload_json = Column(JSON, nullable=False)
    
    # Audit timestamp
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    
    # Indexes for common queries
    __table_args__ = (
        Index('idx_events_office_timestamp', 'office_id', 'timestamp'),
        Index('idx_events_asset_timestamp', 'asset_id', 'timestamp'),
        Index('idx_events_class_status', 'exposure_class', 'exposure_status'),
    )


class ExposureCurrent(Base):
    """
    Current state of exposures (upserted).
    Optimized for Metabase dashboards and KRI queries.
    """
    __tablename__ = "exposures_current"
    
    # Auto-increment primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Unique business key
    office_id = Column(String, nullable=False)
    exposure_id = Column(String, nullable=False)
    
    # Exposure classification
    exposure_class = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False, index=True)
    
    # Network vector
    dst_ip = Column(String, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    transport = Column(String, nullable=True)
    network_direction = Column(String, nullable=True)
    
    # Severity and risk
    severity = Column(Integer, nullable=False)
    risk_score = Column(Float, nullable=True)
    confidence = Column(Float, nullable=True)
    
    # Timestamps (first_seen preserved, last_seen updated)
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    
    # Asset details
    asset_id = Column(String, nullable=False, index=True)
    asset_hostname = Column(String, nullable=True)
    asset_ip = Column(String, nullable=True)
    asset_mac = Column(String, nullable=True)
    asset_os = Column(String, nullable=True)
    asset_managed = Column(Boolean, nullable=True)
    
    # Service details (flattened for easier querying)
    service_name = Column(String, nullable=True)
    service_product = Column(String, nullable=True)
    service_version = Column(String, nullable=True)
    service_tls = Column(Boolean, nullable=True)
    service_auth = Column(String, nullable=True)
    service_bind_scope = Column(String, nullable=True)
    
    # Full service/resource JSON for complete data
    service_json = Column(JSON, nullable=True)
    resource_json = Column(JSON, nullable=True)
    
    # Latest event details
    event_action = Column(String, nullable=False)
    event_kind = Column(String, nullable=False)
    
    # Scanner information
    scanner_id = Column(String, nullable=False)
    scanner_type = Column(String, nullable=False)
    
    # Office context (for dimensional analysis)
    office_name = Column(String, nullable=False)
    office_region = Column(String, nullable=True)
    office_network_zone = Column(String, nullable=True)
    
    # Data classification
    data_class_json = Column(JSON, nullable=True)
    
    # Disposition
    disposition_ticket = Column(String, nullable=True)
    disposition_owner = Column(String, nullable=True)
    disposition_sla = Column(String, nullable=True)
    
    # Audit timestamps
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=True, onupdate=func.now())
    
    # Constraints and indexes
    __table_args__ = (
        UniqueConstraint('office_id', 'exposure_id', name='uq_office_exposure'),
        Index('idx_current_office_class', 'office_id', 'exposure_class'),
        Index('idx_current_status_severity', 'status', 'severity'),
        Index('idx_current_asset', 'asset_id'),
        Index('idx_current_last_seen', 'last_seen'),
    )


class QuarantinedFile(Base):
    """
    Log of files that failed processing.
    Used for dead-letter queue and troubleshooting.
    """
    __tablename__ = "quarantined_files"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # File details
    filename = Column(String, nullable=False)
    file_size = Column(Integer, nullable=True)
    file_hash = Column(String, nullable=True)
    
    # Error details
    error_type = Column(String, nullable=False)
    error_message = Column(Text, nullable=False)
    error_details_json = Column(JSON, nullable=True)
    
    # Processing context
    scanner_type = Column(String, nullable=True)
    office_id = Column(String, nullable=True)
    
    # Timestamps
    quarantined_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    
    # Index for troubleshooting
    __table_args__ = (
        Index('idx_quarantine_time', 'quarantined_at'),
        Index('idx_quarantine_error_type', 'error_type'),
    )
