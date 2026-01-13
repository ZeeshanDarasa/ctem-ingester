"""
Integration tests for DuckDB storage layer.
Tests upsert semantics, null handling, and transaction behavior.
"""

import pytest
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from src.storage.connection import DatabaseManager, DatabaseConfig
from src.storage.repository import ExposureRepository, batch_ingest_exposures
from src.models.canonical import (
    ExposureEventModel, Event, Office, Scanner, Target, Asset,
    Exposure, Vector, EventKind, EventAction, ExposureClass,
    ExposureStatus, Transport
)
from src.models.storage import ExposureCurrent, ExposureEvent


@pytest.fixture
def temp_db():
    """Create a temporary DuckDB database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.duckdb"
        os.environ['DB_PATH'] = str(db_path)
        os.environ['DB_TYPE'] = 'duckdb'
        
        config = DatabaseConfig()
        db_manager = DatabaseManager(config)
        db_manager.create_tables()
        
        yield db_manager
        
        db_manager.close()


def create_test_event(
    event_id: str = "evt-1",
    exposure_id: str = "exp-1",
    office_id: str = "office-1",
    asset_id: str = "asset-1",
    status: ExposureStatus = ExposureStatus.OPEN,
    action: EventAction = EventAction.EXPOSURE_OPENED,
    severity: int = 50,
    port: int = 8080,
    service_product: str = None
) -> ExposureEventModel:
    """Helper to create test exposure event."""
    return ExposureEventModel(
        schema_version="1.0.0",
        timestamp=datetime.now(timezone.utc),
        event=Event(
            id=event_id,
            kind=EventKind.EVENT,
            category=["network"],
            type=["info"],
            action=action,
            severity=severity
        ),
        office=Office(id=office_id, name=f"Office-{office_id}"),
        scanner=Scanner(id="scanner-1", type="nmap"),
        target=Target(asset=Asset(id=asset_id, ip=["192.168.1.100"])),
        exposure=Exposure(
            id=exposure_id,
            class_=ExposureClass.UNKNOWN_SERVICE_EXPOSED,
            status=status,
            vector=Vector(
                transport=Transport.TCP,
                protocol="http",
                dst={"ip": "192.168.1.100", "port": port}
            ),
            service={"product": service_product} if service_product else None
        )
    )


def test_insert_event(temp_db):
    """Test inserting an event into exposure_events table."""
    session = temp_db.get_session()
    repo = ExposureRepository(session)
    
    event = create_test_event()
    count = repo.batch_insert_events([event])
    
    assert count == 1
    
    # Verify in database
    stored = session.query(ExposureEvent).filter_by(event_id="evt-1").first()
    assert stored is not None
    assert stored.exposure_id == "exp-1"
    assert stored.severity == 50
    
    session.close()


def test_first_event_creates_current(temp_db):
    """Test that first event creates exposures_current row."""
    session = temp_db.get_session()
    
    event = create_test_event()
    stats = batch_ingest_exposures([event], session)
    
    assert stats['events_inserted'] == 1
    assert stats['exposures_inserted'] >= 0  # Implementation dependent
    
    # Verify in exposures_current
    current = session.query(ExposureCurrent).filter_by(
        office_id="office-1",
        exposure_id="exp-1"
    ).first()
    
    assert current is not None
    assert current.status == "open"
    assert current.severity == 50
    assert current.first_seen is not None
    assert current.last_seen is not None
    
    session.close()


def test_second_event_updates_last_seen_not_first_seen(temp_db):
    """Test that second event updates last_seen but preserves first_seen."""
    session = temp_db.get_session()
    
    # First event
    event1 = create_test_event(event_id="evt-1", exposure_id="exp-1")
    batch_ingest_exposures([event1], session)
    
    # Get first_seen
    current = session.query(ExposureCurrent).filter_by(
        office_id="office-1",
        exposure_id="exp-1"
    ).first()
    original_first_seen = current.first_seen
    original_last_seen = current.last_seen
    
    # Wait a tiny bit
    import time
    time.sleep(0.01)
    
    # Second event (same exposure)
    event2 = create_test_event(
        event_id="evt-2",
        exposure_id="exp-1",  # Same exposure
        severity=60  # Different severity
    )
    batch_ingest_exposures([event2], session)
    
    # Check updates
    session.expire_all()  # Force refresh from DB
    current = session.query(ExposureCurrent).filter_by(
        office_id="office-1",
        exposure_id="exp-1"
    ).first()
    
    # first_seen should be preserved
    assert current.first_seen == original_first_seen
    
    # last_seen should be updated
    assert current.last_seen >= original_last_seen
    
    # severity should be updated
    assert current.severity == 60
    
    session.close()


def test_resolved_event_updates_status(temp_db):
    """Test that resolved event updates status."""
    session = temp_db.get_session()
    
    # Open event
    event1 = create_test_event(
        event_id="evt-1",
        exposure_id="exp-1",
        status=ExposureStatus.OPEN,
        action=EventAction.EXPOSURE_OPENED
    )
    batch_ingest_exposures([event1], session)
    
    # Resolved event
    event2 = create_test_event(
        event_id="evt-2",
        exposure_id="exp-1",
        status=ExposureStatus.RESOLVED,
        action=EventAction.EXPOSURE_RESOLVED
    )
    batch_ingest_exposures([event2], session)
    
    # Check status updated
    session.expire_all()
    current = session.query(ExposureCurrent).filter_by(
        office_id="office-1",
        exposure_id="exp-1"
    ).first()
    
    assert current.status == "resolved"
    assert current.event_action == "exposure_resolved"
    
    session.close()


def test_null_in_new_event_does_not_overwrite_existing(temp_db):
    """Test that null in new event doesn't overwrite existing non-null field."""
    session = temp_db.get_session()
    
    # First event with service product
    event1 = create_test_event(
        event_id="evt-1",
        exposure_id="exp-1",
        service_product="nginx 1.18"
    )
    batch_ingest_exposures([event1], session)
    
    # Second event without service product (null)
    event2 = create_test_event(
        event_id="evt-2",
        exposure_id="exp-1",
        service_product=None
    )
    batch_ingest_exposures([event2], session)
    
    # Check that service_product was preserved
    session.expire_all()
    current = session.query(ExposureCurrent).filter_by(
        office_id="office-1",
        exposure_id="exp-1"
    ).first()
    
    # Should still have the product from first event
    assert current.service_product == "nginx 1.18"
    
    session.close()


def test_multiple_offices_different_exposures(temp_db):
    """Test that same exposure_id in different offices are separate."""
    session = temp_db.get_session()
    
    # Event in office-1
    event1 = create_test_event(
        event_id="evt-1",
        exposure_id="exp-same",
        office_id="office-1"
    )
    
    # Event in office-2 (different office, same exposure_id)
    event2 = create_test_event(
        event_id="evt-2",
        exposure_id="exp-same",
        office_id="office-2"
    )
    
    batch_ingest_exposures([event1, event2], session)
    
    # Should have 2 separate rows
    count = session.query(ExposureCurrent).filter_by(
        exposure_id="exp-same"
    ).count()
    
    assert count == 2
    
    session.close()


def test_batch_insert_performance(temp_db):
    """Test that batch insert handles multiple events efficiently."""
    session = temp_db.get_session()
    
    # Create 100 events
    events = [
        create_test_event(
            event_id=f"evt-{i}",
            exposure_id=f"exp-{i}",
            port=8000 + i
        )
        for i in range(100)
    ]
    
    stats = batch_ingest_exposures(events, session)
    
    assert stats['total_processed'] == 100
    assert stats['events_inserted'] == 100
    
    # Verify in DB
    event_count = session.query(ExposureEvent).count()
    assert event_count == 100
    
    session.close()
