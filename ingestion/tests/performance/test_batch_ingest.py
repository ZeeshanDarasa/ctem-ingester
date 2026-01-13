"""
Performance tests for batch ingestion.
Tests that 10k events can be ingested within reasonable time.
"""

import pytest
import os
import tempfile
import time
import psutil
from pathlib import Path
from datetime import datetime, timezone

from src.storage.connection import DatabaseManager, DatabaseConfig
from src.storage.repository import batch_ingest_exposures
from src.models.canonical import (
    ExposureEventModel, Event, Office, Scanner, Target, Asset,
    Exposure, Vector, EventKind, EventAction, ExposureClass,
    ExposureStatus, Transport
)
from src.models.storage import ExposureEvent, ExposureCurrent


@pytest.fixture
def perf_db():
    """Create a temporary database for performance tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "perf_test.duckdb"
        os.environ['DB_PATH'] = str(db_path)
        os.environ['DB_TYPE'] = 'duckdb'
        
        config = DatabaseConfig()
        db_manager = DatabaseManager(config)
        db_manager.create_tables()
        
        yield db_manager
        
        db_manager.close()


def generate_synthetic_events(count: int) -> list[ExposureEventModel]:
    """Generate synthetic exposure events for testing."""
    events = []
    
    for i in range(count):
        # Vary the parameters to create realistic diversity
        office_id = f"office-{i % 10}"  # 10 offices
        asset_id = f"asset-{i % 100}"   # 100 assets
        port = 8000 + (i % 1000)         # Various ports
        
        event = ExposureEventModel(
            schema_version="1.0.0",
            timestamp=datetime.now(timezone.utc),
            event=Event(
                id=f"evt-{i}",
                kind=EventKind.EVENT,
                category=["network"],
                type=["info"],
                action=EventAction.EXPOSURE_OPENED,
                severity=50 + (i % 50)
            ),
            office=Office(
                id=office_id,
                name=f"Office-{office_id}"
            ),
            scanner=Scanner(
                id=f"scanner-{i % 5}",  # 5 scanners
                type="nmap"
            ),
            target=Target(
                asset=Asset(
                    id=asset_id,
                    ip=[f"192.168.{i % 255}.{(i // 255) % 255}"]
                )
            ),
            exposure=Exposure(
                id=f"exp-{office_id}-{asset_id}-{port}",
                class_=ExposureClass.UNKNOWN_SERVICE_EXPOSED,
                status=ExposureStatus.OPEN,
                vector=Vector(
                    transport=Transport.TCP,
                    protocol="http",
                    dst={
                        "ip": f"192.168.{i % 255}.{(i // 255) % 255}",
                        "port": port
                    }
                )
            )
        )
        events.append(event)
    
    return events


def test_ingest_10k_events_performance(perf_db):
    """
    Test ingesting 10,000 events completes within 30 seconds.
    
    Success criteria:
    - Total time < 30 seconds
    - Memory usage stable (no excessive growth)
    - All events successfully inserted
    """
    # Generate 10,000 synthetic events
    print("\nGenerating 10,000 synthetic events...")
    events = generate_synthetic_events(10000)
    
    # Measure memory before
    process = psutil.Process()
    memory_before = process.memory_info().rss / 1024 / 1024  # MB
    
    # Measure ingestion time
    session = perf_db.get_session()
    
    print("Starting batch ingestion...")
    start_time = time.time()
    
    stats = batch_ingest_exposures(events, session)
    
    end_time = time.time()
    elapsed = end_time - start_time
    
    # Measure memory after
    memory_after = process.memory_info().rss / 1024 / 1024  # MB
    memory_growth = memory_after - memory_before
    
    print(f"\nPerformance Results:")
    print(f"  Total events: {stats['total_processed']}")
    print(f"  Events inserted: {stats['events_inserted']}")
    print(f"  Exposures inserted: {stats['exposures_inserted']}")
    print(f"  Exposures updated: {stats['exposures_updated']}")
    print(f"  Elapsed time: {elapsed:.2f} seconds")
    print(f"  Throughput: {stats['total_processed'] / elapsed:.0f} events/sec")
    print(f"  Memory before: {memory_before:.1f} MB")
    print(f"  Memory after: {memory_after:.1f} MB")
    print(f"  Memory growth: {memory_growth:.1f} MB")
    
    # Verify results
    event_count = session.query(ExposureEvent).count()
    current_count = session.query(ExposureCurrent).count()
    
    print(f"  Verified events in DB: {event_count}")
    print(f"  Verified current exposures: {current_count}")
    
    session.close()
    
    # Assertions
    assert stats['total_processed'] == 10000, "Should process all 10k events"
    assert stats['events_inserted'] == 10000, "Should insert all events"
    assert elapsed < 30, f"Ingestion took {elapsed:.2f}s, should be < 30s"
    assert memory_growth < 500, f"Memory grew by {memory_growth:.1f}MB, should be < 500MB"
    assert event_count == 10000, "All events should be in database"
    assert current_count > 0, "Should have current exposures"


def test_batch_ingest_with_updates(perf_db):
    """Test ingestion performance with mix of inserts and updates."""
    # First batch: 5000 new events
    print("\nIngesting first batch of 5000 events...")
    events1 = generate_synthetic_events(5000)
    
    session = perf_db.get_session()
    start_time = time.time()
    
    stats1 = batch_ingest_exposures(events1, session)
    
    elapsed1 = time.time() - start_time
    print(f"  First batch: {elapsed1:.2f}s, {stats1['exposures_inserted']} inserted")
    
    # Second batch: 5000 events (some overlap with first batch)
    print("Ingesting second batch of 5000 events (with overlaps)...")
    events2 = generate_synthetic_events(5000)  # Will have same exposure IDs
    
    start_time = time.time()
    
    stats2 = batch_ingest_exposures(events2, session)
    
    elapsed2 = time.time() - start_time
    print(f"  Second batch: {elapsed2:.2f}s")
    print(f"    Inserted: {stats2['exposures_inserted']}")
    print(f"    Updated: {stats2['exposures_updated']}")
    
    total_elapsed = elapsed1 + elapsed2
    print(f"  Total time: {total_elapsed:.2f}s")
    
    session.close()
    
    # Assertions
    assert total_elapsed < 30, f"Total ingestion took {total_elapsed:.2f}s, should be < 30s"
    assert stats2['exposures_updated'] > 0, "Should have updates in second batch"


def test_query_performance(perf_db):
    """Test that queries on large dataset remain fast."""
    # Ingest 5000 events
    events = generate_synthetic_events(5000)
    session = perf_db.get_session()
    batch_ingest_exposures(events, session)
    
    # Test various query patterns
    print("\nQuery Performance:")
    
    # Query 1: Count by office
    start = time.time()
    from sqlalchemy import func
    results = session.query(
        ExposureCurrent.office_id,
        func.count(ExposureCurrent.id)
    ).group_by(ExposureCurrent.office_id).all()
    elapsed = time.time() - start
    print(f"  Count by office: {elapsed*1000:.1f}ms, {len(results)} offices")
    assert elapsed < 1.0, "Group by query should be < 1s"
    
    # Query 2: Filter by severity
    start = time.time()
    high_severity = session.query(ExposureCurrent).filter(
        ExposureCurrent.severity >= 80
    ).count()
    elapsed = time.time() - start
    print(f"  High severity filter: {elapsed*1000:.1f}ms, {high_severity} results")
    assert elapsed < 0.5, "Indexed filter should be < 500ms"
    
    # Query 3: Join to events
    start = time.time()
    joined = session.query(ExposureCurrent).join(
        ExposureEvent,
        ExposureCurrent.exposure_id == ExposureEvent.exposure_id
    ).limit(100).all()
    elapsed = time.time() - start
    print(f"  Join query (100 rows): {elapsed*1000:.1f}ms")
    assert elapsed < 1.0, "Join query should be < 1s"
    
    session.close()


if __name__ == "__main__":
    # Allow running performance tests directly
    pytest.main([__file__, "-v", "-s"])
