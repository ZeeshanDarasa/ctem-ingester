"""
Integration test for nuclei transformer with DuckDB storage.
Tests end-to-end: JSON → transform → store → verify.
"""

import pytest
import os
import json
import tempfile
from pathlib import Path

from src.storage.connection import DatabaseManager, DatabaseConfig
from src.storage.repository import batch_ingest_exposures
from src.transformers.nuclei_transformer import NucleiTransformer
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


@pytest.fixture
def nuclei_sample_file():
    """Create temporary nuclei JSON file."""
    sample_data = [
        {
            "template-id": "exposed-panel-laravel",
            "info": {
                "name": "Laravel Debug Mode Enabled",
                "author": "pdteam",
                "severity": "high",
                "description": "Laravel application with debug mode enabled",
                "tags": ["exposure", "laravel", "debug", "panel"]
            },
            "type": "http",
            "host": "http://10.0.2.131:80",
            "matched-at": "http://10.0.2.131:80/debug",
            "extracted-results": ["Laravel v8.0"],
            "timestamp": "2024-01-13T10:30:00Z"
        },
        {
            "template-id": "mongodb-unauth",
            "info": {
                "name": "MongoDB Unauthenticated Access",
                "author": "pdteam",
                "severity": "critical",
                "description": "MongoDB instance accessible without authentication",
                "tags": ["database", "mongodb", "unauth"]
            },
            "type": "network",
            "host": "tcp://10.0.2.169:27017",
            "matched-at": "tcp://10.0.2.169:27017",
            "extracted-results": ["MongoDB 4.2.8"],
            "timestamp": "2024-01-13T10:31:00Z"
        },
        {
            "template-id": "git-config-exposure",
            "info": {
                "name": "Git Config File Exposed",
                "author": "pdteam",
                "severity": "medium",
                "description": "Git configuration file accessible via HTTP",
                "tags": ["exposure", "git", "vcs", "leak"]
            },
            "type": "http",
            "host": "http://10.0.2.174:8080",
            "matched-at": "http://10.0.2.174:8080/.git/config",
            "timestamp": "2024-01-13T10:32:00Z"
        }
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(sample_data, f)
        temp_path = Path(f.name)
    
    yield temp_path
    
    temp_path.unlink()


def test_end_to_end_nuclei_ingestion(temp_db, nuclei_sample_file):
    """Test complete workflow: nuclei JSON → transform → store → verify."""
    session = temp_db.get_session()
    
    # Transform nuclei JSON
    transformer = NucleiTransformer()
    events = transformer.transform(
        file_path=nuclei_sample_file,
        office_id="office-1",
        scanner_id="scanner-nuclei-1"
    )
    
    # Should have transformed 3 findings
    assert len(events) == 3
    
    # Verify event properties
    assert all(e.scanner.type == "nuclei" for e in events)
    assert all(e.office.id == "office-1" for e in events)
    
    # Ingest into database
    stats = batch_ingest_exposures(events, session)
    
    assert stats['total_processed'] == 3
    assert stats['events_inserted'] == 3
    
    # Verify events in exposure_events table
    event_count = session.query(ExposureEvent).count()
    assert event_count == 3
    
    # Verify exposures in exposures_current table
    current_count = session.query(ExposureCurrent).filter_by(
        office_id="office-1"
    ).count()
    assert current_count == 3
    
    # Verify specific findings
    laravel = session.query(ExposureCurrent).filter_by(
        office_id="office-1",
        dst_ip="10.0.2.131"
    ).first()
    assert laravel is not None
    assert laravel.dst_port == 80
    assert laravel.exposure_class == "debug_port_exposed"
    assert laravel.scanner_type == "nuclei"
    
    mongodb = session.query(ExposureCurrent).filter_by(
        office_id="office-1",
        dst_ip="10.0.2.169"
    ).first()
    assert mongodb is not None
    assert mongodb.dst_port == 27017
    assert mongodb.exposure_class == "db_exposed"
    assert mongodb.severity >= 90  # Critical severity
    
    git = session.query(ExposureCurrent).filter_by(
        office_id="office-1",
        dst_ip="10.0.2.174"
    ).first()
    assert git is not None
    assert git.dst_port == 8080
    assert git.exposure_class == "vcs_protocol_exposed"
    
    session.close()


def test_nuclei_rescan_updates_last_seen(temp_db, nuclei_sample_file):
    """Test that re-scanning with nuclei updates last_seen timestamps."""
    session = temp_db.get_session()
    transformer = NucleiTransformer()
    
    # First scan
    events1 = transformer.transform(
        file_path=nuclei_sample_file,
        office_id="office-1",
        scanner_id="scanner-1"
    )
    batch_ingest_exposures(events1, session)
    
    # Get original timestamps
    original = session.query(ExposureCurrent).filter_by(
        office_id="office-1",
        dst_ip="10.0.2.131"
    ).first()
    original_first_seen = original.first_seen
    original_last_seen = original.last_seen
    
    # Wait a bit
    import time
    time.sleep(0.01)
    
    # Second scan (same data)
    events2 = transformer.transform(
        file_path=nuclei_sample_file,
        office_id="office-1",
        scanner_id="scanner-1"
    )
    batch_ingest_exposures(events2, session)
    
    # Check timestamps
    session.expire_all()
    updated = session.query(ExposureCurrent).filter_by(
        office_id="office-1",
        dst_ip="10.0.2.131"
    ).first()
    
    # first_seen should be preserved
    assert updated.first_seen == original_first_seen
    
    # last_seen should be updated
    assert updated.last_seen >= original_last_seen
    
    session.close()


def test_nuclei_deterministic_ids(temp_db, nuclei_sample_file):
    """Test that nuclei transformer generates deterministic exposure IDs."""
    session = temp_db.get_session()
    transformer = NucleiTransformer()
    
    # First scan
    events1 = transformer.transform(
        file_path=nuclei_sample_file,
        office_id="office-1",
        scanner_id="scanner-1"
    )
    exposure_ids1 = sorted([e.exposure.id for e in events1])
    
    # Second scan
    events2 = transformer.transform(
        file_path=nuclei_sample_file,
        office_id="office-1",
        scanner_id="scanner-1"
    )
    exposure_ids2 = sorted([e.exposure.id for e in events2])
    
    # IDs should match
    assert exposure_ids1 == exposure_ids2
    
    session.close()


def test_nuclei_multiple_offices(temp_db, nuclei_sample_file):
    """Test that same nuclei scan in different offices creates separate exposures."""
    session = temp_db.get_session()
    transformer = NucleiTransformer()
    
    # Scan for office-1
    events1 = transformer.transform(
        file_path=nuclei_sample_file,
        office_id="office-1",
        scanner_id="scanner-1"
    )
    batch_ingest_exposures(events1, session)
    
    # Scan for office-2 (same findings, different office)
    events2 = transformer.transform(
        file_path=nuclei_sample_file,
        office_id="office-2",
        scanner_id="scanner-2"
    )
    batch_ingest_exposures(events2, session)
    
    # Should have separate exposures for each office
    office1_count = session.query(ExposureCurrent).filter_by(
        office_id="office-1"
    ).count()
    office2_count = session.query(ExposureCurrent).filter_by(
        office_id="office-2"
    ).count()
    
    assert office1_count == 3
    assert office2_count == 3
    
    # Total should be 6
    total_count = session.query(ExposureCurrent).count()
    assert total_count == 6
    
    session.close()


def test_nuclei_severity_mapping(temp_db, nuclei_sample_file):
    """Test that nuclei severity levels are correctly mapped."""
    session = temp_db.get_session()
    transformer = NucleiTransformer()
    
    events = transformer.transform(
        file_path=nuclei_sample_file,
        office_id="office-1",
        scanner_id="scanner-1"
    )
    batch_ingest_exposures(events, session)
    
    # MongoDB (critical) should have high severity
    mongodb = session.query(ExposureCurrent).filter_by(
        office_id="office-1",
        dst_ip="10.0.2.169"
    ).first()
    assert mongodb.severity >= 90
    
    # Laravel debug panel (high) should have high severity
    laravel = session.query(ExposureCurrent).filter_by(
        office_id="office-1",
        dst_ip="10.0.2.131"
    ).first()
    assert 60 <= laravel.severity <= 95
    
    # Git config (medium) should have medium severity
    git = session.query(ExposureCurrent).filter_by(
        office_id="office-1",
        dst_ip="10.0.2.174"
    ).first()
    assert 50 <= git.severity <= 70
    
    session.close()


def test_nuclei_empty_file(temp_db):
    """Test handling of empty nuclei JSON file."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump([], f)
        temp_path = Path(f.name)
    
    try:
        session = temp_db.get_session()
        transformer = NucleiTransformer()
        
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        assert len(events) == 0
        
        stats = batch_ingest_exposures(events, session)
        assert stats['total_processed'] == 0
        
        session.close()
    finally:
        temp_path.unlink()


def test_nuclei_batch_processing(temp_db):
    """Test processing large nuclei scan with many findings."""
    # Create a large nuclei scan
    large_scan = [
        {
            "template-id": f"finding-{i}",
            "info": {
                "name": f"Finding {i}",
                "severity": "medium",
                "tags": ["test"]
            },
            "type": "http",
            "host": f"http://10.0.2.{100 + i}:80",
            "timestamp": "2024-01-13T10:30:00Z"
        }
        for i in range(50)
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(large_scan, f)
        temp_path = Path(f.name)
    
    try:
        session = temp_db.get_session()
        transformer = NucleiTransformer()
        
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        assert len(events) == 50
        
        stats = batch_ingest_exposures(events, session)
        assert stats['total_processed'] == 50
        assert stats['events_inserted'] == 50
        
        # Verify in database
        event_count = session.query(ExposureEvent).count()
        assert event_count == 50
        
        current_count = session.query(ExposureCurrent).filter_by(
            office_id="office-1"
        ).count()
        assert current_count == 50
        
        session.close()
    finally:
        temp_path.unlink()
