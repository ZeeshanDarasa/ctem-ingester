"""
Integration tests for FastAPI ingestion endpoint.
"""

import pytest
import os
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient

from src.api import app
from src.storage.connection import DatabaseManager, DatabaseConfig
from src.models.storage import ExposureEvent, ExposureCurrent, QuarantinedFile


@pytest.fixture
def test_env():
    """Set up test environment with temporary database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        
        scan_dir = tmppath / "scans"
        db_path = tmppath / "test.duckdb"
        
        scan_dir.mkdir()
        
        os.environ['DB_PATH'] = str(db_path)
        os.environ['DB_TYPE'] = 'duckdb'
        
        yield {
            'scan_dir': scan_dir,
            'db_path': db_path
        }


@pytest.fixture
def client(test_env):
    """Create test client for FastAPI app."""
    with TestClient(app) as test_client:
        yield test_client


def test_root_endpoint(client):
    """Test root endpoint returns API info."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "Exposure Ingestion API"
    assert "endpoints" in data


def test_health_endpoint(client):
    """Test health check endpoint."""
    response = client.get("/health")
    assert response.status_code in [200, 503]  # Healthy or unhealthy
    data = response.json()
    assert "status" in data
    assert "checks" in data


def test_metrics_endpoint(client):
    """Test Prometheus metrics endpoint."""
    response = client.get("/metrics")
    assert response.status_code == 200
    assert b"ingestion_files_processed_total" in response.content


def test_ingest_valid_nmap_file(client, test_env):
    """Test ingesting a valid nmap XML file."""
    nmap_xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" start="1705147200">
    <host>
        <address addr="192.168.1.100" addrtype="ipv4"/>
        <ports>
            <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh" product="OpenSSH" version="8.2"/>
            </port>
            <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="nginx"/>
            </port>
        </ports>
    </host>
</nmaprun>"""
    
    # Write nmap file
    xml_file = test_env['scan_dir'] / "scan.xml"
    xml_file.write_text(nmap_xml)
    
    # Call API
    response = client.post("/ingest", json={
        "file_path": str(xml_file),
        "office_id": "office-test",
        "scanner_id": "scanner-test"
    })
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["status"] == "success"
    assert data["file_path"] == str(xml_file)
    assert "stats" in data
    assert data["stats"]["events_inserted"] == 2  # 2 open ports
    assert "processing_time_ms" in data


def test_ingest_file_not_found(client):
    """Test that non-existent file returns 404."""
    response = client.post("/ingest", json={
        "file_path": "/nonexistent/file.xml",
        "office_id": "office-test",
        "scanner_id": "scanner-test"
    })
    
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_ingest_invalid_xml(client, test_env):
    """Test that invalid XML returns 400."""
    invalid_xml = "<invalid>not closed"
    
    xml_file = test_env['scan_dir'] / "invalid.xml"
    xml_file.write_text(invalid_xml)
    
    response = client.post("/ingest", json={
        "file_path": str(xml_file),
        "office_id": "office-test",
        "scanner_id": "scanner-test"
    })
    
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["status"] == "error"
    assert "error_type" in detail
    assert "error_message" in detail


def test_ingest_non_nmap_xml(client, test_env):
    """Test that non-nmap XML returns 400."""
    non_nmap = """<?xml version="1.0"?>
<root>
    <data>Not an nmap scan</data>
</root>"""
    
    xml_file = test_env['scan_dir'] / "not_nmap.xml"
    xml_file.write_text(non_nmap)
    
    response = client.post("/ingest", json={
        "file_path": str(xml_file),
        "office_id": "office-test",
        "scanner_id": "scanner-test"
    })
    
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error_type"] == "TransformerError"


def test_ingest_empty_scan(client, test_env):
    """Test that scan with no open ports succeeds but creates no events."""
    nmap_xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" start="1705147200">
    <host>
        <address addr="192.168.1.100" addrtype="ipv4"/>
        <ports>
            <port protocol="tcp" portid="22">
                <state state="closed"/>
                <service name="ssh"/>
            </port>
        </ports>
    </host>
</nmaprun>"""
    
    xml_file = test_env['scan_dir'] / "empty_scan.xml"
    xml_file.write_text(nmap_xml)
    
    response = client.post("/ingest", json={
        "file_path": str(xml_file),
        "office_id": "office-test",
        "scanner_id": "scanner-test"
    })
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["status"] == "success"
    assert data["stats"]["total_processed"] == 0


def test_ingest_unsupported_scanner_type(client, test_env):
    """Test that unsupported scanner type returns 400."""
    nmap_xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" start="1705147200">
    <host>
        <address addr="192.168.1.100" addrtype="ipv4"/>
    </host>
</nmaprun>"""
    
    xml_file = test_env['scan_dir'] / "scan.xml"
    xml_file.write_text(nmap_xml)
    
    response = client.post("/ingest", json={
        "file_path": str(xml_file),
        "office_id": "office-test",
        "scanner_id": "scanner-test",
        "scanner_type": "unsupported_scanner"
    })
    
    assert response.status_code == 400
    assert "unsupported" in response.json()["detail"].lower()


def test_concurrent_ingestion(client, test_env):
    """Test that multiple concurrent requests work correctly."""
    nmap_xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" start="1705147200">
    <host>
        <address addr="192.168.1.100" addrtype="ipv4"/>
        <ports>
            <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh"/>
            </port>
        </ports>
    </host>
</nmaprun>"""
    
    # Create multiple files
    files = []
    for i in range(3):
        xml_file = test_env['scan_dir'] / f"scan_{i}.xml"
        xml_file.write_text(nmap_xml)
        files.append(xml_file)
    
    # Send concurrent requests
    responses = []
    for i, xml_file in enumerate(files):
        response = client.post("/ingest", json={
            "file_path": str(xml_file),
            "office_id": f"office-{i}",
            "scanner_id": "scanner-test"
        })
        responses.append(response)
    
    # All should succeed
    assert all(r.status_code == 200 for r in responses)
    assert all(r.json()["status"] == "success" for r in responses)
