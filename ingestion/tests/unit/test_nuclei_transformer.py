"""
Unit tests for nuclei JSON transformer.
Tests parsing, classification, and canonical model generation.
"""

import pytest
import json
from pathlib import Path
import tempfile

from src.transformers.nuclei_transformer import NucleiTransformer
from src.transformers.base import TransformerError
from src.models.canonical import ExposureClass


@pytest.fixture
def transformer():
    return NucleiTransformer()


@pytest.fixture
def sample_nuclei_json():
    """Sample nuclei JSON output."""
    return [
        {
            "template-id": "exposed-panel-laravel",
            "info": {
                "name": "Laravel Debug Mode",
                "severity": "high",
                "tags": ["exposure", "laravel", "debug"]
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
                "name": "MongoDB Unauth",
                "severity": "critical",
                "tags": ["database", "mongodb"]
            },
            "type": "network",
            "host": "tcp://10.0.2.169:27017",
            "timestamp": "2024-01-13T10:31:00Z"
        }
    ]


def test_parse_valid_json(transformer, sample_nuclei_json):
    """Test parsing valid nuclei JSON."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(sample_nuclei_json, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        # Should have 2 events
        assert len(events) == 2
        
        # Check first event (Laravel debug panel)
        laravel_event = next(e for e in events if e.exposure.service.name == "exposed-panel-laravel")
        assert laravel_event.exposure.class_ == ExposureClass.DEBUG_PORT_EXPOSED
        assert laravel_event.target.asset.ip == ["10.0.2.131"]
        assert laravel_event.exposure.vector.dst.port == 80
        assert laravel_event.scanner.type == "nuclei"
        
        # Check second event (MongoDB)
        mongo_event = next(e for e in events if e.exposure.service.name == "mongodb-unauth")
        assert mongo_event.exposure.class_ == ExposureClass.DB_EXPOSED
        assert mongo_event.target.asset.ip == ["10.0.2.169"]
        assert mongo_event.exposure.vector.dst.port == 27017
        
    finally:
        temp_path.unlink()


def test_parse_empty_json(transformer):
    """Test parsing empty JSON array."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump([], f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        assert len(events) == 0
    finally:
        temp_path.unlink()


def test_reject_invalid_json(transformer):
    """Test that invalid JSON is rejected."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        f.write("{invalid json")
        temp_path = Path(f.name)
    
    try:
        with pytest.raises(TransformerError):
            transformer.transform(
                file_path=temp_path,
                office_id="office-1",
                scanner_id="scanner-1"
            )
    finally:
        temp_path.unlink()


def test_reject_non_array_json(transformer):
    """Test that non-array JSON is rejected."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump({"not": "an array"}, f)
        temp_path = Path(f.name)
    
    try:
        with pytest.raises(TransformerError) as exc_info:
            transformer.transform(
                file_path=temp_path,
                office_id="office-1",
                scanner_id="scanner-1"
            )
        assert "Expected JSON array" in str(exc_info.value)
    finally:
        temp_path.unlink()


def test_extract_host_info_http(transformer):
    """Test extracting host info from HTTP URL."""
    host_info = transformer._extract_host_info("http://10.0.2.131:80")
    assert host_info['ip'] == "10.0.2.131"
    assert host_info['port'] == 80
    assert host_info['protocol'] == "http"


def test_extract_host_info_https(transformer):
    """Test extracting host info from HTTPS URL."""
    host_info = transformer._extract_host_info("https://192.168.1.100:443")
    assert host_info['ip'] == "192.168.1.100"
    assert host_info['port'] == 443
    assert host_info['protocol'] == "https"


def test_extract_host_info_tcp(transformer):
    """Test extracting host info from TCP URL."""
    host_info = transformer._extract_host_info("tcp://10.0.2.169:27017")
    assert host_info['ip'] == "10.0.2.169"
    assert host_info['port'] == 27017
    assert host_info['protocol'] == "tcp"


def test_extract_host_info_default_port(transformer):
    """Test default port assignment for HTTP."""
    host_info = transformer._extract_host_info("http://10.0.2.131")
    assert host_info['ip'] == "10.0.2.131"
    assert host_info['port'] == 80
    assert host_info['protocol'] == "http"


def test_extract_host_info_hostname(transformer):
    """Test extracting hostname instead of IP."""
    host_info = transformer._extract_host_info("http://example.com:8080")
    assert host_info['ip'] == "example.com"  # Falls back to hostname
    assert host_info['port'] == 8080


def test_classify_database_mongodb(transformer):
    """Test MongoDB classification."""
    exposure_class = transformer._classify_exposure(
        severity="critical",
        tags=["database", "mongodb"],
        template_id="mongodb-unauth",
        finding_type="network"
    )
    assert exposure_class == ExposureClass.DB_EXPOSED


def test_classify_database_mysql(transformer):
    """Test MySQL classification."""
    exposure_class = transformer._classify_exposure(
        severity="critical",
        tags=["database", "mysql"],
        template_id="mysql-default",
        finding_type="network"
    )
    assert exposure_class == ExposureClass.DB_EXPOSED


def test_classify_remote_admin_ssh(transformer):
    """Test SSH classification."""
    exposure_class = transformer._classify_exposure(
        severity="high",
        tags=["ssh", "admin"],
        template_id="ssh-weak-algo",
        finding_type="network"
    )
    assert exposure_class == ExposureClass.REMOTE_ADMIN_EXPOSED


def test_classify_remote_admin_vnc(transformer):
    """Test VNC classification."""
    exposure_class = transformer._classify_exposure(
        severity="high",
        tags=["vnc", "admin"],
        template_id="vnc-no-auth",
        finding_type="network"
    )
    assert exposure_class == ExposureClass.REMOTE_ADMIN_EXPOSED


def test_classify_debug_panel(transformer):
    """Test debug panel classification."""
    exposure_class = transformer._classify_exposure(
        severity="high",
        tags=["exposure", "laravel", "debug"],
        template_id="exposed-panel-laravel",
        finding_type="http"
    )
    assert exposure_class == ExposureClass.DEBUG_PORT_EXPOSED


def test_classify_debug_console(transformer):
    """Test debug console classification via template-id."""
    exposure_class = transformer._classify_exposure(
        severity="medium",
        tags=["web"],
        template_id="debug-console-exposed",
        finding_type="http"
    )
    assert exposure_class == ExposureClass.DEBUG_PORT_EXPOSED


def test_classify_container_docker(transformer):
    """Test Docker API classification."""
    exposure_class = transformer._classify_exposure(
        severity="critical",
        tags=["docker", "container"],
        template_id="docker-api-unauth",
        finding_type="http"
    )
    assert exposure_class == ExposureClass.CONTAINER_API_EXPOSED


def test_classify_container_kubernetes(transformer):
    """Test Kubernetes classification."""
    exposure_class = transformer._classify_exposure(
        severity="high",
        tags=["k8s", "kubernetes"],
        template_id="kubernetes-dashboard",
        finding_type="http"
    )
    assert exposure_class == ExposureClass.CONTAINER_API_EXPOSED


def test_classify_fileshare_smb(transformer):
    """Test SMB classification."""
    exposure_class = transformer._classify_exposure(
        severity="medium",
        tags=["smb", "fileshare"],
        template_id="smb-signing-disabled",
        finding_type="network"
    )
    assert exposure_class == ExposureClass.FILESHARE_EXPOSED


def test_classify_vcs_git(transformer):
    """Test Git VCS classification."""
    exposure_class = transformer._classify_exposure(
        severity="medium",
        tags=["exposure", "git", "vcs"],
        template_id="git-config-exposure",
        finding_type="http"
    )
    assert exposure_class == ExposureClass.VCS_PROTOCOL_EXPOSED


def test_classify_http_content_leak(transformer):
    """Test HTTP content leak classification."""
    exposure_class = transformer._classify_exposure(
        severity="info",
        tags=["exposure", "disclosure"],
        template_id="env-file-disclosure",
        finding_type="http"
    )
    assert exposure_class == ExposureClass.HTTP_CONTENT_LEAK


def test_classify_unknown(transformer):
    """Test unknown service classification."""
    exposure_class = transformer._classify_exposure(
        severity="info",
        tags=["misconfiguration"],
        template_id="some-generic-check",
        finding_type="http"
    )
    assert exposure_class == ExposureClass.UNKNOWN_SERVICE_EXPOSED


def test_severity_critical(transformer):
    """Test severity calculation for critical findings."""
    severity = transformer._calculate_severity(
        nuclei_severity="critical",
        exposure_class=ExposureClass.DB_EXPOSED
    )
    assert severity == 95


def test_severity_high(transformer):
    """Test severity calculation for high findings."""
    severity = transformer._calculate_severity(
        nuclei_severity="high",
        exposure_class=ExposureClass.REMOTE_ADMIN_EXPOSED
    )
    assert severity == 80


def test_severity_medium(transformer):
    """Test severity calculation for medium findings."""
    severity = transformer._calculate_severity(
        nuclei_severity="medium",
        exposure_class=ExposureClass.HTTP_CONTENT_LEAK
    )
    assert severity == 60


def test_severity_low(transformer):
    """Test severity calculation for low findings."""
    severity = transformer._calculate_severity(
        nuclei_severity="low",
        exposure_class=ExposureClass.UNKNOWN_SERVICE_EXPOSED
    )
    assert severity == 40


def test_severity_info(transformer):
    """Test severity calculation for info findings."""
    severity = transformer._calculate_severity(
        nuclei_severity="info",
        exposure_class=ExposureClass.HTTP_CONTENT_LEAK
    )
    assert severity == 50  # Class severity (50) > nuclei severity (20)


def test_severity_uses_higher_value(transformer):
    """Test that severity uses higher of nuclei vs class severity."""
    # Class severity (90) should override low nuclei severity (40)
    severity = transformer._calculate_severity(
        nuclei_severity="low",
        exposure_class=ExposureClass.DB_EXPOSED
    )
    assert severity == 90


def test_deterministic_exposure_ids(transformer, sample_nuclei_json):
    """Test that same scan produces same exposure IDs."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(sample_nuclei_json, f)
        temp_path = Path(f.name)
    
    try:
        events1 = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        events2 = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        # Same inputs should produce same exposure IDs
        ids1 = sorted([e.exposure.id for e in events1])
        ids2 = sorted([e.exposure.id for e in events2])
        assert ids1 == ids2
        
    finally:
        temp_path.unlink()


def test_handle_missing_fields(transformer):
    """Test graceful handling of findings with missing fields."""
    minimal_finding = [
        {
            "template-id": "test-finding",
            "host": "http://10.0.2.1:80"
            # Missing info, timestamp, etc.
        }
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(minimal_finding, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        # Should still produce an event with defaults
        assert len(events) == 1
        assert events[0].exposure.service.name == "test-finding"
        
    finally:
        temp_path.unlink()


def test_skip_finding_without_ip(transformer):
    """Test that findings without extractable IP are skipped."""
    bad_finding = [
        {
            "template-id": "test-finding",
            "info": {"name": "Test", "severity": "low"},
            "host": "invalid-host-format"
        }
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(bad_finding, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        # Should skip the finding
        assert len(events) == 0
        
    finally:
        temp_path.unlink()


def test_version_extraction_from_extracted_results(transformer):
    """Test version extraction from extracted-results field."""
    finding = [
        {
            "template-id": "version-detect",
            "info": {"name": "Version", "severity": "info"},
            "host": "http://10.0.2.1:80",
            "extracted-results": ["Laravel v8.0.2"]
        }
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(finding, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        assert len(events) == 1
        assert events[0].exposure.service.version == "8.0.2"
        assert events[0].exposure.service.product == "Laravel v8.0.2"
        
    finally:
        temp_path.unlink()


def test_tls_detection_from_https(transformer):
    """Test TLS detection from HTTPS protocol."""
    finding = [
        {
            "template-id": "test",
            "info": {"name": "Test", "severity": "info"},
            "host": "https://10.0.2.1:443"
        }
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(finding, f)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        assert len(events) == 1
        assert events[0].exposure.service.tls is True
        
    finally:
        temp_path.unlink()


def test_scanner_type(transformer):
    """Test that transformer returns correct scanner type."""
    assert transformer.get_scanner_type() == "nuclei"


def test_file_size_limit(transformer):
    """Test that oversized files are rejected."""
    # Create a file larger than 10MB
    large_data = [{"template-id": f"test-{i}", "host": "http://10.0.0.1"} for i in range(500000)]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(large_data, f)
        temp_path = Path(f.name)
    
    try:
        with pytest.raises(TransformerError) as exc_info:
            transformer.transform(
                file_path=temp_path,
                office_id="office-1",
                scanner_id="scanner-1"
            )
        assert "too large" in str(exc_info.value).lower()
    finally:
        temp_path.unlink()
