"""
Unit tests for nmap XML transformer.
Tests service classification and canonical model generation.
"""

import pytest
from pathlib import Path
import tempfile

from src.transformers.nmap_transformer import NmapTransformer
from src.transformers.base import TransformerError
from src.models.canonical import ExposureClass


@pytest.fixture
def transformer():
    return NmapTransformer()


@pytest.fixture
def sample_nmap_xml():
    """Sample nmap XML with various open ports."""
    return """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" start="1705147200">
    <host>
        <address addr="192.168.1.100" addrtype="ipv4"/>
        <address addr="00:11:22:33:44:55" addrtype="mac"/>
        <hostnames>
            <hostname name="test-host.local"/>
        </hostnames>
        <ports>
            <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh" product="OpenSSH" version="8.2"/>
            </port>
            <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="nginx" version="1.18"/>
            </port>
            <port protocol="tcp" portid="3306">
                <state state="open"/>
                <service name="mysql" product="MySQL" version="8.0"/>
            </port>
            <port protocol="tcp" portid="9999">
                <state state="open"/>
                <service name="unknown"/>
            </port>
        </ports>
    </host>
</nmaprun>"""


def test_parse_valid_nmap_xml(transformer, sample_nmap_xml):
    """Test parsing valid nmap XML."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.xml') as f:
        f.write(sample_nmap_xml)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform_file(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        # Should have 4 events (4 open ports)
        assert len(events) == 4
        
        # Check first event (SSH)
        ssh_event = next(e for e in events if e.exposure.vector.dst.port == 22)
        assert ssh_event.exposure.class_ == ExposureClass.REMOTE_ADMIN_EXPOSED
        assert ssh_event.exposure.service.name == "ssh"
        assert ssh_event.target.asset.ip == ["192.168.1.100"]
        assert ssh_event.target.asset.mac == "00:11:22:33:44:55"
        assert ssh_event.target.asset.hostname == "test-host.local"
        
    finally:
        temp_path.unlink()


def test_classify_ssh(transformer):
    """Test SSH port classification."""
    exposure_class = transformer._classify_exposure(
        port=22,
        service_name="ssh",
        product="OpenSSH",
        tunnel=None
    )
    assert exposure_class == ExposureClass.REMOTE_ADMIN_EXPOSED


def test_classify_rdp(transformer):
    """Test RDP port classification."""
    exposure_class = transformer._classify_exposure(
        port=3389,
        service_name="ms-wbt-server",
        product="Microsoft Terminal Services",
        tunnel=None
    )
    assert exposure_class == ExposureClass.REMOTE_ADMIN_EXPOSED


def test_classify_smb(transformer):
    """Test SMB/file share classification."""
    exposure_class = transformer._classify_exposure(
        port=445,
        service_name="microsoft-ds",
        product=None,
        tunnel=None
    )
    assert exposure_class == ExposureClass.FILESHARE_EXPOSED


def test_classify_mysql(transformer):
    """Test MySQL database classification."""
    exposure_class = transformer._classify_exposure(
        port=3306,
        service_name="mysql",
        product="MySQL",
        tunnel=None
    )
    assert exposure_class == ExposureClass.DB_EXPOSED


def test_classify_postgres(transformer):
    """Test PostgreSQL classification."""
    exposure_class = transformer._classify_exposure(
        port=5432,
        service_name="postgresql",
        product="PostgreSQL",
        tunnel=None
    )
    assert exposure_class == ExposureClass.DB_EXPOSED


def test_classify_docker(transformer):
    """Test Docker API classification."""
    exposure_class = transformer._classify_exposure(
        port=2375,
        service_name="docker",
        product="Docker Engine",
        tunnel=None
    )
    assert exposure_class == ExposureClass.CONTAINER_API_EXPOSED


def test_classify_kubernetes(transformer):
    """Test Kubernetes API classification."""
    exposure_class = transformer._classify_exposure(
        port=6443,
        service_name="ssl",
        product="Kubernetes",
        tunnel="ssl"
    )
    assert exposure_class == ExposureClass.CONTAINER_API_EXPOSED


def test_classify_http(transformer):
    """Test HTTP service classification."""
    exposure_class = transformer._classify_exposure(
        port=80,
        service_name="http",
        product="nginx",
        tunnel=None
    )
    assert exposure_class == ExposureClass.HTTP_CONTENT_LEAK


def test_classify_git_protocol(transformer):
    """Test git protocol classification."""
    exposure_class = transformer._classify_exposure(
        port=9418,
        service_name="git",
        product=None,
        tunnel=None
    )
    assert exposure_class == ExposureClass.VCS_PROTOCOL_EXPOSED


def test_classify_unknown(transformer):
    """Test unknown service classification."""
    exposure_class = transformer._classify_exposure(
        port=9999,
        service_name="unknown",
        product=None,
        tunnel=None
    )
    assert exposure_class == ExposureClass.UNKNOWN_SERVICE_EXPOSED


def test_severity_calculation(transformer):
    """Test severity scoring for different exposure classes."""
    # Database exposure should be critical
    db_severity = transformer._calculate_severity(
        ExposureClass.DB_EXPOSED,
        "mysql",
        "MySQL"
    )
    assert db_severity >= 80
    
    # Container API should be critical
    container_severity = transformer._calculate_severity(
        ExposureClass.CONTAINER_API_EXPOSED,
        "docker",
        "Docker Engine"
    )
    assert container_severity >= 80
    
    # Remote admin should be high
    ssh_severity = transformer._calculate_severity(
        ExposureClass.REMOTE_ADMIN_EXPOSED,
        "ssh",
        "OpenSSH"
    )
    assert 60 <= ssh_severity < 80
    
    # Unknown should be low
    unknown_severity = transformer._calculate_severity(
        ExposureClass.UNKNOWN_SERVICE_EXPOSED,
        "unknown",
        None
    )
    assert unknown_severity < 50


def test_deterministic_exposure_ids(transformer, sample_nmap_xml):
    """Test that same scan produces same exposure IDs."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.xml') as f:
        f.write(sample_nmap_xml)
        temp_path = Path(f.name)
    
    try:
        events1 = transformer.transform_file(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        events2 = transformer.transform_file(
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


def test_reject_invalid_xml(transformer):
    """Test that invalid XML is rejected."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.xml') as f:
        f.write("<invalid>not closed")
        temp_path = Path(f.name)
    
    try:
        with pytest.raises(TransformerError):
            transformer.transform_file(
                file_path=temp_path,
                office_id="office-1",
                scanner_id="scanner-1"
            )
    finally:
        temp_path.unlink()


def test_reject_non_nmap_xml(transformer):
    """Test that non-nmap XML is rejected."""
    non_nmap = """<?xml version="1.0"?>
<root>
    <data>Not an nmap scan</data>
</root>"""
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.xml') as f:
        f.write(non_nmap)
        temp_path = Path(f.name)
    
    try:
        with pytest.raises(TransformerError) as exc_info:
            transformer.transform_file(
                file_path=temp_path,
                office_id="office-1",
                scanner_id="scanner-1"
            )
        assert "not a valid nmap" in str(exc_info.value).lower()
    finally:
        temp_path.unlink()


def test_handle_closed_ports(transformer):
    """Test that closed ports are skipped."""
    nmap_with_closed = """<?xml version="1.0"?>
<nmaprun scanner="nmap" start="1705147200">
    <host>
        <address addr="192.168.1.100" addrtype="ipv4"/>
        <ports>
            <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh"/>
            </port>
            <port protocol="tcp" portid="23">
                <state state="closed"/>
                <service name="telnet"/>
            </port>
        </ports>
    </host>
</nmaprun>"""
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.xml') as f:
        f.write(nmap_with_closed)
        temp_path = Path(f.name)
    
    try:
        events = transformer.transform_file(
            file_path=temp_path,
            office_id="office-1",
            scanner_id="scanner-1"
        )
        
        # Should only have 1 event (open port)
        assert len(events) == 1
        assert events[0].exposure.vector.dst.port == 22
        
    finally:
        temp_path.unlink()
