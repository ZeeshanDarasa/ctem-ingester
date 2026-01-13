"""
Unit tests for XML security utilities.
Tests protection against XXE, entity expansion, and size limits.
"""

import pytest
from pathlib import Path
import tempfile

from src.utils.security import (
    parse_xml_safely,
    parse_xml_string_safely,
    XMLSecurityError,
    MAX_XML_SIZE_BYTES
)


def test_parse_valid_xml():
    """Test that valid XML parses successfully."""
    xml_content = """<?xml version="1.0"?>
<nmaprun>
    <host>
        <address addr="192.168.1.100" addrtype="ipv4"/>
    </host>
</nmaprun>"""
    
    root = parse_xml_string_safely(xml_content)
    assert root.tag == 'nmaprun'
    assert len(root.findall('.//host')) == 1


def test_reject_xxe_attack():
    """Test that XXE (XML External Entity) attacks are blocked."""
    xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<nmaprun>
    <data>&xxe;</data>
</nmaprun>"""
    
    # defusedxml should prevent this
    with pytest.raises(XMLSecurityError):
        parse_xml_string_safely(xxe_payload)


def test_reject_entity_expansion():
    """Test that entity expansion bombs (billion laughs) are blocked."""
    entity_bomb = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<nmaprun>
    <data>&lol3;</data>
</nmaprun>"""
    
    # defusedxml should prevent this
    with pytest.raises(XMLSecurityError):
        parse_xml_string_safely(entity_bomb)


def test_reject_oversized_file():
    """Test that files exceeding size limit are rejected."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.xml') as f:
        # Write more than MAX_XML_SIZE_BYTES
        large_content = '<?xml version="1.0"?><root>' + 'x' * (MAX_XML_SIZE_BYTES + 1000) + '</root>'
        f.write(large_content)
        temp_path = f.name
    
    try:
        with pytest.raises(XMLSecurityError) as exc_info:
            parse_xml_safely(temp_path)
        
        assert "too large" in str(exc_info.value).lower()
    finally:
        Path(temp_path).unlink()


def test_reject_oversized_string():
    """Test that strings exceeding size limit are rejected."""
    large_xml = '<?xml version="1.0"?><root>' + 'x' * (MAX_XML_SIZE_BYTES + 1000) + '</root>'
    
    with pytest.raises(XMLSecurityError) as exc_info:
        parse_xml_string_safely(large_xml)
    
    assert "too large" in str(exc_info.value).lower()


def test_reject_deep_nesting():
    """Test that excessively nested XML is rejected."""
    # Create XML with > MAX_XML_DEPTH levels
    depth = 60  # More than MAX_XML_DEPTH (50)
    xml_content = '<?xml version="1.0"?>' + '<a>' * depth + 'content' + '</a>' * depth
    
    with pytest.raises(XMLSecurityError) as exc_info:
        parse_xml_string_safely(xml_content)
    
    assert "deep" in str(exc_info.value).lower() or "depth" in str(exc_info.value).lower()


def test_parse_normal_nmap_output():
    """Test that normal nmap output parses successfully."""
    nmap_xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
    <host>
        <address addr="192.168.1.100" addrtype="ipv4"/>
        <ports>
            <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh" product="OpenSSH" version="8.2"/>
            </port>
        </ports>
    </host>
</nmaprun>"""
    
    root = parse_xml_string_safely(nmap_xml)
    assert root.tag == 'nmaprun'
    assert root.get('scanner') == 'nmap'
    
    hosts = root.findall('.//host')
    assert len(hosts) == 1
    
    ports = root.findall('.//port[@portid="22"]')
    assert len(ports) == 1


def test_sanitize_payload():
    """Test that payload sanitization works correctly."""
    from src.utils.security import sanitize_payload
    
    payload = {
        "event": {
            "reason": "x" * 2000  # Very long reason
        },
        "evidence": [
            {
                "http": {
                    "title": "y" * 1000,  # Very long title
                    "status_code": 200
                }
            }
        ]
    }
    
    sanitized = sanitize_payload(payload)
    
    # Long strings should be truncated
    assert len(sanitized["event"]["reason"]) <= 1003  # 1000 + '...'
    assert len(sanitized["evidence"][0]["http"]["title"]) <= 503  # 500 + '...'


def test_compute_evidence_hash():
    """Test that evidence hash computation works."""
    from src.utils.security import compute_evidence_hash
    
    data = "sensitive response body"
    hash1 = compute_evidence_hash(data)
    hash2 = compute_evidence_hash(data)
    
    # Same input should give same hash
    assert hash1 == hash2
    assert len(hash1) == 64  # SHA256 hex
    
    # Different input should give different hash
    hash3 = compute_evidence_hash("different data")
    assert hash1 != hash3
