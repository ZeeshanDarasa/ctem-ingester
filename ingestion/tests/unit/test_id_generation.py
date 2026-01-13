"""
Unit tests for ID generation utilities.
Tests deterministic exposure IDs and UUIDv7 generation.
"""

import pytest
from src.utils.id_generation import (
    generate_exposure_id,
    generate_event_id,
    generate_dedupe_key
)


def test_exposure_id_deterministic():
    """Test that same inputs produce same exposure ID."""
    id1 = generate_exposure_id(
        office_id="office-1",
        asset_id="asset-1",
        dst_ip="192.168.1.100",
        dst_port=8080,
        protocol="http",
        exposure_class="http_content_leak"
    )
    
    id2 = generate_exposure_id(
        office_id="office-1",
        asset_id="asset-1",
        dst_ip="192.168.1.100",
        dst_port=8080,
        protocol="http",
        exposure_class="http_content_leak"
    )
    
    assert id1 == id2
    assert len(id1) == 32  # SHA256 truncated to 32 chars


def test_exposure_id_different_port():
    """Test that different port produces different exposure ID."""
    id1 = generate_exposure_id(
        office_id="office-1",
        asset_id="asset-1",
        dst_ip="192.168.1.100",
        dst_port=8080,
        protocol="http",
        exposure_class="http_content_leak"
    )
    
    id2 = generate_exposure_id(
        office_id="office-1",
        asset_id="asset-1",
        dst_ip="192.168.1.100",
        dst_port=8443,  # Different port
        protocol="http",
        exposure_class="http_content_leak"
    )
    
    assert id1 != id2


def test_exposure_id_none_port():
    """Test that None port is handled consistently."""
    id1 = generate_exposure_id(
        office_id="office-1",
        asset_id="asset-1",
        dst_ip="192.168.1.100",
        dst_port=None,
        protocol="icmp",
        exposure_class="egress_tunnel_indicator"
    )
    
    id2 = generate_exposure_id(
        office_id="office-1",
        asset_id="asset-1",
        dst_ip="192.168.1.100",
        dst_port=None,
        protocol="icmp",
        exposure_class="egress_tunnel_indicator"
    )
    
    assert id1 == id2


def test_event_id_unique():
    """Test that event IDs are unique (UUIDv7)."""
    id1 = generate_event_id()
    id2 = generate_event_id()
    
    assert id1 != id2
    assert len(id1) == 36  # UUID format with hyphens
    assert '-' in id1


def test_event_id_ordering():
    """Test that UUIDv7 has time-ordering property."""
    import time
    
    id1 = generate_event_id()
    time.sleep(0.001)  # Small delay
    id2 = generate_event_id()
    
    # UUIDv7 should be sortable by time
    assert id1 < id2  # Lexicographic ordering


def test_dedupe_key_with_product():
    """Test that dedupe key includes service product."""
    key1 = generate_dedupe_key(
        office_id="office-1",
        asset_id="asset-1",
        dst_ip="192.168.1.100",
        dst_port=3306,
        protocol="mysql",
        exposure_class="db_exposed",
        service_product="MySQL 8.0"
    )
    
    key2 = generate_dedupe_key(
        office_id="office-1",
        asset_id="asset-1",
        dst_ip="192.168.1.100",
        dst_port=3306,
        protocol="mysql",
        exposure_class="db_exposed",
        service_product="MariaDB 10.5"
    )
    
    # Different products should give different keys
    assert key1 != key2


def test_dedupe_key_without_product():
    """Test that dedupe key works without product."""
    key1 = generate_dedupe_key(
        office_id="office-1",
        asset_id="asset-1",
        dst_ip="192.168.1.100",
        dst_port=8080,
        protocol="http",
        exposure_class="http_content_leak"
    )
    
    key2 = generate_dedupe_key(
        office_id="office-1",
        asset_id="asset-1",
        dst_ip="192.168.1.100",
        dst_port=8080,
        protocol="http",
        exposure_class="http_content_leak",
        service_product=None
    )
    
    assert key1 == key2
