"""
Unit tests for Pydantic canonical models.
Tests strict validation, enums, and field validators.
"""

import pytest
from datetime import datetime, timezone
from pydantic import ValidationError

from src.models.canonical import (
    ExposureEventModel, Event, Office, Scanner, Target, Asset,
    Exposure, Vector, Service, EventKind, EventAction,
    ExposureClass, ExposureStatus, Transport, ServiceAuth
)


def test_valid_minimal_exposure_event():
    """Test that a minimal valid exposure event passes validation."""
    event_data = {
        "schema_version": "1.0.0",
        "@timestamp": "2026-01-13T10:00:00Z",
        "event": {
            "id": "evt-123",
            "kind": "event",
            "category": ["network"],
            "type": ["info"],
            "action": "exposure_opened",
            "severity": 50
        },
        "office": {
            "id": "office-1",
            "name": "Office One"
        },
        "scanner": {
            "id": "scanner-1",
            "type": "nmap"
        },
        "target": {
            "asset": {
                "id": "asset-1",
                "ip": ["192.168.1.100"]
            }
        },
        "exposure": {
            "id": "exp-123",
            "class": "unknown_service_exposed",
            "status": "open",
            "vector": {
                "transport": "tcp",
                "protocol": "unknown",
                "dst": {
                    "ip": "192.168.1.100",
                    "port": 8080
                }
            }
        }
    }
    
    # Should not raise
    event = ExposureEventModel(**event_data)
    assert event.event.severity == 50
    assert event.exposure.class_ == ExposureClass.UNKNOWN_SERVICE_EXPOSED


def test_invalid_enum_value():
    """Test that invalid enum values are rejected."""
    event_data = {
        "schema_version": "1.0.0",
        "@timestamp": "2026-01-13T10:00:00Z",
        "event": {
            "id": "evt-123",
            "kind": "invalid_kind",  # Invalid enum
            "category": ["network"],
            "type": ["info"],
            "action": "exposure_opened",
            "severity": 50
        },
        "office": {"id": "office-1", "name": "Office One"},
        "scanner": {"id": "scanner-1", "type": "nmap"},
        "target": {"asset": {"id": "asset-1"}},
        "exposure": {
            "id": "exp-123",
            "class": "unknown_service_exposed",
            "status": "open",
            "vector": {
                "transport": "tcp",
                "protocol": "unknown",
                "dst": {"ip": "192.168.1.100", "port": 8080}
            }
        }
    }
    
    with pytest.raises(ValidationError) as exc_info:
        ExposureEventModel(**event_data)
    
    assert "kind" in str(exc_info.value)


def test_extra_fields_rejected():
    """Test that extra fields are rejected (forbid mode)."""
    event_data = {
        "schema_version": "1.0.0",
        "@timestamp": "2026-01-13T10:00:00Z",
        "event": {
            "id": "evt-123",
            "kind": "event",
            "category": ["network"],
            "type": ["info"],
            "action": "exposure_opened",
            "severity": 50,
            "extra_field": "should_fail"  # Extra field
        },
        "office": {"id": "office-1", "name": "Office One"},
        "scanner": {"id": "scanner-1", "type": "nmap"},
        "target": {"asset": {"id": "asset-1"}},
        "exposure": {
            "id": "exp-123",
            "class": "unknown_service_exposed",
            "status": "open",
            "vector": {
                "transport": "tcp",
                "protocol": "unknown",
                "dst": {"ip": "192.168.1.100", "port": 8080}
            }
        }
    }
    
    with pytest.raises(ValidationError) as exc_info:
        ExposureEventModel(**event_data)
    
    assert "extra" in str(exc_info.value).lower() or "forbidden" in str(exc_info.value).lower()


def test_severity_bounds():
    """Test that severity must be in [0, 100]."""
    event_data = {
        "id": "evt-123",
        "kind": "event",
        "category": ["network"],
        "type": ["info"],
        "action": "exposure_opened",
        "severity": 150  # Invalid
    }
    
    with pytest.raises(ValidationError):
        Event(**event_data)
    
    # Test negative
    event_data["severity"] = -10
    with pytest.raises(ValidationError):
        Event(**event_data)
    
    # Test valid boundaries
    event_data["severity"] = 0
    Event(**event_data)  # Should work
    
    event_data["severity"] = 100
    Event(**event_data)  # Should work


def test_confidence_bounds():
    """Test that confidence must be in [0, 1]."""
    exposure_data = {
        "id": "exp-123",
        "class": "unknown_service_exposed",
        "status": "open",
        "vector": {
            "transport": "tcp",
            "protocol": "unknown",
            "dst": {"ip": "192.168.1.100", "port": 8080}
        },
        "confidence": 1.5  # Invalid
    }
    
    with pytest.raises(ValidationError):
        Exposure(**exposure_data)
    
    # Test valid
    exposure_data["confidence"] = 0.95
    Exposure(**exposure_data)  # Should work


def test_last_seen_after_first_seen():
    """Test that last_seen must be >= first_seen."""
    exposure_data = {
        "id": "exp-123",
        "class": "unknown_service_exposed",
        "status": "open",
        "vector": {
            "transport": "tcp",
            "protocol": "unknown",
            "dst": {"ip": "192.168.1.100", "port": 8080}
        },
        "first_seen": "2026-01-13T12:00:00Z",
        "last_seen": "2026-01-13T10:00:00Z"  # Before first_seen
    }
    
    with pytest.raises(ValidationError) as exc_info:
        Exposure(**exposure_data)
    
    assert "last_seen" in str(exc_info.value)


def test_status_action_alignment():
    """Test that resolved status requires resolved action."""
    event_data = {
        "schema_version": "1.0.0",
        "@timestamp": "2026-01-13T10:00:00Z",
        "event": {
            "id": "evt-123",
            "kind": "event",
            "category": ["network"],
            "type": ["info"],
            "action": "exposure_opened",  # Wrong action for resolved status
            "severity": 50
        },
        "office": {"id": "office-1", "name": "Office One"},
        "scanner": {"id": "scanner-1", "type": "nmap"},
        "target": {"asset": {"id": "asset-1"}},
        "exposure": {
            "id": "exp-123",
            "class": "unknown_service_exposed",
            "status": "resolved",  # Resolved status
            "vector": {
                "transport": "tcp",
                "protocol": "unknown",
                "dst": {"ip": "192.168.1.100", "port": 8080}
            }
        }
    }
    
    with pytest.raises(ValidationError) as exc_info:
        ExposureEventModel(**event_data)
    
    assert "action" in str(exc_info.value) or "resolved" in str(exc_info.value)


def test_port_required_for_tcp():
    """Test that port is required for TCP with port-based exposure classes."""
    exposure_data = {
        "id": "exp-123",
        "class": "unknown_service_exposed",
        "status": "open",
        "vector": {
            "transport": "tcp",
            "protocol": "unknown",
            "dst": {
                "ip": "192.168.1.100"
                # Missing port
            }
        }
    }
    
    with pytest.raises(ValidationError) as exc_info:
        Exposure(**exposure_data)
    
    assert "port" in str(exc_info.value)


def test_port_validation_range():
    """Test that port must be in valid range [0, 65535]."""
    vector_data = {
        "transport": "tcp",
        "protocol": "http",
        "dst": {
            "ip": "192.168.1.100",
            "port": 70000  # Invalid
        }
    }
    
    with pytest.raises(ValidationError):
        Vector(**vector_data)
    
    # Test valid
    vector_data["dst"]["port"] = 8080
    Vector(**vector_data)  # Should work
