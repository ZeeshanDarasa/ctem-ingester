"""
ID generation utilities for deterministic exposure IDs and unique event IDs.
"""

import hashlib
from uuid_utils import uuid7


def generate_exposure_id(
    office_id: str,
    asset_id: str,
    dst_ip: str,
    dst_port: int | None,
    protocol: str,
    exposure_class: str
) -> str:
    """
    Generate deterministic exposure ID for deduplication.
    
    Same inputs always produce the same exposure ID, allowing
    multiple observations of the same exposure to be correlated.
    
    Args:
        office_id: Office identifier
        asset_id: Asset identifier
        dst_ip: Destination IP address
        dst_port: Destination port (or None for ICMP etc)
        protocol: Protocol name
        exposure_class: Exposure classification
    
    Returns:
        32-character hex string (SHA256 truncated)
    """
    # Use empty string for None port to ensure deterministic hashing
    port_str = str(dst_port) if dst_port is not None else ""
    
    components = f"{office_id}|{asset_id}|{dst_ip}|{port_str}|{protocol}|{exposure_class}"
    hash_bytes = hashlib.sha256(components.encode('utf-8')).digest()
    
    # Return first 32 hex characters (16 bytes)
    return hash_bytes.hex()[:32]


def generate_event_id() -> str:
    """
    Generate unique event ID using UUIDv7 (time-ordered).
    
    UUIDv7 provides monotonically increasing IDs with embedded timestamps,
    useful for time-series queries and debugging.
    
    Returns:
        UUIDv7 string
    """
    return str(uuid7())


def generate_dedupe_key(
    office_id: str,
    asset_id: str,
    dst_ip: str,
    dst_port: int | None,
    protocol: str,
    exposure_class: str,
    service_product: str | None = None
) -> str:
    """
    Generate deduplication key for identifying same finding.
    
    Similar to exposure_id but may include additional fields
    for more granular deduplication (e.g., service version).
    
    Args:
        office_id: Office identifier
        asset_id: Asset identifier  
        dst_ip: Destination IP address
        dst_port: Destination port (or None)
        protocol: Protocol name
        exposure_class: Exposure classification
        service_product: Optional service product name
    
    Returns:
        32-character hex string (SHA256 truncated)
    """
    port_str = str(dst_port) if dst_port is not None else ""
    product_str = service_product or ""
    
    components = (
        f"{office_id}|{asset_id}|{dst_ip}|{port_str}|"
        f"{protocol}|{exposure_class}|{product_str}"
    )
    hash_bytes = hashlib.sha256(components.encode('utf-8')).digest()
    
    return hash_bytes.hex()[:32]
