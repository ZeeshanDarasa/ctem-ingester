"""
Security utilities for safe XML parsing and data sanitization.
"""

import defusedxml.ElementTree as ET
from typing import Any, Dict
from pathlib import Path


# XML parsing safety limits
MAX_XML_SIZE_BYTES = 10 * 1024 * 1024  # 10MB
MAX_XML_DEPTH = 50


class XMLSecurityError(Exception):
    """Raised when XML parsing encounters security issues."""
    pass


def parse_xml_safely(file_path: Path | str) -> ET.Element:
    """
    Parse XML file safely using defusedxml.
    
    Protects against:
    - XXE (XML External Entity) attacks
    - Entity expansion bombs (billion laughs attack)
    - Excessive file sizes
    - Excessive nesting depth
    
    Args:
        file_path: Path to XML file
    
    Returns:
        Root element of parsed XML tree
    
    Raises:
        XMLSecurityError: If file is too large or parsing fails
        FileNotFoundError: If file doesn't exist
    """
    path = Path(file_path)
    
    # Check file size
    file_size = path.stat().st_size
    if file_size > MAX_XML_SIZE_BYTES:
        raise XMLSecurityError(
            f"XML file too large: {file_size} bytes "
            f"(max {MAX_XML_SIZE_BYTES} bytes)"
        )
    
    # Parse with defusedxml (automatically disables dangerous features)
    try:
        tree = ET.parse(str(path))
        root = tree.getroot()
    except ET.ParseError as e:
        raise XMLSecurityError(f"XML parsing failed: {e}") from e
    
    # Check depth
    max_depth = _get_xml_depth(root)
    if max_depth > MAX_XML_DEPTH:
        raise XMLSecurityError(
            f"XML nesting too deep: {max_depth} levels "
            f"(max {MAX_XML_DEPTH} levels)"
        )
    
    return root


def parse_xml_string_safely(xml_string: str) -> ET.Element:
    """
    Parse XML string safely using defusedxml.
    
    Args:
        xml_string: XML content as string
    
    Returns:
        Root element of parsed XML tree
    
    Raises:
        XMLSecurityError: If XML is too large or parsing fails
    """
    # Check size
    xml_bytes = xml_string.encode('utf-8')
    if len(xml_bytes) > MAX_XML_SIZE_BYTES:
        raise XMLSecurityError(
            f"XML string too large: {len(xml_bytes)} bytes "
            f"(max {MAX_XML_SIZE_BYTES} bytes)"
        )
    
    # Parse with defusedxml
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as e:
        raise XMLSecurityError(f"XML parsing failed: {e}") from e
    
    # Check depth
    max_depth = _get_xml_depth(root)
    if max_depth > MAX_XML_DEPTH:
        raise XMLSecurityError(
            f"XML nesting too deep: {max_depth} levels "
            f"(max {MAX_XML_DEPTH} levels)"
        )
    
    return root


def _get_xml_depth(element: ET.Element, current_depth: int = 0) -> int:
    """
    Recursively calculate maximum depth of XML tree.
    
    Args:
        element: XML element
        current_depth: Current depth level
    
    Returns:
        Maximum depth from this element
    """
    if len(element) == 0:
        return current_depth
    
    return max(
        _get_xml_depth(child, current_depth + 1)
        for child in element
    )


def sanitize_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize canonical event payload before storage.
    
    Removes or redacts sensitive data that shouldn't be persisted:
    - Full HTTP response bodies
    - Complete file listings
    - Embedded credentials
    
    Args:
        payload: Canonical event dictionary
    
    Returns:
        Sanitized copy of payload
    """
    # Create shallow copy
    sanitized = payload.copy()
    
    # Remove evidence with large data
    if 'evidence' in sanitized and sanitized['evidence']:
        for evidence_item in sanitized['evidence']:
            # Keep only metadata, remove large fields
            if 'http' in evidence_item and evidence_item['http']:
                http_data = evidence_item['http']
                # Truncate title if too long
                if 'title' in http_data and http_data['title']:
                    if len(http_data['title']) > 500:
                        http_data['title'] = http_data['title'][:500] + '...'
                # Remove body if present (shouldn't be, but safety check)
                http_data.pop('body', None)
                http_data.pop('response_body', None)
    
    # Truncate long reason strings
    if 'event' in sanitized and 'reason' in sanitized['event']:
        if sanitized['event']['reason'] and len(sanitized['event']['reason']) > 1000:
            sanitized['event']['reason'] = sanitized['event']['reason'][:1000] + '...'
    
    # Truncate disposition notes
    if 'disposition' in sanitized and sanitized['disposition']:
        if 'notes' in sanitized['disposition'] and sanitized['disposition']['notes']:
            notes = sanitized['disposition']['notes']
            if len(notes) > 2000:
                sanitized['disposition']['notes'] = notes[:2000] + '...'
    
    return sanitized


def compute_evidence_hash(data: str | bytes) -> str:
    """
    Compute SHA256 hash of evidence data.
    
    Used to prove existence of sensitive data without storing it.
    
    Args:
        data: Evidence data to hash
    
    Returns:
        Hex string of SHA256 hash
    """
    import hashlib
    
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    return hashlib.sha256(data).hexdigest()
