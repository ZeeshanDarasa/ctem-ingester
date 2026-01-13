"""
Simple transformer registry for extensibility.
"""

from typing import Optional
from src.transformers.base import BaseTransformer
from src.transformers.nmap_transformer import NmapTransformer


# Registry of available transformers
_TRANSFORMERS = {
    'nmap': NmapTransformer()
}


def get_transformer(scanner_type: str) -> Optional[BaseTransformer]:
    """
    Get transformer for scanner type.
    
    Args:
        scanner_type: Type of scanner (e.g., 'nmap', 'masscan')
    
    Returns:
        Transformer instance or None if not found
    """
    return _TRANSFORMERS.get(scanner_type.lower())


def register_transformer(scanner_type: str, transformer: BaseTransformer):
    """
    Register a new transformer.
    
    Args:
        scanner_type: Type of scanner
        transformer: Transformer instance
    """
    _TRANSFORMERS[scanner_type.lower()] = transformer


def list_transformers() -> list[str]:
    """Get list of registered transformer types."""
    return list(_TRANSFORMERS.keys())
