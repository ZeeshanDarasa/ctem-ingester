"""
Simple base transformer interface for extensibility.
"""

from abc import ABC, abstractmethod
from typing import List
from pathlib import Path

from src.models.canonical import ExposureEventModel


class BaseTransformer(ABC):
    """
    Base interface for transformers.
    
    To add a new scanner:
    1. Create a class that inherits from BaseTransformer
    2. Implement the transform() method
    3. Register in src/transformers/registry.py
    """
    
    @abstractmethod
    def transform(self, file_path: Path, office_id: str, scanner_id: str) -> List[ExposureEventModel]:
        """
        Transform scanner output to canonical exposure events.
        
        Args:
            file_path: Path to scanner output file
            office_id: Office identifier
            scanner_id: Scanner instance identifier
        
        Returns:
            List of ExposureEventModel instances
        
        Raises:
            Exception: If transformation fails
        """
        pass


class TransformerError(Exception):
    """Raised when transformation fails."""
    pass
