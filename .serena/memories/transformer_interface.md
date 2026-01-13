# Transformer Interface - Extensibility Pattern

## Simple Base Interface (src/transformers/base.py)

```python
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List
from src.models.canonical import ExposureEventModel

class BaseTransformer(ABC):
    @abstractmethod
    def transform(
        self,
        file_path: Path,
        office_id: str,
        scanner_id: str
    ) -> List[ExposureEventModel]:
        """
        Transform scanner output to canonical exposure events.
        
        Args:
            file_path: Path to scanner output file
            office_id: Office identifier
            scanner_id: Scanner instance identifier
        
        Returns:
            List of ExposureEventModel instances
        """
        pass
```

## Registry Pattern (src/transformers/registry.py)

Simple dictionary-based registry for scanner types:

```python
from src.transformers.nmap_transformer import NmapTransformer

_TRANSFORMERS = {
    'nmap': NmapTransformer()
}

def get_transformer(scanner_type: str) -> Optional[BaseTransformer]:
    return _TRANSFORMERS.get(scanner_type.lower())

def register_transformer(scanner_type: str, transformer: BaseTransformer):
    _TRANSFORMERS[scanner_type.lower()] = transformer
```

## Adding New Scanner Support (3 Steps)

### 1. Create Transformer Class
```python
# src/transformers/masscan_transformer.py
from src.transformers.base import BaseTransformer

class MasscanTransformer(BaseTransformer):
    def transform(self, file_path, office_id, scanner_id):
        # Parse masscan JSON output
        # Convert to List[ExposureEventModel]
        # Return events
        pass
```

### 2. Register in Registry
```python
# src/transformers/registry.py
from src.transformers.masscan_transformer import MasscanTransformer

_TRANSFORMERS = {
    'nmap': NmapTransformer(),
    'masscan': MasscanTransformer()  # Add here
}
```

### 3. Use It
```bash
python ingest.py scan.json --scanner-type=masscan --office-id=X --scanner-id=Y
```

## nmap Transformer (Reference Implementation)

Located in `src/transformers/nmap_transformer.py`.

**Key responsibilities**:
- Parse nmap XML safely with defusedxml
- Extract host info (IP, MAC, hostname)
- Process open ports only (skip closed/filtered)
- Map port + service → ExposureClass enum
- Calculate severity based on exposure class
- Generate deterministic exposure IDs
- Create canonical ExposureEventModel instances

**Service Classification Logic**:
- Port-based rules (e.g., 22→SSH, 3306→MySQL)
- Service name matching (e.g., "mysql"→DB_EXPOSED)
- Product matching (e.g., "Docker Engine"→CONTAINER_API_EXPOSED)
- Fallback to UNKNOWN_SERVICE_EXPOSED

**Severity Scoring**:
- db_exposed: 90
- container_api_exposed: 85
- remote_admin_exposed: 70
- fileshare_exposed: 65
- debug_port_exposed: 60
- http_content_leak: 50
- unknown_service_exposed: 30

## Design Philosophy
Keep transformers:
- **Simple**: Single method to implement
- **Focused**: Parse input, return canonical models
- **Testable**: Pure functions, no side effects
- **Extensible**: Just implement interface + register
