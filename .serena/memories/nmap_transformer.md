# nmap Transformer (src/transformers/nmap_transformer.py)

## Purpose
Parses nmap XML scan output and transforms to canonical ExposureEventModel instances. One event per open port.

## XML Parsing Security (uses src/utils/security.py)
- **Library**: defusedxml.ElementTree (prevents XXE, entity expansion)
- **Size limit**: 10MB max file size (MAX_XML_SIZE_BYTES)
- **Depth limit**: 50 levels max nesting (MAX_XML_DEPTH)
- **Errors**: Raises XMLSecurityError if limits exceeded or attacks detected

## Service Classification Logic (_classify_exposure method)

Maps port + service name + product to ExposureClass enum:

### Port-Based Rules
- **22, ssh**: remote_admin_exposed
- **3389, rdp/ms-wbt-server**: remote_admin_exposed
- **5900, vnc**: remote_admin_exposed
- **445/548, smb/microsoft-ds**: fileshare_exposed
- **3306, mysql**: db_exposed
- **5432, postgresql**: db_exposed
- **27017, mongodb**: db_exposed
- **6379, redis**: db_exposed
- **2375/2376, docker**: container_api_exposed
- **6443 + ssl/kubernetes**: container_api_exposed
- **80/443/8080/8000/8888, http**: http_content_leak
- **9418, git**: vcs_protocol_exposed
- **9222, 6000, 63342, 5037, 50000, 5555, 5559, 1099**: debug_port_exposed
- **Unknown**: unknown_service_exposed

### Severity Scoring (_calculate_severity method)
Base severity by class:
- db_exposed: 90
- container_api_exposed: 85
- remote_admin_exposed: 70
- fileshare_exposed: 65
- debug_port_exposed: 60
- vcs_protocol_exposed: 55
- http_content_leak: 50
- unknown_service_exposed: 30

Adjustments: +10 for high-risk products (docker, kubernetes, jenkins), capped at 100

## ID Generation
- **event.id**: UUIDv7 (time-ordered, unique per observation)
- **exposure.id**: SHA256 hash of (office_id, asset_id, dst_ip, dst_port, protocol, exposure_class) - deterministic for deduplication
- **dedupe_key**: Similar to exposure.id but includes service_product for finer granularity

## XML Element Mapping
- `<nmaprun>` root: scanner version, start timestamp
- `<host>`: one host per scan target
- `<address addrtype="ipv4">`: target.asset.ip
- `<address addrtype="mac">`: target.asset.mac
- `<hostname>`: target.asset.hostname
- `<port protocol="tcp" portid="N" state="open">`: creates exposure
- `<service name="X" product="Y" version="Z">`: exposure.service

## Transform Flow
1. parse_xml_safely() validates + parses file
2. Verify root tag is 'nmaprun'
3. Extract scan timestamp from 'start' attribute
4. For each `<host>` element:
   - Extract addresses (IP, MAC)
   - Extract hostname
   - For each `<port state="open">`:
     - Extract port number, protocol, service info
     - Classify exposure class
     - Calculate severity
     - Generate IDs (event, exposure, dedupe_key)
     - Create canonical ExposureEventModel
5. Return list of events (one per open port)
