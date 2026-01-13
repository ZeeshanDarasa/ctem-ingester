"""
nmap XML output transformer to canonical exposure events.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
import defusedxml.ElementTree as ET

from src.models.canonical import (
    ExposureEventModel, Event, Office, Scanner, Target, Asset,
    Exposure, Vector, Service, Resource, EventCorrelation,
    EventKind, EventAction, ExposureClass, ExposureStatus,
    Transport, ServiceAuth, ServiceBindScope, NetworkDirection
)
from src.transformers.base import BaseTransformer, TransformerError
from src.utils.security import parse_xml_safely
from src.utils.id_generation import generate_event_id, generate_exposure_id, generate_dedupe_key


class NmapTransformer(BaseTransformer):
    """Transforms nmap XML output to canonical exposure events."""
    
    def __init__(self, schema_version: str = "1.0.0"):
        self.schema_version = schema_version
    
    def transform(
        self,
        file_path: Path,
        office_id: str,
        scanner_id: str
    ) -> List[ExposureEventModel]:
        """
        Transform nmap XML file to canonical events.
        
        Args:
            file_path: Path to nmap XML file
            office_id: Office identifier
            scanner_id: Scanner instance identifier
        
        Returns:
            List of exposure events (one per open port)
        
        Raises:
            TransformerError: If parsing or transformation fails
        """
        try:
            # Parse XML safely
            root = parse_xml_safely(file_path)
        except Exception as e:
            raise TransformerError(f"Failed to parse nmap XML: {e}") from e
        
        # Verify it's an nmap scan
        if root.tag != 'nmaprun':
            raise TransformerError(
                f"Not a valid nmap XML file (root tag: {root.tag})"
            )
        
        # Extract scan timestamp
        scan_start = root.get('start')
        scan_timestamp = (
            datetime.fromtimestamp(int(scan_start), tz=timezone.utc)
            if scan_start else datetime.now(timezone.utc)
        )
        
        # Extract scanner info
        scanner_version = root.get('version', 'unknown')
        
        # Process each host
        events = []
        for host_elem in root.findall('.//host'):
            host_events = self._process_host(
                host_elem=host_elem,
                office_id=office_id,
                scanner_id=scanner_id,
                scanner_version=scanner_version,
                scan_timestamp=scan_timestamp
            )
            events.extend(host_events)
        
        return events
    
    def _process_host(
        self,
        host_elem: ET.Element,
        office_id: str,
        scanner_id: str,
        scanner_version: str,
        scan_timestamp: datetime
    ) -> List[ExposureEventModel]:
        """Process a single host element and generate events for open ports."""
        events = []
        
        # Extract host addresses
        addresses = self._extract_addresses(host_elem)
        if not addresses.get('ip'):
            # Skip hosts without IP
            return events
        
        # Extract hostname
        hostnames = host_elem.findall('.//hostname')
        hostname = hostnames[0].get('name') if hostnames else None
        
        # Create asset
        asset = Asset(
            id=addresses['ip'],  # Use IP as asset ID for now
            ip=[addresses['ip']],
            mac=addresses.get('mac'),
            hostname=hostname
        )
        
        # Process each open port
        for port_elem in host_elem.findall('.//ports/port'):
            state_elem = port_elem.find('state')
            if state_elem is None or state_elem.get('state') != 'open':
                continue  # Skip non-open ports
            
            # Create event for this open port
            event = self._create_port_event(
                port_elem=port_elem,
                asset=asset,
                office_id=office_id,
                scanner_id=scanner_id,
                scanner_version=scanner_version,
                scan_timestamp=scan_timestamp
            )
            
            if event:
                events.append(event)
        
        return events
    
    def _extract_addresses(self, host_elem: ET.Element) -> dict:
        """Extract IP and MAC addresses from host element."""
        addresses = {}
        
        for addr_elem in host_elem.findall('.//address'):
            addr_type = addr_elem.get('addrtype')
            addr = addr_elem.get('addr')
            
            if addr_type == 'ipv4' and not addresses.get('ip'):
                addresses['ip'] = addr
            elif addr_type == 'ipv6' and not addresses.get('ip'):
                addresses['ip'] = addr
            elif addr_type == 'mac':
                addresses['mac'] = addr
        
        return addresses
    
    def _create_port_event(
        self,
        port_elem: ET.Element,
        asset: Asset,
        office_id: str,
        scanner_id: str,
        scanner_version: str,
        scan_timestamp: datetime
    ) -> Optional[ExposureEventModel]:
        """Create exposure event for an open port."""
        # Extract port info
        port_num = int(port_elem.get('portid', '0'))
        protocol = port_elem.get('protocol', 'tcp')
        
        # Extract service info
        service_elem = port_elem.find('service')
        service_name = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
        service_product = service_elem.get('product') if service_elem is not None else None
        service_version = service_elem.get('version') if service_elem is not None else None
        service_tunnel = service_elem.get('tunnel') if service_elem is not None else None
        
        # Determine transport
        transport = Transport.TCP if protocol == 'tcp' else Transport.UDP
        
        # Classify exposure
        exposure_class = self._classify_exposure(
            port=port_num,
            service_name=service_name,
            product=service_product,
            tunnel=service_tunnel
        )
        
        # Determine severity based on exposure class
        severity = self._calculate_severity(exposure_class, service_name, service_product)
        
        # Generate IDs
        exposure_id = generate_exposure_id(
            office_id=office_id,
            asset_id=asset.id,
            dst_ip=asset.ip[0],
            dst_port=port_num,
            protocol=service_name,
            exposure_class=exposure_class.value
        )
        
        event_id = generate_event_id()
        
        dedupe_key = generate_dedupe_key(
            office_id=office_id,
            asset_id=asset.id,
            dst_ip=asset.ip[0],
            dst_port=port_num,
            protocol=service_name,
            exposure_class=exposure_class.value,
            service_product=service_product
        )
        
        # Create service model
        service = Service(
            name=service_name,
            product=service_product,
            version=service_version,
            tls=service_tunnel == 'ssl' if service_tunnel else None,
            auth=ServiceAuth.UNKNOWN,  # nmap doesn't detect this reliably
            bind_scope=ServiceBindScope.UNKNOWN  # nmap doesn't provide this
        )
        
        # Create vector
        vector = Vector(
            transport=transport,
            protocol=service_name,
            dst={
                'ip': asset.ip[0],
                'port': port_num
            },
            network_direction=NetworkDirection.INTERNAL  # Assume internal scan
        )
        
        # Create exposure
        exposure = Exposure(
            id=exposure_id,
            class_=exposure_class,
            status=ExposureStatus.OPEN,
            vector=vector,
            service=service,
            first_seen=scan_timestamp,
            last_seen=scan_timestamp
        )
        
        # Create event
        event = Event(
            id=event_id,
            kind=EventKind.EVENT,
            category=['network'],
            type=['info'],
            action=EventAction.EXPOSURE_OPENED,
            severity=severity,
            correlation=EventCorrelation(dedupe_key=dedupe_key)
        )
        
        # Create office
        office = Office(
            id=office_id,
            name=f"Office-{office_id}"  # Basic name, can be enriched later
        )
        
        # Create scanner
        scanner = Scanner(
            id=scanner_id,
            type=self.get_scanner_type(),
            version=scanner_version
        )
        
        # Create target
        target = Target(asset=asset)
        
        # Create full event model
        try:
            event_model = ExposureEventModel(
                schema_version=self.schema_version,
                timestamp=scan_timestamp,
                event=event,
                office=office,
                scanner=scanner,
                target=target,
                exposure=exposure
            )
            return event_model
        except Exception as e:
            # Log validation error but don't fail entire scan
            print(f"Validation error creating event: {e}")
            return None
    
    def _classify_exposure(
        self,
        port: int,
        service_name: str,
        product: Optional[str],
        tunnel: Optional[str]
    ) -> ExposureClass:
        """
        Classify exposure based on port, service, and product.
        
        Classification rules from plan:
        - 445/548 + smb → fileshare_exposed
        - 22 + ssh → remote_admin_exposed
        - 3389 + rdp → remote_admin_exposed
        - 5900 + vnc → remote_admin_exposed
        - 80/443/8080 + http → http_content_leak (requires secondary probe)
        - 2375/2376 + docker → container_api_exposed
        - 6443 + ssl/kubernetes → container_api_exposed
        - 3306/5432/27017/6379 → db_exposed
        - 9418 + git → vcs_protocol_exposed
        - Unknown → unknown_service_exposed
        """
        service_lower = service_name.lower()
        product_lower = product.lower() if product else ''
        
        # File sharing
        if port in [445, 548] or 'smb' in service_lower or 'microsoft-ds' in service_lower:
            return ExposureClass.FILESHARE_EXPOSED
        
        # Remote administration
        if port == 22 or service_lower == 'ssh':
            return ExposureClass.REMOTE_ADMIN_EXPOSED
        if port == 3389 or service_lower in ['rdp', 'ms-wbt-server']:
            return ExposureClass.REMOTE_ADMIN_EXPOSED
        if port == 5900 or 'vnc' in service_lower:
            return ExposureClass.REMOTE_ADMIN_EXPOSED
        
        # Container APIs
        if port in [2375, 2376] or 'docker' in service_lower or 'docker' in product_lower:
            return ExposureClass.CONTAINER_API_EXPOSED
        if port == 6443 or 'kubernetes' in service_lower or 'k8s' in service_lower:
            return ExposureClass.CONTAINER_API_EXPOSED
        
        # Databases
        if port == 3306 or 'mysql' in service_lower:
            return ExposureClass.DB_EXPOSED
        if port == 5432 or 'postgresql' in service_lower:
            return ExposureClass.DB_EXPOSED
        if port == 27017 or 'mongodb' in service_lower:
            return ExposureClass.DB_EXPOSED
        if port == 6379 or 'redis' in service_lower:
            return ExposureClass.DB_EXPOSED
        
        # VCS protocols
        if port == 9418 or service_lower == 'git':
            return ExposureClass.VCS_PROTOCOL_EXPOSED
        
        # HTTP services (potential content leaks)
        if port in [80, 443, 8000, 8080, 8888] or 'http' in service_lower:
            return ExposureClass.HTTP_CONTENT_LEAK
        
        # Debug ports
        if port in [9222, 6000, 63342, 5037]:
            return ExposureClass.DEBUG_PORT_EXPOSED
        
        # Jenkins
        if port in [50000] or 'jenkins' in product_lower:
            return ExposureClass.DEBUG_PORT_EXPOSED
        
        # Dev tool proxies (Postman, JMeter)
        if port in [5555, 5559, 1099]:
            return ExposureClass.DEBUG_PORT_EXPOSED
        
        # Default: unknown service
        return ExposureClass.UNKNOWN_SERVICE_EXPOSED
    
    def _calculate_severity(
        self,
        exposure_class: ExposureClass,
        service_name: str,
        product: Optional[str]
    ) -> int:
        """
        Calculate severity score (0-100) based on exposure class and context.
        
        Severity levels:
        - Critical (80-100): Databases, container APIs, unauthenticated admin
        - High (60-79): Remote admin, file shares
        - Medium (40-59): Debug ports, HTTP services
        - Low (20-39): Unknown services
        """
        severity_map = {
            ExposureClass.DB_EXPOSED: 90,
            ExposureClass.CONTAINER_API_EXPOSED: 85,
            ExposureClass.REMOTE_ADMIN_EXPOSED: 70,
            ExposureClass.FILESHARE_EXPOSED: 65,
            ExposureClass.DEBUG_PORT_EXPOSED: 60,
            ExposureClass.VCS_PROTOCOL_EXPOSED: 55,
            ExposureClass.HTTP_CONTENT_LEAK: 50,
            ExposureClass.SERVICE_ADVERTISED_MDNS: 40,
            ExposureClass.EGRESS_TUNNEL_INDICATOR: 45,
            ExposureClass.UNKNOWN_SERVICE_EXPOSED: 30,
        }
        
        base_severity = severity_map.get(exposure_class, 30)
        
        # Adjust for specific high-risk products
        if product:
            product_lower = product.lower()
            if any(keyword in product_lower for keyword in ['docker', 'kubernetes', 'jenkins']):
                base_severity = min(base_severity + 10, 100)
        
        return base_severity
