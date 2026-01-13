"""
Nuclei JSON output transformer to canonical exposure events.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
import re

from src.models.canonical import (
    ExposureEventModel, Event, Office, Scanner, Target, Asset,
    Exposure, Vector, Service, EventCorrelation,
    EventKind, EventAction, ExposureClass, ExposureStatus,
    Transport, ServiceAuth, ServiceBindScope, NetworkDirection
)
from src.transformers.base import BaseTransformer, TransformerError
from src.utils.id_generation import generate_event_id, generate_exposure_id, generate_dedupe_key


# Maximum JSON file size: 10MB
MAX_JSON_SIZE_BYTES = 10 * 1024 * 1024


class NucleiTransformer(BaseTransformer):
    """Transforms nuclei JSON output to canonical exposure events."""
    
    def __init__(self, schema_version: str = "1.0.0"):
        self.schema_version = schema_version
    
    def get_scanner_type(self) -> str:
        """Return the scanner type identifier."""
        return "nuclei"
    
    def transform(
        self,
        file_path: Path,
        office_id: str,
        scanner_id: str
    ) -> List[ExposureEventModel]:
        """
        Transform nuclei JSON file to canonical events.
        
        Args:
            file_path: Path to nuclei JSON file
            office_id: Office identifier
            scanner_id: Scanner instance identifier
        
        Returns:
            List of exposure events (one per finding)
        
        Raises:
            TransformerError: If parsing or transformation fails
        """
        try:
            findings = self._parse_json_safely(file_path)
        except Exception as e:
            raise TransformerError(f"Failed to parse nuclei JSON: {e}") from e
        
        # Validate it's a list
        if not isinstance(findings, list):
            raise TransformerError(
                f"Expected JSON array, got {type(findings).__name__}"
            )
        
        # Process each finding
        events = []
        scan_timestamp = datetime.now(timezone.utc)
        
        for finding in findings:
            if not isinstance(finding, dict):
                print(f"Warning: Skipping non-dict finding: {type(finding)}")
                continue
            
            event = self._process_finding(
                finding=finding,
                office_id=office_id,
                scanner_id=scanner_id,
                scan_timestamp=scan_timestamp
            )
            
            if event:
                events.append(event)
        
        return events
    
    def _parse_json_safely(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Parse JSON file with size limits for security.
        
        Args:
            file_path: Path to JSON file
        
        Returns:
            Parsed JSON data
        
        Raises:
            TransformerError: If file is too large or invalid JSON
        """
        # Check file size
        file_size = file_path.stat().st_size
        if file_size > MAX_JSON_SIZE_BYTES:
            raise TransformerError(
                f"JSON file too large: {file_size} bytes (max: {MAX_JSON_SIZE_BYTES})"
            )
        
        # Parse JSON
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _process_finding(
        self,
        finding: Dict[str, Any],
        office_id: str,
        scanner_id: str,
        scan_timestamp: datetime
    ) -> Optional[ExposureEventModel]:
        """Process a single nuclei finding and generate an event."""
        try:
            # Extract basic info
            template_id = finding.get('template-id', 'unknown')
            info = finding.get('info', {})
            finding_type = finding.get('type', 'unknown')
            host = finding.get('host', '')
            matched_at = finding.get('matched-at', host)
            
            # Extract info fields
            name = info.get('name', template_id)
            severity = info.get('severity', 'info')
            tags = info.get('tags', [])
            
            # Use timestamp from finding if available
            timestamp_str = finding.get('timestamp')
            if timestamp_str:
                try:
                    finding_timestamp = datetime.fromisoformat(
                        timestamp_str.replace('Z', '+00:00')
                    )
                except (ValueError, AttributeError):
                    finding_timestamp = scan_timestamp
            else:
                finding_timestamp = scan_timestamp
            
            # Parse host information
            host_info = self._extract_host_info(host)
            if not host_info.get('ip'):
                print(f"Warning: Could not extract IP from host: {host}")
                return None
            
            # Create asset
            asset = Asset(
                id=host_info['ip'],
                ip=[host_info['ip']],
                hostname=host_info.get('hostname')
            )
            
            # Classify exposure
            exposure_class = self._classify_exposure(
                severity=severity,
                tags=tags,
                template_id=template_id,
                finding_type=finding_type
            )
            
            # Calculate severity score
            severity_score = self._calculate_severity(severity, exposure_class)
            
            # Extract service information
            extracted_results = finding.get('extracted-results', [])
            service_product = None
            service_version = None
            
            if extracted_results:
                # Try to parse version from first extracted result
                result_str = str(extracted_results[0]) if extracted_results else None
                if result_str:
                    # Look for version patterns like "v8.0" or "8.0"
                    version_match = re.search(r'v?(\d+\.\d+(?:\.\d+)?)', result_str)
                    if version_match:
                        service_version = version_match.group(1)
                    service_product = result_str
            
            # Determine protocol and transport
            protocol = host_info.get('protocol', finding_type)
            transport = Transport.TCP  # Default to TCP for most protocols
            
            # Create service model
            service = Service(
                name=template_id,
                product=service_product,
                version=service_version,
                tls=protocol == 'https',
                auth=ServiceAuth.UNKNOWN,
                bind_scope=ServiceBindScope.UNKNOWN
            )
            
            # Create vector
            vector = Vector(
                transport=transport,
                protocol=protocol,
                dst={
                    'ip': host_info['ip'],
                    'port': host_info.get('port')
                },
                network_direction=NetworkDirection.INTERNAL
            )
            
            # Generate IDs
            exposure_id = generate_exposure_id(
                office_id=office_id,
                asset_id=asset.id,
                dst_ip=host_info['ip'],
                dst_port=host_info.get('port', 0),
                protocol=template_id,
                exposure_class=exposure_class.value
            )
            
            event_id = generate_event_id()
            
            dedupe_key = generate_dedupe_key(
                office_id=office_id,
                asset_id=asset.id,
                dst_ip=host_info['ip'],
                dst_port=host_info.get('port', 0),
                protocol=template_id,
                exposure_class=exposure_class.value,
                service_product=service_product
            )
            
            # Create exposure
            exposure = Exposure(
                id=exposure_id,
                class_=exposure_class,
                status=ExposureStatus.OPEN,
                vector=vector,
                service=service,
                first_seen=finding_timestamp,
                last_seen=finding_timestamp
            )
            
            # Create event
            event = Event(
                id=event_id,
                kind=EventKind.EVENT,
                category=['network'],
                type=['info'],
                action=EventAction.EXPOSURE_OPENED,
                severity=severity_score,
                correlation=EventCorrelation(dedupe_key=dedupe_key)
            )
            
            # Create office
            office = Office(
                id=office_id,
                name=f"Office-{office_id}"
            )
            
            # Create scanner
            scanner = Scanner(
                id=scanner_id,
                type=self.get_scanner_type(),
                version="unknown"  # Nuclei doesn't provide scanner version in output
            )
            
            # Create target
            target = Target(asset=asset)
            
            # Create full event model
            event_model = ExposureEventModel(
                schema_version=self.schema_version,
                timestamp=finding_timestamp,
                event=event,
                office=office,
                scanner=scanner,
                target=target,
                exposure=exposure
            )
            
            return event_model
            
        except Exception as e:
            # Log validation error but don't fail entire scan
            print(f"Error creating event for finding {finding.get('template-id', 'unknown')}: {e}")
            return None
    
    def _extract_host_info(self, host_url: str) -> Dict[str, Any]:
        """
        Extract IP, port, hostname, and protocol from host URL.
        
        Args:
            host_url: URL string (e.g., "http://10.0.2.131:80", "tcp://192.168.1.5:3306")
        
        Returns:
            Dict with keys: ip, port, hostname, protocol
        """
        host_info = {}
        
        try:
            parsed = urlparse(host_url)
            
            # Extract protocol
            host_info['protocol'] = parsed.scheme or 'unknown'
            
            # Extract hostname (could be IP or domain)
            hostname = parsed.hostname or parsed.netloc.split(':')[0]
            
            # Check if hostname is an IP address
            if self._is_ip_address(hostname):
                host_info['ip'] = hostname
            else:
                host_info['hostname'] = hostname
                # If not an IP, we still need an IP for asset.id
                # Use hostname as fallback
                host_info['ip'] = hostname
            
            # Extract port
            if parsed.port:
                host_info['port'] = parsed.port
            else:
                # Default ports based on protocol
                default_ports = {
                    'http': 80,
                    'https': 443,
                    'ftp': 21,
                    'ssh': 22,
                    'telnet': 23,
                    'smtp': 25,
                    'dns': 53,
                }
                host_info['port'] = default_ports.get(parsed.scheme)
            
        except Exception as e:
            print(f"Warning: Failed to parse host URL '{host_url}': {e}")
            # Try simple regex as fallback
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', host_url)
            if ip_match:
                host_info['ip'] = ip_match.group(1)
            
            port_match = re.search(r':(\d+)', host_url)
            if port_match:
                host_info['port'] = int(port_match.group(1))
        
        return host_info
    
    def _is_ip_address(self, s: str) -> bool:
        """Check if string is an IPv4 address."""
        try:
            parts = s.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False
    
    def _classify_exposure(
        self,
        severity: str,
        tags: List[str],
        template_id: str,
        finding_type: str
    ) -> ExposureClass:
        """
        Classify exposure based on nuclei finding attributes.
        
        Args:
            severity: Nuclei severity (critical, high, medium, low, info)
            tags: List of template tags
            template_id: Template identifier
            finding_type: Type of finding (http, dns, network, etc.)
        
        Returns:
            ExposureClass enum value
        """
        # Convert to lowercase for comparison
        tags_lower = [tag.lower() for tag in tags]
        template_lower = template_id.lower()
        
        # Database exposures
        if any(keyword in tags_lower for keyword in ['database', 'mongodb', 'mysql', 'postgresql', 'redis', 'db']):
            return ExposureClass.DB_EXPOSED
        
        # Container APIs (check before debug panels since k8s dashboard should be container)
        if any(keyword in tags_lower for keyword in ['docker', 'kubernetes', 'k8s', 'container']):
            return ExposureClass.CONTAINER_API_EXPOSED
        
        # Remote admin interfaces
        if any(keyword in tags_lower for keyword in ['admin', 'ssh', 'rdp', 'vnc', 'telnet']):
            return ExposureClass.REMOTE_ADMIN_EXPOSED
        
        # Debug/admin panels
        if any(keyword in template_lower for keyword in ['debug', 'console', 'panel', 'dashboard']):
            return ExposureClass.DEBUG_PORT_EXPOSED
        if any(keyword in tags_lower for keyword in ['debug', 'console', 'panel']):
            return ExposureClass.DEBUG_PORT_EXPOSED
        
        # File shares
        if any(keyword in tags_lower for keyword in ['smb', 'nfs', 'ftp', 'fileshare']):
            return ExposureClass.FILESHARE_EXPOSED
        
        # VCS protocols
        if any(keyword in tags_lower for keyword in ['git', 'svn', 'cvs', 'vcs']):
            return ExposureClass.VCS_PROTOCOL_EXPOSED
        
        # HTTP content leaks (exposure, disclosure, leak tags)
        if any(keyword in tags_lower for keyword in ['exposure', 'disclosure', 'leak', 'exposure']):
            return ExposureClass.HTTP_CONTENT_LEAK
        
        # mDNS service advertisement
        if any(keyword in tags_lower for keyword in ['mdns', 'bonjour', 'zeroconf']):
            return ExposureClass.SERVICE_ADVERTISED_MDNS
        
        # Egress tunnel indicators
        if any(keyword in tags_lower for keyword in ['tunnel', 'proxy', 'socks', 'vpn']):
            return ExposureClass.EGRESS_TUNNEL_INDICATOR
        
        # Default to unknown service exposed
        return ExposureClass.UNKNOWN_SERVICE_EXPOSED
    
    def _calculate_severity(
        self,
        nuclei_severity: str,
        exposure_class: ExposureClass
    ) -> int:
        """
        Calculate severity score (0-100) based on nuclei severity and exposure class.
        
        Args:
            nuclei_severity: Nuclei severity level (critical, high, medium, low, info)
            exposure_class: Classified exposure class
        
        Returns:
            Severity score (0-100)
        """
        # Base severity from nuclei
        severity_map = {
            'critical': 95,
            'high': 80,
            'medium': 60,
            'low': 40,
            'info': 20,
            'unknown': 30
        }
        
        base_severity = severity_map.get(nuclei_severity.lower(), 30)
        
        # Adjust based on exposure class if it's more severe
        class_severity_map = {
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
        
        class_severity = class_severity_map.get(exposure_class, 30)
        
        # Use the higher of the two
        return max(base_severity, class_severity)
