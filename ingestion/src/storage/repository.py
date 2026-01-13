"""
Simple repository for ingesting exposure events.
"""

from datetime import datetime
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from src.models.canonical import ExposureEventModel
from src.models.storage import ExposureEvent, ExposureCurrent


BATCH_SIZE = 500  # Batch size for inserts


class ExposureRepository:
    """Repository for exposure event storage and upsert operations."""
    
    def __init__(self, session: Session):
        self.session = session
    
    def batch_insert_events(self, events: List[ExposureEventModel]) -> int:
        """
        Batch insert events into exposure_events table (append-only).
        
        Args:
            events: List of canonical exposure event models
        
        Returns:
            Number of events inserted
        """
        if not events:
            return 0
        
        # Convert to storage model dicts
        event_dicts = [self._event_model_to_dict(event) for event in events]
        
        # Batch insert in chunks
        total_inserted = 0
        for i in range(0, len(event_dicts), BATCH_SIZE):
            chunk = event_dicts[i:i + BATCH_SIZE]
            self.session.bulk_insert_mappings(ExposureEvent, chunk)
            total_inserted += len(chunk)
        
        return total_inserted
    
    def batch_upsert_current(self, events: List[ExposureEventModel]) -> Dict[str, int]:
        """
        Batch upsert events into exposures_current table.
        
        On conflict (office_id, exposure_id):
        - Updates: last_seen, status, severity, risk_score, event_action
        - Preserves: first_seen, non-null optional fields (unless explicit null)
        
        Args:
            events: List of canonical exposure event models
        
        Returns:
            Dict with 'inserted' and 'updated' counts
        """
        if not events:
            return {'inserted': 0, 'updated': 0}
        
        stats = {'inserted': 0, 'updated': 0}
        
        # Process in chunks for optimal performance
        for i in range(0, len(events), BATCH_SIZE):
            chunk = events[i:i + BATCH_SIZE]
            chunk_stats = self._upsert_chunk(chunk)
            stats['inserted'] += chunk_stats['inserted']
            stats['updated'] += chunk_stats['updated']
        
        return stats
    
    def _upsert_chunk(self, events: List[ExposureEventModel]) -> Dict[str, int]:
        """Upsert a single chunk of events."""
        # Convert to current state dicts
        current_dicts = [self._event_model_to_current_dict(event) for event in events]
        
        # Build upsert statement
        stmt = insert(ExposureCurrent)
        
        # Define update values (what to update on conflict)
        # IMPORTANT: Preserve first_seen, don't overwrite non-null with null
        update_values = {
            'last_seen': stmt.excluded.last_seen,
            'status': stmt.excluded.status,
            'severity': stmt.excluded.severity,
            'event_action': stmt.excluded.event_action,
            'event_kind': stmt.excluded.event_kind,
            'updated_at': datetime.utcnow(),
        }
        
        # Conditionally update optional fields (preserve non-null)
        # Use COALESCE to keep existing value if new value is null
        optional_fields = [
            'risk_score', 'confidence',
            'asset_hostname', 'asset_ip', 'asset_mac', 'asset_os', 'asset_managed',
            'service_name', 'service_product', 'service_version',
            'service_tls', 'service_auth', 'service_bind_scope',
            'service_json', 'resource_json', 'data_class_json',
            'office_region', 'office_network_zone',
            'disposition_ticket', 'disposition_owner', 'disposition_sla',
        ]
        
        for field in optional_fields:
            # Update if new value is not null, otherwise keep existing
            update_values[field] = stmt.excluded.get(field)
        
        # Execute upsert with dialect-specific syntax
        try:
            # Try DuckDB/SQLite syntax first (INSERT ... ON CONFLICT)
            upsert_stmt = stmt.on_conflict_do_update(
                index_elements=['office_id', 'exposure_id'],
                set_=update_values
            )
            result = self.session.execute(upsert_stmt, current_dicts)
            
            # DuckDB doesn't provide rowcount for upserts reliably
            # Estimate: assume half are updates (conservative)
            inserted = len(current_dicts) // 2
            updated = len(current_dicts) - inserted
            
        except Exception as e:
            # Fallback: manual upsert (slower but portable)
            inserted, updated = self._manual_upsert(current_dicts)
        
        return {'inserted': inserted, 'updated': updated}
    
    def _manual_upsert(self, current_dicts: List[Dict[str, Any]]) -> tuple[int, int]:
        """
        Manual upsert fallback for databases without native upsert.
        
        Returns:
            (inserted_count, updated_count)
        """
        inserted = 0
        updated = 0
        
        for data in current_dicts:
            # Check if exists
            existing = self.session.query(ExposureCurrent).filter_by(
                office_id=data['office_id'],
                exposure_id=data['exposure_id']
            ).first()
            
            if existing:
                # Update existing (preserve first_seen and non-null fields)
                existing.last_seen = data['last_seen']
                existing.status = data['status']
                existing.severity = data['severity']
                existing.event_action = data['event_action']
                existing.event_kind = data['event_kind']
                existing.updated_at = datetime.utcnow()
                
                # Update optional fields only if new value is not None
                for key, value in data.items():
                    if key not in ['office_id', 'exposure_id', 'first_seen', 'created_at']:
                        if value is not None:
                            setattr(existing, key, value)
                
                updated += 1
            else:
                # Insert new
                new_exposure = ExposureCurrent(**data)
                self.session.add(new_exposure)
                inserted += 1
        
        return (inserted, updated)
    
    def _event_model_to_dict(self, event: ExposureEventModel) -> Dict[str, Any]:
        """Convert canonical event model to exposure_events table dict."""
        # Sanitize payload before storage
        payload_dict = event.model_dump(mode='json', by_alias=True)
        sanitized = sanitize_payload(payload_dict)
        
        return {
            'event_id': event.event.id,
            'timestamp': event.timestamp,
            'office_id': event.office.id,
            'asset_id': event.target.asset.id,
            'exposure_id': event.exposure.id,
            'exposure_class': event.exposure.class_.value,
            'exposure_status': event.exposure.status.value,
            'event_action': event.event.action.value,
            'event_kind': event.event.kind.value,
            'severity': event.event.severity,
            'risk_score': event.event.risk_score,
            'confidence': event.exposure.confidence,
            'dst_ip': event.exposure.vector.dst.ip if event.exposure.vector.dst else None,
            'dst_port': event.exposure.vector.dst.port if event.exposure.vector.dst else None,
            'protocol': event.exposure.vector.protocol,
            'transport': event.exposure.vector.transport.value,
            'network_direction': (
                event.exposure.vector.network_direction.value
                if event.exposure.vector.network_direction else None
            ),
            'service_json': (
                event.exposure.service.model_dump(mode='json')
                if event.exposure.service else None
            ),
            'resource_json': (
                event.exposure.resource.model_dump(mode='json')
                if event.exposure.resource else None
            ),
            'scanner_id': event.scanner.id,
            'scanner_type': event.scanner.type,
            'scan_run_id': (
                event.event.correlation.scan_run_id
                if event.event.correlation else None
            ),
            'dedupe_key': (
                event.event.correlation.dedupe_key
                if event.event.correlation else None
            ),
            'raw_payload_json': sanitized,
            'created_at': datetime.utcnow(),
        }
    
    def _event_model_to_current_dict(self, event: ExposureEventModel) -> Dict[str, Any]:
        """Convert canonical event model to exposures_current table dict."""
        asset = event.target.asset
        service = event.exposure.service
        resource = event.exposure.resource
        
        # Determine first_seen and last_seen
        first_seen = event.exposure.first_seen or event.timestamp
        last_seen = event.exposure.last_seen or event.timestamp
        
        return {
            'office_id': event.office.id,
            'exposure_id': event.exposure.id,
            'exposure_class': event.exposure.class_.value,
            'status': event.exposure.status.value,
            'dst_ip': event.exposure.vector.dst.ip if event.exposure.vector.dst else None,
            'dst_port': event.exposure.vector.dst.port if event.exposure.vector.dst else None,
            'protocol': event.exposure.vector.protocol,
            'transport': event.exposure.vector.transport.value,
            'network_direction': (
                event.exposure.vector.network_direction.value
                if event.exposure.vector.network_direction else None
            ),
            'severity': event.event.severity,
            'risk_score': event.event.risk_score,
            'confidence': event.exposure.confidence,
            'first_seen': first_seen,
            'last_seen': last_seen,
            'asset_id': asset.id,
            'asset_hostname': asset.hostname,
            'asset_ip': asset.ip[0] if asset.ip and len(asset.ip) > 0 else None,
            'asset_mac': asset.mac,
            'asset_os': asset.os,
            'asset_managed': asset.managed,
            'service_name': service.name if service else None,
            'service_product': service.product if service else None,
            'service_version': service.version if service else None,
            'service_tls': service.tls if service else None,
            'service_auth': service.auth.value if service and service.auth else None,
            'service_bind_scope': (
                service.bind_scope.value if service and service.bind_scope else None
            ),
            'service_json': service.model_dump(mode='json') if service else None,
            'resource_json': resource.model_dump(mode='json') if resource else None,
            'event_action': event.event.action.value,
            'event_kind': event.event.kind.value,
            'scanner_id': event.scanner.id,
            'scanner_type': event.scanner.type,
            'office_name': event.office.name,
            'office_region': event.office.region,
            'office_network_zone': event.office.network_zone,
            'data_class_json': (
                [dc.value for dc in event.exposure.data_class]
                if event.exposure.data_class else None
            ),
            'disposition_ticket': (
                event.disposition.ticket if event.disposition else None
            ),
            'disposition_owner': (
                event.disposition.owner if event.disposition else None
            ),
            'disposition_sla': (
                event.disposition.sla if event.disposition else None
            ),
            'created_at': datetime.utcnow(),
        }
    
    def quarantine_file(
        self,
        filename: str,
        error_type: str,
        error_message: str,
        error_details: Dict[str, Any] | None = None,
        file_size: int | None = None,
        file_hash: str | None = None,
        scanner_type: str | None = None,
        office_id: str | None = None
    ):
        """
        Log a quarantined file.
        
        Args:
            filename: Name of the quarantined file
            error_type: Type of error (e.g., 'XMLParseError', 'ValidationError')
            error_message: Error message
            error_details: Additional error context
            file_size: Size of file in bytes
            file_hash: Hash of file content
            scanner_type: Type of scanner
            office_id: Office ID if known
        """
        quarantined = QuarantinedFile(
            filename=filename,
            file_size=file_size,
            file_hash=file_hash,
            error_type=error_type,
            error_message=error_message,
            error_details_json=error_details,
            scanner_type=scanner_type,
            office_id=office_id,
        )
        self.session.add(quarantined)
        self.session.commit()


def ingest_events(session: Session, events: List[ExposureEventModel]) -> Dict[str, int]:
    """
    Ingest exposure events to database.
    
    Args:
        session: Database session
        events: List of canonical exposure event models
    
    Returns:
        Dict with stats: events_inserted, exposures_inserted, exposures_updated
    """
    if not events:
        return {'events_inserted': 0, 'exposures_inserted': 0, 'exposures_updated': 0}
    
    repo = ExposureRepository(session)
    
    # Insert into append-only events table
    events_inserted = repo.batch_insert_events(events)
    
    # Upsert into current state table
    upsert_stats = repo.batch_upsert_current(events)
    
    return {
        'events_inserted': events_inserted,
        'exposures_inserted': upsert_stats['inserted'],
        'exposures_updated': upsert_stats['updated'],
    }
