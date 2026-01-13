"""
Prometheus metrics for ingestion service observability.
"""

from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST


# File processing metrics
files_processed_total = Counter(
    'ingestion_files_processed_total',
    'Total number of files processed',
    ['status']  # success, failed
)

events_created_total = Counter(
    'ingestion_events_created_total',
    'Total number of exposure events created'
)

exposures_inserted_total = Counter(
    'ingestion_exposures_inserted_total',
    'Total number of new exposures inserted'
)

exposures_updated_total = Counter(
    'ingestion_exposures_updated_total',
    'Total number of exposures updated'
)

# Processing duration
processing_duration_seconds = Histogram(
    'ingestion_processing_duration_seconds',
    'Duration of file processing',
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]
)

# Current state gauges
exposures_open_total = Gauge(
    'exposures_open_total',
    'Total number of open exposures',
    ['office_id', 'exposure_class']
)

quarantined_files_total = Gauge(
    'quarantined_files_total',
    'Total number of quarantined files'
)

# Database metrics
db_events_total = Gauge(
    'db_exposure_events_total',
    'Total number of events in exposure_events table'
)

db_current_exposures_total = Gauge(
    'db_exposures_current_total',
    'Total number of rows in exposures_current table'
)


def update_exposure_gauges(session):
    """
    Update gauges for current exposure state.
    
    Should be called periodically (e.g., every 60 seconds).
    """
    from sqlalchemy import func
    from src.models.storage import ExposureCurrent, QuarantinedFile, ExposureEvent
    
    try:
        # Update open exposures by office and class
        results = session.query(
            ExposureCurrent.office_id,
            ExposureCurrent.exposure_class,
            func.count(ExposureCurrent.id)
        ).filter(
            ExposureCurrent.status == 'open'
        ).group_by(
            ExposureCurrent.office_id,
            ExposureCurrent.exposure_class
        ).all()
        
        # Reset gauges
        exposures_open_total._metrics.clear()
        
        for office_id, exposure_class, count in results:
            exposures_open_total.labels(
                office_id=office_id,
                exposure_class=exposure_class
            ).set(count)
        
        # Update quarantined files count
        quarantined_count = session.query(func.count(QuarantinedFile.id)).scalar()
        quarantined_files_total.set(quarantined_count)
        
        # Update total events count
        events_count = session.query(func.count(ExposureEvent.event_id)).scalar()
        db_events_total.set(events_count)
        
        # Update current exposures count
        current_count = session.query(func.count(ExposureCurrent.id)).scalar()
        db_current_exposures_total.set(current_count)
        
    except Exception as e:
        # Don't let metrics updates crash the service
        import structlog
        logger = structlog.get_logger()
        logger.error("failed_to_update_metrics", error=str(e))


def get_metrics_text() -> bytes:
    """Get Prometheus metrics in text format."""
    return generate_latest()


def get_metrics_content_type() -> str:
    """Get Prometheus metrics content type."""
    return CONTENT_TYPE_LATEST
