----------------------------------------------------------------------------------------
-- CTEM Key Risk Indicators (KRIs) and Analytics Queries
-- Based on ingestion/src/models/storage.py schema
-- Tables: exposure_events (append-only), exposures_current (latest state)
----------------------------------------------------------------------------------------

----------------------------------------------------------------------------------------
-- 1. New Exposures (Incidence)
-- Metric: count(event.action="exposure_opened")
-- Dimensions: event.action, office.id
----------------------------------------------------------------------------------------

-- Total new exposures by office
SELECT 
    office_id,
    COUNT(*) as new_exposure_count
FROM exposure_events
WHERE event_action = 'exposure_opened'
GROUP BY office_id
ORDER BY new_exposure_count DESC;

-- New exposures by office and action (with time window)
SELECT 
    office_id,
    event_action,
    COUNT(*) as exposure_count,
    COUNT(DISTINCT exposure_id) as unique_exposures,
    MIN(timestamp) as first_occurrence,
    MAX(timestamp) as last_occurrence
FROM exposure_events
WHERE event_action = 'exposure_opened'
    AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY office_id, event_action
ORDER BY exposure_count DESC;

-- New exposures trend (daily)
SELECT 
    DATE(timestamp) as detection_date,
    office_id,
    COUNT(*) as new_exposures,
    COUNT(DISTINCT exposure_id) as unique_exposures,
    AVG(severity) as avg_severity,
    SUM(risk_score) as total_risk_score
FROM exposure_events
WHERE event_action = 'exposure_opened'
    AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '90 days'
GROUP BY DATE(timestamp), office_id
ORDER BY detection_date DESC, office_id;


----------------------------------------------------------------------------------------
-- 2. Active Exposures (Prevalence)
-- Metric: countDistinct(exposure.id where exposure.status in ["open","observed"] 
--         and last_seen within window)
-- Dimensions: exposure.id, exposure.status, exposure.last_seen
----------------------------------------------------------------------------------------

-- Active exposures by status (within last 30 days)
SELECT 
    status,
    COUNT(DISTINCT exposure_id) as active_exposure_count,
    COUNT(DISTINCT office_id) as offices_affected,
    COUNT(DISTINCT asset_id) as assets_affected,
    AVG(severity) as avg_severity,
    SUM(risk_score) as total_risk_score
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY status
ORDER BY active_exposure_count DESC;

-- Active exposures by office
SELECT 
    office_id,
    office_name,
    COUNT(DISTINCT exposure_id) as active_exposures,
    COUNT(DISTINCT CASE WHEN status = 'open' THEN exposure_id END) as open_count,
    COUNT(DISTINCT CASE WHEN status = 'observed' THEN exposure_id END) as observed_count,
    COUNT(DISTINCT asset_id) as affected_assets,
    AVG(severity) as avg_severity,
    SUM(risk_score) as total_risk_score
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY office_id, office_name
ORDER BY active_exposures DESC;

-- Active exposures detail (recent observations)
SELECT 
    exposure_id,
    exposure_class,
    status,
    first_seen,
    last_seen,
    severity,
    risk_score,
    office_id,
    asset_id,
    asset_hostname,
    dst_ip,
    dst_port,
    protocol
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
ORDER BY last_seen DESC, severity DESC
LIMIT 100;


----------------------------------------------------------------------------------------
-- 3. Exposed Endpoint Rate
-- Metric: distinct(target.asset.id with active exposure) ÷ distinct(target.asset.id scanned)
-- Dimensions: target.asset.id, exposure.status
----------------------------------------------------------------------------------------

-- Overall exposed endpoint rate
WITH active_assets AS (
    SELECT COUNT(DISTINCT asset_id) as exposed_count
    FROM exposures_current
    WHERE status IN ('open', 'observed')
        AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
),
scanned_assets AS (
    SELECT COUNT(DISTINCT asset_id) as scanned_count
    FROM exposure_events
    WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '30 days'
)
SELECT 
    active_assets.exposed_count,
    scanned_assets.scanned_count,
    ROUND(100.0 * active_assets.exposed_count / scanned_assets.scanned_count, 2) as exposure_rate_pct
FROM active_assets, scanned_assets;

-- Exposed endpoint rate by office
WITH active_assets_per_office AS (
    SELECT 
        office_id,
        COUNT(DISTINCT asset_id) as exposed_count
    FROM exposures_current
    WHERE status IN ('open', 'observed')
        AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
    GROUP BY office_id
),
scanned_assets_per_office AS (
    SELECT 
        office_id,
        COUNT(DISTINCT asset_id) as scanned_count
    FROM exposure_events
    WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '30 days'
    GROUP BY office_id
)
SELECT 
    a.office_id,
    a.exposed_count,
    s.scanned_count,
    ROUND(100.0 * a.exposed_count / s.scanned_count, 2) as exposure_rate_pct
FROM active_assets_per_office a
JOIN scanned_assets_per_office s ON a.office_id = s.office_id
ORDER BY exposure_rate_pct DESC;

-- Exposed endpoints list with exposure details
SELECT DISTINCT
    ec.asset_id,
    ec.asset_hostname,
    ec.asset_ip,
    ec.asset_os,
    ec.asset_managed,
    ec.office_id,
    ec.office_name,
    COUNT(DISTINCT ec.exposure_id) as exposure_count,
    MAX(ec.severity) as max_severity,
    SUM(ec.risk_score) as total_risk_score,
    MIN(ec.first_seen) as first_exposure_seen,
    MAX(ec.last_seen) as last_exposure_seen
FROM exposures_current ec
WHERE ec.status IN ('open', 'observed')
    AND ec.last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY 
    ec.asset_id, ec.asset_hostname, ec.asset_ip, ec.asset_os, 
    ec.asset_managed, ec.office_id, ec.office_name
ORDER BY total_risk_score DESC;


----------------------------------------------------------------------------------------
-- 4. Distribution by Class
-- Metric: count by exposure.class (incidence + prevalence)
-- Dimensions: exposure.class
----------------------------------------------------------------------------------------

-- Incidence: new exposures by class
SELECT 
    exposure_class,
    COUNT(*) as new_exposure_count,
    COUNT(DISTINCT exposure_id) as unique_exposures,
    COUNT(DISTINCT office_id) as offices_affected,
    AVG(severity) as avg_severity,
    SUM(risk_score) as total_risk_score
FROM exposure_events
WHERE event_action = 'exposure_opened'
    AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY exposure_class
ORDER BY new_exposure_count DESC;

-- Prevalence: active exposures by class
SELECT 
    exposure_class,
    COUNT(DISTINCT exposure_id) as active_exposure_count,
    COUNT(DISTINCT office_id) as offices_affected,
    COUNT(DISTINCT asset_id) as assets_affected,
    AVG(severity) as avg_severity,
    SUM(risk_score) as total_risk_score
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY exposure_class
ORDER BY active_exposure_count DESC;

-- Combined: distribution by class (incidence + prevalence)
WITH incidence AS (
    SELECT 
        exposure_class,
        COUNT(*) as new_count,
        COUNT(DISTINCT exposure_id) as new_unique,
        AVG(severity) as new_avg_severity
    FROM exposure_events
    WHERE event_action = 'exposure_opened'
        AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '30 days'
    GROUP BY exposure_class
),
prevalence AS (
    SELECT 
        exposure_class,
        COUNT(DISTINCT exposure_id) as active_count,
        AVG(severity) as active_avg_severity
    FROM exposures_current
    WHERE status IN ('open', 'observed')
        AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
    GROUP BY exposure_class
)
SELECT 
    COALESCE(i.exposure_class, p.exposure_class) as exposure_class,
    COALESCE(i.new_count, 0) as new_exposures,
    COALESCE(i.new_unique, 0) as new_unique_exposures,
    COALESCE(p.active_count, 0) as active_exposures,
    COALESCE(i.new_avg_severity, 0) as avg_severity_new,
    COALESCE(p.active_avg_severity, 0) as avg_severity_active,
    COALESCE(i.new_count, 0) + COALESCE(p.active_count, 0) as total_count
FROM incidence i
FULL OUTER JOIN prevalence p ON i.exposure_class = p.exposure_class
ORDER BY total_count DESC;


----------------------------------------------------------------------------------------
-- 5. Top Risky Offices
-- Metric: sum(event.severity) or sum(event.risk_score) per office
-- Dimensions: event.severity, event.risk_score, office.id
----------------------------------------------------------------------------------------

-- Top risky offices by risk score (active exposures)
SELECT 
    office_id,
    office_name,
    office_region,
    COUNT(DISTINCT exposure_id) as active_exposures,
    COUNT(DISTINCT asset_id) as affected_assets,
    SUM(risk_score) as total_risk_score,
    AVG(risk_score) as avg_risk_score,
    MAX(risk_score) as max_risk_score,
    SUM(severity) as total_severity,
    AVG(severity) as avg_severity,
    -- Severity breakdown
    COUNT(CASE WHEN severity >= 90 THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity >= 70 AND severity < 90 THEN 1 END) as high_count,
    COUNT(CASE WHEN severity >= 40 AND severity < 70 THEN 1 END) as medium_count,
    COUNT(CASE WHEN severity < 40 THEN 1 END) as low_count
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY office_id, office_name, office_region
ORDER BY total_risk_score DESC
LIMIT 20;

-- Top risky offices by incident volume (new exposures)
SELECT 
    office_id,
    COUNT(*) as new_exposure_count,
    COUNT(DISTINCT exposure_id) as unique_exposures,
    SUM(severity) as total_severity,
    AVG(severity) as avg_severity,
    SUM(risk_score) as total_risk_score,
    AVG(risk_score) as avg_risk_score,
    -- Severity breakdown
    COUNT(CASE WHEN severity >= 90 THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity >= 70 AND severity < 90 THEN 1 END) as high_count,
    COUNT(CASE WHEN severity >= 40 AND severity < 70 THEN 1 END) as medium_count
FROM exposure_events
WHERE event_action = 'exposure_opened'
    AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY office_id
ORDER BY total_risk_score DESC
LIMIT 20;

-- Risk trend by office over time (weekly)
SELECT 
    DATE_TRUNC('week', timestamp) as week_start,
    office_id,
    COUNT(*) as new_exposures,
    SUM(severity) as total_severity,
    SUM(risk_score) as total_risk_score,
    AVG(risk_score) as avg_risk_score
FROM exposure_events
WHERE event_action = 'exposure_opened'
    AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '90 days'
GROUP BY DATE_TRUNC('week', timestamp), office_id
ORDER BY week_start DESC, total_risk_score DESC;


----------------------------------------------------------------------------------------
-- 6. Exposure Dwell Time (per exposure.id)
-- Metric: exposure.last_seen - exposure.first_seen (or open→resolved when available)
-- Dimensions: exposure.first_seen, exposure.last_seen
----------------------------------------------------------------------------------------

-- Dwell time for all exposures (hours and days)
SELECT 
    exposure_id,
    exposure_class,
    status,
    office_id,
    office_name,
    asset_id,
    asset_hostname,
    first_seen,
    last_seen,
    severity,
    risk_score,
    -- Calculate dwell time
    EXTRACT(EPOCH FROM (last_seen - first_seen)) / 3600.0 as dwell_time_hours,
    EXTRACT(EPOCH FROM (last_seen - first_seen)) / 86400.0 as dwell_time_days,
    -- Age since first seen
    EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - first_seen)) / 86400.0 as age_days
FROM exposures_current
WHERE first_seen IS NOT NULL
    AND last_seen IS NOT NULL
    AND last_seen >= first_seen
ORDER BY dwell_time_hours DESC
LIMIT 100;

-- Average dwell time by exposure class
SELECT 
    exposure_class,
    COUNT(*) as exposure_count,
    AVG(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 3600.0) as avg_dwell_hours,
    AVG(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 86400.0) as avg_dwell_days,
    PERCENTILE_CONT(0.5) WITHIN GROUP (
        ORDER BY EXTRACT(EPOCH FROM (last_seen - first_seen)) / 3600.0
    ) as median_dwell_hours,
    MIN(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 3600.0) as min_dwell_hours,
    MAX(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 3600.0) as max_dwell_hours
FROM exposures_current
WHERE first_seen IS NOT NULL
    AND last_seen IS NOT NULL
    AND last_seen >= first_seen
GROUP BY exposure_class
ORDER BY avg_dwell_hours DESC;

-- Dwell time by office
SELECT 
    office_id,
    office_name,
    COUNT(*) as exposure_count,
    AVG(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 86400.0) as avg_dwell_days,
    PERCENTILE_CONT(0.5) WITHIN GROUP (
        ORDER BY EXTRACT(EPOCH FROM (last_seen - first_seen)) / 86400.0
    ) as median_dwell_days,
    MAX(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 86400.0) as max_dwell_days
FROM exposures_current
WHERE first_seen IS NOT NULL
    AND last_seen IS NOT NULL
    AND last_seen >= first_seen
GROUP BY office_id, office_name
ORDER BY avg_dwell_days DESC;

-- Time to remediation (resolved exposures only) ** Not working
SELECT 
    exposure_id,
    exposure_class,
    office_id,
    office_name,
    first_seen,
    last_seen,
    severity,
    EXTRACT(EPOCH FROM (last_seen - first_seen)) / 86400.0 as time_to_remediation_days
FROM exposures_current
WHERE status IN ('resolved', 'suppressed')
    AND first_seen IS NOT NULL
    AND last_seen IS NOT NULL
    AND last_seen >= first_seen
ORDER BY time_to_remediation_days DESC
LIMIT 100;


----------------------------------------------------------------------------------------
-- 7. Total Risk-Time ("Exposure Hours")
-- Metric: sum(dwell_time_hours) per office/class/severity band
-- Dimensions: office.id, exposure.class, severity bands
----------------------------------------------------------------------------------------

-- Total exposure hours by office
SELECT 
    office_id,
    office_name,
    COUNT(*) as exposure_count,
    SUM(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 3600.0) as total_exposure_hours,
    SUM(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 86400.0) as total_exposure_days,
    AVG(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 3600.0) as avg_exposure_hours
FROM exposures_current
WHERE first_seen IS NOT NULL
    AND last_seen IS NOT NULL
    AND last_seen >= first_seen
GROUP BY office_id, office_name
ORDER BY total_exposure_hours DESC;

-- Total exposure hours by class
SELECT 
    exposure_class,
    COUNT(*) as exposure_count,
    SUM(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 3600.0) as total_exposure_hours,
    SUM(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 86400.0) as total_exposure_days,
    AVG(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 3600.0) as avg_exposure_hours
FROM exposures_current
WHERE first_seen IS NOT NULL
    AND last_seen IS NOT NULL
    AND last_seen >= first_seen
GROUP BY exposure_class
ORDER BY total_exposure_hours DESC;

-- Total exposure hours by severity band
SELECT 
    CASE 
        WHEN severity >= 90 THEN 'Critical (90-100)'
        WHEN severity >= 70 THEN 'High (70-89)'
        WHEN severity >= 40 THEN 'Medium (40-69)'
        ELSE 'Low (0-39)'
    END as severity_band,
    COUNT(*) as exposure_count,
    SUM(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 3600.0) as total_exposure_hours,
    SUM(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 86400.0) as total_exposure_days,
    AVG(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 3600.0) as avg_exposure_hours
FROM exposures_current
WHERE first_seen IS NOT NULL
    AND last_seen IS NOT NULL
    AND last_seen >= first_seen
GROUP BY 
    CASE 
        WHEN severity >= 90 THEN 'Critical (90-100)'
        WHEN severity >= 70 THEN 'High (70-89)'
        WHEN severity >= 40 THEN 'Medium (40-69)'
        ELSE 'Low (0-39)'
    END
ORDER BY total_exposure_hours DESC;

-- Comprehensive risk-time analysis (office × class × severity band)
SELECT 
    office_id,
    office_name,
    exposure_class,
    CASE 
        WHEN severity >= 90 THEN 'Critical'
        WHEN severity >= 70 THEN 'High'
        WHEN severity >= 40 THEN 'Medium'
        ELSE 'Low'
    END as severity_band,
    COUNT(*) as exposure_count,
    SUM(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 3600.0) as total_exposure_hours,
    AVG(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 3600.0) as avg_exposure_hours,
    -- Risk-weighted exposure hours
    SUM(
        EXTRACT(EPOCH FROM (last_seen - first_seen)) / 3600.0 * 
        COALESCE(risk_score, severity)
    ) as risk_weighted_exposure_hours
FROM exposures_current
WHERE first_seen IS NOT NULL
    AND last_seen IS NOT NULL
    AND last_seen >= first_seen
GROUP BY 
    office_id,
    office_name,
    exposure_class,
    CASE 
        WHEN severity >= 90 THEN 'Critical'
        WHEN severity >= 70 THEN 'High'
        WHEN severity >= 40 THEN 'Medium'
        ELSE 'Low'
    END
ORDER BY risk_weighted_exposure_hours DESC
LIMIT 50;


----------------------------------------------------------------------------------------
-- BONUS QUERIES
----------------------------------------------------------------------------------------

-- Top 10 unknown ports (from existing query)
SELECT DISTINCT
    dst_port, 
    COUNT(dst_port) as port_count
FROM exposures_current 
WHERE exposure_class = 'unknown_service_exposed'
    AND dst_port IS NOT NULL
GROUP BY dst_port 
ORDER BY port_count DESC 
LIMIT 10;

-- Exposure lifecycle analysis (open → resolved)
WITH exposure_lifecycle AS (
    SELECT 
        exposure_id,
        office_id,
        exposure_class,
        MIN(CASE WHEN event_action = 'exposure_opened' THEN timestamp END) as opened_at,
        MAX(CASE WHEN event_action = 'exposure_resolved' THEN timestamp END) as resolved_at,
        MAX(CASE WHEN event_action = 'exposure_suppressed' THEN timestamp END) as suppressed_at
    FROM exposure_events
    WHERE event_action IN ('exposure_opened', 'exposure_resolved', 'exposure_suppressed')
    GROUP BY exposure_id, office_id, exposure_class
)
SELECT 
    exposure_id,
    office_id,
    exposure_class,
    opened_at,
    COALESCE(resolved_at, suppressed_at) as closed_at,
    CASE 
        WHEN resolved_at IS NOT NULL THEN 'resolved'
        WHEN suppressed_at IS NOT NULL THEN 'suppressed'
        ELSE 'still_open'
    END as closure_type,
    -- Time to close (if closed)
    CASE 
        WHEN resolved_at IS NOT NULL THEN 
            EXTRACT(EPOCH FROM (resolved_at - opened_at)) / 86400.0
        WHEN suppressed_at IS NOT NULL THEN 
            EXTRACT(EPOCH FROM (suppressed_at - opened_at)) / 86400.0
    END as time_to_close_days
FROM exposure_lifecycle
ORDER BY opened_at DESC
LIMIT 100;

-- Asset risk profile (which assets have the most exposures)
SELECT 
    asset_id,
    asset_hostname,
    asset_ip,
    asset_os,
    office_id,
    office_name,
    COUNT(DISTINCT exposure_id) as total_exposures,
    COUNT(DISTINCT CASE WHEN status IN ('open', 'observed') THEN exposure_id END) as active_exposures,
    COUNT(DISTINCT exposure_class) as exposure_class_count,
    MAX(severity) as max_severity,
    SUM(risk_score) as total_risk_score,
    AVG(risk_score) as avg_risk_score
FROM exposures_current
GROUP BY 
    asset_id, asset_hostname, asset_ip, asset_os, 
    office_id, office_name
ORDER BY active_exposures DESC, total_risk_score DESC
LIMIT 50;
