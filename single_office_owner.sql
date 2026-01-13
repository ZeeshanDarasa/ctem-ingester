----------------------------------------------------------------------------------------
-- CTEM Single Office Analytics Queries
-- Tailored for deployments scanning a single office environment
-- Based on ingestion/src/models/storage.py schema
-- Tables: exposure_events (append-only), exposures_current (latest state)
----------------------------------------------------------------------------------------

----------------------------------------------------------------------------------------
-- 1. OFFICE RISK OVERVIEW
-- High-level risk metrics and health indicators for the office
----------------------------------------------------------------------------------------

-- Overall office risk score and summary
SELECT 
    office_id,
    office_name,
    office_region,
    -- Active exposure counts
    COUNT(DISTINCT exposure_id) as total_active_exposures,
    COUNT(DISTINCT asset_id) as exposed_assets,
    -- Severity breakdown
    COUNT(CASE WHEN severity >= 90 THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity >= 70 AND severity < 90 THEN 1 END) as high_count,
    COUNT(CASE WHEN severity >= 40 AND severity < 70 THEN 1 END) as medium_count,
    COUNT(CASE WHEN severity < 40 THEN 1 END) as low_count,
    -- Risk scores
    SUM(risk_score) as total_risk_score,
    AVG(risk_score) as avg_risk_score,
    MAX(risk_score) as max_risk_score,
    AVG(severity) as avg_severity,
    MAX(severity) as max_severity
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY office_id, office_name, office_region;

-- Office risk trend over time (daily)
SELECT 
    CAST(timestamp AS DATE) as date,
    COUNT(*) as new_exposures,
    COUNT(DISTINCT exposure_id) as unique_exposures,
    COUNT(DISTINCT asset_id) as affected_assets,
    AVG(severity) as avg_severity,
    SUM(risk_score) as daily_risk_score,
    -- Severity breakdown
    COUNT(CASE WHEN severity >= 90 THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity >= 70 AND severity < 90 THEN 1 END) as high_count,
    COUNT(CASE WHEN severity >= 40 AND severity < 70 THEN 1 END) as medium_count
FROM exposure_events
WHERE event_action = 'exposure_opened'
    AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '90 days'
GROUP BY CAST(timestamp AS DATE)
ORDER BY date DESC;

-- Office risk trend over time (weekly)
SELECT 
    DATE_TRUNC('week', timestamp) as week_start,
    COUNT(*) as new_exposures,
    COUNT(DISTINCT exposure_id) as unique_exposures,
    COUNT(DISTINCT asset_id) as affected_assets,
    AVG(severity) as avg_severity,
    SUM(risk_score) as weekly_risk_score,
    -- Severity breakdown
    COUNT(CASE WHEN severity >= 90 THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity >= 70 AND severity < 90 THEN 1 END) as high_count
FROM exposure_events
WHERE event_action = 'exposure_opened'
    AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '180 days'
GROUP BY DATE_TRUNC('week', timestamp)
ORDER BY week_start DESC;


----------------------------------------------------------------------------------------
-- 2. MOST VULNERABLE MACHINES
-- Asset risk ranking and detailed vulnerability profiles
----------------------------------------------------------------------------------------

-- Top 20 most vulnerable machines by risk score
SELECT 
    asset_id,
    asset_hostname,
    asset_ip,
    asset_os,
    asset_managed,
    COUNT(DISTINCT exposure_id) as total_exposures,
    COUNT(DISTINCT CASE WHEN status IN ('open', 'observed') THEN exposure_id END) as active_exposures,
    COUNT(DISTINCT exposure_class) as exposure_class_count,
    -- Severity breakdown
    COUNT(CASE WHEN severity >= 90 THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity >= 70 AND severity < 90 THEN 1 END) as high_count,
    COUNT(CASE WHEN severity >= 40 AND severity < 70 THEN 1 END) as medium_count,
    -- Risk metrics
    MAX(severity) as max_severity,
    AVG(severity) as avg_severity,
    SUM(risk_score) as total_risk_score,
    AVG(risk_score) as avg_risk_score,
    -- Time metrics
    MIN(first_seen) as first_exposure_date,
    MAX(last_seen) as last_exposure_date
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY 
    asset_id, asset_hostname, asset_ip, asset_os, asset_managed
ORDER BY total_risk_score DESC
LIMIT 20;

-- Most vulnerable machines by exposure count
SELECT 
    asset_id,
    asset_hostname,
    asset_ip,
    asset_os,
    COUNT(DISTINCT exposure_id) as active_exposures,
    -- Top exposure classes for this asset
    STRING_AGG(DISTINCT exposure_class, ', ') as exposure_classes,
    -- Risk metrics
    SUM(risk_score) as total_risk_score,
    MAX(severity) as max_severity,
    AVG(severity) as avg_severity,
    -- Severity breakdown
    COUNT(CASE WHEN severity >= 90 THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity >= 70 AND severity < 90 THEN 1 END) as high_count
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY asset_id, asset_hostname, asset_ip, asset_os
ORDER BY active_exposures DESC
LIMIT 20;

-- Detailed vulnerability profile for a specific machine (replace 'ASSET_ID' with actual ID)
-- SELECT 
--     exposure_id,
--     exposure_class,
--     status,
--     severity,
--     risk_score,
--     dst_ip,
--     dst_port,
--     protocol,
--     service_name,
--     service_product,
--     service_version,
--     first_seen,
--     last_seen,
--     EXTRACT(EPOCH FROM (last_seen - first_seen)) / 86400.0 as dwell_time_days
-- FROM exposures_current
-- WHERE asset_id = 'ASSET_ID'
--     AND status IN ('open', 'observed')
-- ORDER BY severity DESC, risk_score DESC;


----------------------------------------------------------------------------------------
-- 3. MOST COMMONLY EXPOSED PORTS
-- Port-level exposure analysis for identifying attack surface
----------------------------------------------------------------------------------------

-- Top 20 most commonly exposed ports with risk metrics
SELECT 
    dst_port,
    COUNT(DISTINCT exposure_id) as exposure_count,
    COUNT(DISTINCT asset_id) as affected_assets,
    -- Protocol breakdown
    STRING_AGG(DISTINCT protocol, ', ') as protocols,
    STRING_AGG(DISTINCT transport, ', ') as transports,
    -- Risk metrics
    AVG(severity) as avg_severity,
    MAX(severity) as max_severity,
    SUM(risk_score) as total_risk_score,
    AVG(risk_score) as avg_risk_score,
    -- Severity breakdown
    COUNT(CASE WHEN severity >= 90 THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity >= 70 AND severity < 90 THEN 1 END) as high_count,
    COUNT(CASE WHEN severity >= 40 AND severity < 70 THEN 1 END) as medium_count,
    -- Services on this port
    COUNT(DISTINCT service_name) as unique_services,
    STRING_AGG(DISTINCT service_name, ', ') as service_names
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
    AND dst_port IS NOT NULL
GROUP BY dst_port
ORDER BY exposure_count DESC, total_risk_score DESC
LIMIT 20;

-- Top high-risk ports (critical/high severity only)
SELECT 
    dst_port,
    COUNT(DISTINCT exposure_id) as exposure_count,
    COUNT(DISTINCT asset_id) as affected_assets,
    STRING_AGG(DISTINCT service_name, ', ') as services,
    AVG(severity) as avg_severity,
    SUM(risk_score) as total_risk_score,
    -- Severity breakdown
    COUNT(CASE WHEN severity >= 90 THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity >= 70 AND severity < 90 THEN 1 END) as high_count
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
    AND dst_port IS NOT NULL
    AND severity >= 70  -- High and Critical only
GROUP BY dst_port
ORDER BY total_risk_score DESC, critical_count DESC
LIMIT 20;

-- Port exposure details (which assets expose which ports)
SELECT 
    dst_port,
    protocol,
    asset_id,
    asset_hostname,
    asset_ip,
    exposure_class,
    service_name,
    service_product,
    service_version,
    severity,
    risk_score,
    first_seen,
    last_seen
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
    AND dst_port IS NOT NULL
ORDER BY dst_port, severity DESC;

-- Unknown ports (not in common port list)
SELECT 
    dst_port,
    COUNT(DISTINCT exposure_id) as exposure_count,
    COUNT(DISTINCT asset_id) as affected_assets,
    AVG(severity) as avg_severity,
    SUM(risk_score) as total_risk_score,
    STRING_AGG(DISTINCT service_name, ', ') as detected_services
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
    AND dst_port IS NOT NULL
    AND exposure_class = 'unknown_service_exposed'
GROUP BY dst_port
ORDER BY exposure_count DESC, total_risk_score DESC;


----------------------------------------------------------------------------------------
-- 4. EXPOSURE CLASS DISTRIBUTION
-- What types of exposures are most common
----------------------------------------------------------------------------------------

-- Active exposures by class (current state)
SELECT 
    exposure_class,
    COUNT(DISTINCT exposure_id) as active_exposure_count,
    COUNT(DISTINCT asset_id) as assets_affected,
    -- Risk metrics
    AVG(severity) as avg_severity,
    MAX(severity) as max_severity,
    SUM(risk_score) as total_risk_score,
    AVG(risk_score) as avg_risk_score,
    -- Severity breakdown
    COUNT(CASE WHEN severity >= 90 THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity >= 70 AND severity < 90 THEN 1 END) as high_count,
    COUNT(CASE WHEN severity >= 40 AND severity < 70 THEN 1 END) as medium_count
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY exposure_class
ORDER BY total_risk_score DESC, active_exposure_count DESC;

-- New exposures by class (incidence trend)
SELECT 
    exposure_class,
    COUNT(*) as new_exposure_count,
    COUNT(DISTINCT exposure_id) as unique_exposures,
    COUNT(DISTINCT asset_id) as assets_affected,
    AVG(severity) as avg_severity,
    SUM(risk_score) as total_risk_score,
    -- Severity breakdown
    COUNT(CASE WHEN severity >= 90 THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity >= 70 AND severity < 90 THEN 1 END) as high_count
FROM exposure_events
WHERE event_action = 'exposure_opened'
    AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY exposure_class
ORDER BY total_risk_score DESC, new_exposure_count DESC;

-- Exposure class trend over time (weekly)
SELECT 
    DATE_TRUNC('week', timestamp) as week_start,
    exposure_class,
    COUNT(*) as new_exposures,
    AVG(severity) as avg_severity,
    SUM(risk_score) as weekly_risk_score
FROM exposure_events
WHERE event_action = 'exposure_opened'
    AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '90 days'
GROUP BY DATE_TRUNC('week', timestamp), exposure_class
ORDER BY week_start DESC, weekly_risk_score DESC;


----------------------------------------------------------------------------------------
-- 5. SERVICE INVENTORY & RISK
-- Exposed services and their risk profiles
----------------------------------------------------------------------------------------

-- Exposed services summary
SELECT 
    service_name,
    service_product,
    COUNT(DISTINCT exposure_id) as exposure_count,
    COUNT(DISTINCT asset_id) as assets_running_service,
    COUNT(DISTINCT dst_port) as ports_used,
    -- Version diversity
    COUNT(DISTINCT service_version) as version_count,
    STRING_AGG(DISTINCT service_version, ', ') as versions,
    -- Risk metrics
    AVG(severity) as avg_severity,
    MAX(severity) as max_severity,
    SUM(risk_score) as total_risk_score,
    -- Severity breakdown
    COUNT(CASE WHEN severity >= 90 THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity >= 70 AND severity < 90 THEN 1 END) as high_count
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
    AND service_name IS NOT NULL
GROUP BY service_name, service_product
ORDER BY total_risk_score DESC, exposure_count DESC;

-- Detailed service exposure inventory
SELECT 
    service_name,
    service_product,
    service_version,
    dst_port,
    protocol,
    asset_id,
    asset_hostname,
    asset_ip,
    exposure_class,
    severity,
    risk_score,
    service_auth,
    service_tls,
    first_seen,
    last_seen
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
    AND service_name IS NOT NULL
ORDER BY severity DESC, risk_score DESC;

-- Services without authentication
SELECT 
    service_name,
    service_product,
    dst_port,
    COUNT(DISTINCT asset_id) as exposed_assets,
    COUNT(DISTINCT exposure_id) as exposure_count,
    AVG(severity) as avg_severity,
    SUM(risk_score) as total_risk_score
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
    AND service_auth = 'not_required'
GROUP BY service_name, service_product, dst_port
ORDER BY total_risk_score DESC;

-- Services without TLS/encryption
SELECT 
    service_name,
    service_product,
    dst_port,
    COUNT(DISTINCT asset_id) as exposed_assets,
    COUNT(DISTINCT exposure_id) as exposure_count,
    AVG(severity) as avg_severity,
    SUM(risk_score) as total_risk_score
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
    AND service_tls = FALSE
GROUP BY service_name, service_product, dst_port
ORDER BY total_risk_score DESC;


----------------------------------------------------------------------------------------
-- 6. ASSET INVENTORY & COVERAGE
-- Understanding the scanned asset base
----------------------------------------------------------------------------------------

-- Total asset inventory summary
WITH scanned_assets AS (
    SELECT DISTINCT asset_id, asset_hostname, asset_ip, asset_os, asset_managed
    FROM exposure_events
    WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '30 days'
),
exposed_assets AS (
    SELECT DISTINCT asset_id
    FROM exposures_current
    WHERE status IN ('open', 'observed')
        AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
)
SELECT 
    COUNT(DISTINCT sa.asset_id) as total_scanned_assets,
    COUNT(DISTINCT ea.asset_id) as exposed_assets,
    ROUND(100.0 * COUNT(DISTINCT ea.asset_id) / COUNT(DISTINCT sa.asset_id), 2) as exposure_rate_pct,
    COUNT(DISTINCT CASE WHEN sa.asset_managed = TRUE THEN sa.asset_id END) as managed_assets,
    COUNT(DISTINCT CASE WHEN sa.asset_managed = FALSE THEN sa.asset_id END) as unmanaged_assets
FROM scanned_assets sa
LEFT JOIN exposed_assets ea ON sa.asset_id = ea.asset_id;

-- Asset inventory with exposure status
SELECT 
    sa.asset_id,
    sa.asset_hostname,
    sa.asset_ip,
    sa.asset_os,
    sa.asset_managed,
    CASE WHEN ea.asset_id IS NOT NULL THEN 'Exposed' ELSE 'Clean' END as status,
    COALESCE(ea.exposure_count, 0) as exposure_count,
    COALESCE(ea.total_risk_score, 0) as total_risk_score,
    COALESCE(ea.max_severity, 0) as max_severity
FROM (
    SELECT DISTINCT asset_id, asset_hostname, asset_ip, asset_os, asset_managed
    FROM exposure_events
    WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '30 days'
) sa
LEFT JOIN (
    SELECT 
        asset_id,
        COUNT(DISTINCT exposure_id) as exposure_count,
        SUM(risk_score) as total_risk_score,
        MAX(severity) as max_severity
    FROM exposures_current
    WHERE status IN ('open', 'observed')
        AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
    GROUP BY asset_id
) ea ON sa.asset_id = ea.asset_id
ORDER BY ea.total_risk_score DESC NULLS LAST, ea.exposure_count DESC NULLS LAST;

-- Asset exposure by OS type
SELECT 
    asset_os,
    COUNT(DISTINCT asset_id) as asset_count,
    COUNT(DISTINCT CASE WHEN status IN ('open', 'observed') THEN asset_id END) as exposed_assets,
    COUNT(DISTINCT exposure_id) as total_exposures,
    AVG(severity) as avg_severity,
    SUM(risk_score) as total_risk_score
FROM exposures_current
WHERE last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY asset_os
ORDER BY total_risk_score DESC;


----------------------------------------------------------------------------------------
-- 7. CRITICAL & HIGH SEVERITY EXPOSURES
-- Urgent items requiring immediate attention
----------------------------------------------------------------------------------------

-- Critical severity exposures (90+)
SELECT 
    exposure_id,
    exposure_class,
    asset_id,
    asset_hostname,
    asset_ip,
    dst_port,
    protocol,
    service_name,
    service_product,
    severity,
    risk_score,
    first_seen,
    last_seen,
    EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - first_seen)) / 86400.0 as age_days,
    EXTRACT(EPOCH FROM (last_seen - first_seen)) / 86400.0 as dwell_time_days
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
    AND severity >= 90
ORDER BY severity DESC, risk_score DESC, age_days DESC;

-- High severity exposures (70-89)
SELECT 
    exposure_id,
    exposure_class,
    asset_id,
    asset_hostname,
    asset_ip,
    dst_port,
    protocol,
    service_name,
    severity,
    risk_score,
    first_seen,
    last_seen,
    EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - first_seen)) / 86400.0 as age_days
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
    AND severity >= 70 
    AND severity < 90
ORDER BY severity DESC, risk_score DESC, age_days DESC;

-- Oldest unresolved critical/high exposures (stale vulnerabilities)
SELECT 
    exposure_id,
    exposure_class,
    asset_id,
    asset_hostname,
    asset_ip,
    dst_port,
    service_name,
    severity,
    risk_score,
    first_seen,
    last_seen,
    EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - first_seen)) / 86400.0 as age_days,
    EXTRACT(EPOCH FROM (last_seen - first_seen)) / 86400.0 as dwell_time_days
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND severity >= 70
ORDER BY first_seen ASC
LIMIT 50;


----------------------------------------------------------------------------------------
-- 8. RECENT ACTIVITY & CHANGES
-- What's new and what's changed recently
----------------------------------------------------------------------------------------

-- Recently discovered exposures (last 7 days)
SELECT 
    exposure_id,
    exposure_class,
    asset_id,
    asset_hostname,
    asset_ip,
    dst_port,
    protocol,
    service_name,
    severity,
    risk_score,
    first_seen,
    last_seen
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND first_seen >= CURRENT_TIMESTAMP - INTERVAL '7 days'
ORDER BY first_seen DESC, severity DESC;

-- Recently resolved exposures (last 30 days)
SELECT 
    exposure_id,
    exposure_class,
    asset_id,
    asset_hostname,
    dst_port,
    severity,
    first_seen,
    last_seen,
    EXTRACT(EPOCH FROM (last_seen - first_seen)) / 86400.0 as time_to_remediation_days
FROM exposures_current
WHERE status IN ('resolved', 'suppressed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
ORDER BY last_seen DESC;

-- Daily exposure activity (new vs resolved)
SELECT 
    CAST(timestamp AS DATE) as date,
    event_action,
    COUNT(*) as event_count,
    COUNT(DISTINCT exposure_id) as unique_exposures,
    COUNT(DISTINCT asset_id) as affected_assets,
    AVG(severity) as avg_severity
FROM exposure_events
WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '30 days'
    AND event_action IN ('exposure_opened', 'exposure_resolved', 'exposure_suppressed')
GROUP BY CAST(timestamp AS DATE), event_action
ORDER BY date DESC, event_action;


----------------------------------------------------------------------------------------
-- 9. DWELL TIME & TIME TO REMEDIATION
-- How long exposures persist in the environment
----------------------------------------------------------------------------------------

-- Average dwell time by exposure class
SELECT 
    exposure_class,
    COUNT(*) as exposure_count,
    AVG(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 86400.0) as avg_dwell_days,
    PERCENTILE_CONT(0.5) WITHIN GROUP (
        ORDER BY EXTRACT(EPOCH FROM (last_seen - first_seen)) / 86400.0
    ) as median_dwell_days,
    MIN(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 86400.0) as min_dwell_days,
    MAX(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 86400.0) as max_dwell_days,
    AVG(severity) as avg_severity,
    SUM(risk_score) as total_risk_score
FROM exposures_current
WHERE first_seen IS NOT NULL
    AND last_seen IS NOT NULL
    AND last_seen >= first_seen
    AND status IN ('open', 'observed')
GROUP BY exposure_class
ORDER BY avg_dwell_days DESC;

-- Longest dwelling exposures (current)
SELECT 
    exposure_id,
    exposure_class,
    asset_id,
    asset_hostname,
    dst_port,
    severity,
    risk_score,
    first_seen,
    last_seen,
    EXTRACT(EPOCH FROM (last_seen - first_seen)) / 86400.0 as dwell_time_days,
    EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - first_seen)) / 86400.0 as age_days
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND first_seen IS NOT NULL
    AND last_seen IS NOT NULL
ORDER BY dwell_time_days DESC
LIMIT 50;

-- Total risk-time (exposure hours) by severity band
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
    AVG(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 3600.0) as avg_exposure_hours,
    -- Risk-weighted exposure time
    SUM(
        EXTRACT(EPOCH FROM (last_seen - first_seen)) / 3600.0 * 
        COALESCE(risk_score, severity)
    ) as risk_weighted_exposure_hours
FROM exposures_current
WHERE first_seen IS NOT NULL
    AND last_seen IS NOT NULL
    AND last_seen >= first_seen
    AND status IN ('open', 'observed')
GROUP BY 
    CASE 
        WHEN severity >= 90 THEN 'Critical (90-100)'
        WHEN severity >= 70 THEN 'High (70-89)'
        WHEN severity >= 40 THEN 'Medium (40-69)'
        ELSE 'Low (0-39)'
    END
ORDER BY risk_weighted_exposure_hours DESC;


----------------------------------------------------------------------------------------
-- 10. NETWORK EXPOSURE ANALYSIS
-- Understanding network-level attack surface
----------------------------------------------------------------------------------------

-- Exposures by network direction
SELECT 
    network_direction,
    COUNT(DISTINCT exposure_id) as exposure_count,
    COUNT(DISTINCT asset_id) as affected_assets,
    AVG(severity) as avg_severity,
    SUM(risk_score) as total_risk_score,
    -- Severity breakdown
    COUNT(CASE WHEN severity >= 90 THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity >= 70 AND severity < 90 THEN 1 END) as high_count
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY network_direction
ORDER BY total_risk_score DESC;

-- Exposures by transport protocol
SELECT 
    transport,
    protocol,
    COUNT(DISTINCT exposure_id) as exposure_count,
    COUNT(DISTINCT asset_id) as affected_assets,
    COUNT(DISTINCT dst_port) as unique_ports,
    AVG(severity) as avg_severity,
    SUM(risk_score) as total_risk_score
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY transport, protocol
ORDER BY total_risk_score DESC, exposure_count DESC;

-- Public-facing exposures (inbound or unknown direction)
SELECT 
    exposure_id,
    exposure_class,
    asset_id,
    asset_hostname,
    dst_ip,
    dst_port,
    protocol,
    network_direction,
    service_name,
    severity,
    risk_score,
    first_seen,
    last_seen
FROM exposures_current
WHERE status IN ('open', 'observed')
    AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
    AND network_direction IN ('inbound', 'unknown')
ORDER BY severity DESC, risk_score DESC;


----------------------------------------------------------------------------------------
-- BONUS: EXECUTIVE SUMMARY QUERY
-- Single query for high-level dashboard
----------------------------------------------------------------------------------------

-- Comprehensive office health summary
WITH severity_counts AS (
    SELECT 
        COUNT(DISTINCT CASE WHEN severity >= 90 THEN exposure_id END) as critical,
        COUNT(DISTINCT CASE WHEN severity >= 70 AND severity < 90 THEN exposure_id END) as high,
        COUNT(DISTINCT CASE WHEN severity >= 40 AND severity < 70 THEN exposure_id END) as medium,
        COUNT(DISTINCT CASE WHEN severity < 40 THEN exposure_id END) as low,
        COUNT(DISTINCT exposure_id) as total_exposures,
        COUNT(DISTINCT asset_id) as exposed_assets,
        SUM(risk_score) as total_risk_score
    FROM exposures_current
    WHERE status IN ('open', 'observed')
        AND last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 days'
),
recent_activity AS (
    SELECT 
        COUNT(DISTINCT CASE WHEN event_action = 'exposure_opened' AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '7 days' THEN exposure_id END) as new_last_7d,
        COUNT(DISTINCT CASE WHEN event_action = 'exposure_resolved' AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '7 days' THEN exposure_id END) as resolved_last_7d
    FROM exposure_events
),
scanned_assets AS (
    SELECT COUNT(DISTINCT asset_id) as total_scanned
    FROM exposure_events
    WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '30 days'
)
SELECT 
    -- Current state
    sc.total_exposures,
    sc.exposed_assets,
    sa.total_scanned as total_scanned_assets,
    ROUND(100.0 * sc.exposed_assets / sa.total_scanned, 2) as exposure_rate_pct,
    -- Risk score
    sc.total_risk_score,
    ROUND(sc.total_risk_score / sc.total_exposures, 2) as avg_risk_per_exposure,
    -- Severity breakdown
    sc.critical,
    sc.high,
    sc.medium,
    sc.low,
    -- Recent activity
    ra.new_last_7d,
    ra.resolved_last_7d,
    ra.new_last_7d - ra.resolved_last_7d as net_change_7d
FROM severity_counts sc, recent_activity ra, scanned_assets sa;
