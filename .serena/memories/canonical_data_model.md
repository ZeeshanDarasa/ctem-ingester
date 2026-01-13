# Canonical Data Model (src/models/canonical.py)

## Root Model: ExposureEventModel
Strict Pydantic v2 model with `ConfigDict(strict=True, extra="forbid")` to prevent schema drift.

### Required Top-Level Fields
- `schema_version`: str (e.g., "1.0.0")
- `@timestamp`: datetime (observation time)
- `event`: Event object
- `office`: Office object
- `scanner`: Scanner object
- `target`: Target object (contains asset)
- `exposure`: Exposure object

## Key Enums (Strict Validation)
- **EventKind**: alert, state, event
- **EventAction**: exposure_opened, exposure_observed, exposure_resolved, exposure_suppressed
- **ExposureClass**: http_content_leak, vcs_protocol_exposed, fileshare_exposed, remote_admin_exposed, db_exposed, container_api_exposed, debug_port_exposed, service_advertised_mdns, egress_tunnel_indicator, unknown_service_exposed
- **ExposureStatus**: open, observed, resolved, suppressed
- **Transport**: tcp, udp, icmp, other
- **NetworkDirection**: internal, inbound, outbound, unknown
- **ServiceAuth**: unknown, required, not_required
- **ServiceBindScope**: loopback_only, local_subnet, any, unknown
- **ResourceType**: http_path, smb_share, nfs_export, repo, api_endpoint, mdns_service, domain
- **DataClassification**: source_code, secrets, pii, credentials, internal_only, unknown

## Critical Validation Rules
1. **Severity bounds**: Field validator ensures `severity in [0, 100]`
2. **Confidence bounds**: Field validator ensures `confidence in [0, 1]`
3. **Timestamp logic**: Model validator ensures `last_seen >= first_seen`
4. **Status/action alignment**: Model validator ensures resolved status requires exposure_resolved action, suppressed requires exposure_suppressed
5. **Port requirement**: Model validator ensures TCP/UDP transports for port-based exposure classes must have dst.port
6. **Port range**: Field validator ensures `port in [0, 65535]`

## Minimal Valid Event
Minimum required fields for an "unknown open port" finding:
- schema_version, @timestamp
- event: {id, kind, category, type, action, severity}
- office: {id, name}
- scanner: {id, type}
- target.asset: {id}
- exposure: {id, class, status, vector{transport, protocol, dst{ip, port?}}}

## Field Aliases
`exposure.class` is aliased as `class_` in Python (reserved keyword) but serializes as "class" in JSON.
