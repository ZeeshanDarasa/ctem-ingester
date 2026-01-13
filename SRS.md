SRS: Exposure/Finding Canonicalization + Ingestion Module

1) Purpose

Build a Python ingestion module that accepts scan outputs (JSON/XML) from multiple scanners via n8n, normalizes them into one strict “Exposure Event” model, and writes to the DB with upsert so Metabase can generate consistent KRIs across offices.

2) Scope (in / out)

In scope
	•	Canonical Pydantic (v2) models matching your schema (strict enums, nullables, minimal required set).
	•	Transformer: JSON → model, XML → model (safe parsing).
	•	Persistence: SQLAlchemy-based storage (DuckDB now, swappable later) + upsert.
	•	Sanity/security/performance checks and tests.

Out of scope
	•	The scanning tools themselves, n8n workflow design, Metabase dashboards, auth/seed scripts (already covered by you).

⸻

3) Actors & Data Flow

Actors
	•	Scanners (nmap-like, SMB enum, HTTP probes, etc.)
	•	n8n workflow (orchestrator, transport)
	•	Ingestion service (this module)
	•	DB (DuckDB initially; future: Postgres, etc.)
	•	Metabase (read-only analytics)

Flow
	1.	Scanner produces raw JSON or XML.
	2.	n8n POSTs payload to ingestion endpoint or drops it to a queue/file watched by ingestion.
	3.	Ingestion:
	•	parse (XML safely),
	•	transform to canonical dict,
	•	validate via strict Pydantic models,
	•	compute dedupe_key + stable exposure.id (if missing),
	•	store:
	•	append-only events table (auditable history),
	•	current-state exposures table (upserted).

⸻

4) Data Model Requirements

4.1 Canonical Pydantic models (strict)

Requirement: The canonical model must:
	•	Enforce strict enums for:
	•	event.kind, event.action, exposure.class, exposure.status, vector.transport, vector.network_direction, service.auth, service.bind_scope, resource.type, data_class[].
	•	Reject unknown fields by default (extra="forbid") to avoid schema drift.  ￼
	•	Prefer strict type validation (strict=True) to avoid coercion surprises.  ￼

Minimal “starting point” for a valid finding
A finding event must be creatable for:
	•	Unknown open port (your most common baseline)
	•	Known exposure class (http leak, docker api, k8s api, etc.)

Minimum required fields (aligned to your schema):
	•	schema_version
	•	@timestamp
	•	event: {id, kind, category[], type[], action, severity}
	•	office: {id, name}
	•	scanner: {id, type}
	•	target.asset: {id}
	•	exposure: {id, class, status, vector{transport, protocol, dst{ip, port?}} }

Key invariants (sanity rules)
	•	severity in [0,100]
	•	confidence in [0,1]
	•	last_seen >= first_seen (if both provided)
	•	If exposure.status == resolved, then event.action must be exposure_resolved (and similarly for suppressed).
	•	vector.dst.port required for transport=tcp|udp when class indicates a port exposure (e.g., unknown_service_exposed).

Extensibility rule
	•	You may add new exposure subclasses later without breaking dashboards by:
	•	keeping exposure.class within the existing enum buckets,
	•	adding optional fields like exposure.subclass (string) for future specificity.

⸻

5) Storage Requirements (SQLAlchemy, no DB lock-in)

5.1 Database Initialization (auto-detection)

Requirement: The ingestion service must automatically detect and initialize database tables on first run.
	•	Auto-detection: Check if required tables exist using SQLAlchemy metadata inspection.
	•	Idempotent creation: Create tables only if they don't exist (CREATE TABLE IF NOT EXISTS semantics).
	•	Zero-config deployment: No manual database initialization scripts required.
	•	Safe for restarts: Re-running ingestion with existing tables is a no-op.

Implementation:
	•	check_tables_exist(): Uses sqlalchemy.inspect() to verify presence of required tables.
	•	ensure_database_initialized(): Creates tables via Base.metadata.create_all() if missing.
	•	Automatic invocation: Called transparently in get_db_session() context manager.

This enables true "drop and run" deployments where n8n can start calling the ingester immediately after container startup.

5.2 Tables (recommended)

A) exposure_events (append-only)
	•	Primary key: event_id
	•	Stores: timestamps, office_id, asset_id, exposure_id, class/status, port/ip/protocol, severity, plus raw_payload_json (sanitized) and evidence_hashes.
	•	Purpose: time series, audit, "what changed when?"

B) exposures_current (upserted "latest state")
	•	Unique key: (office_id, exposure_id) (or just exposure_id if globally unique in your org—don't assume).
	•	Fields: latest status, last_seen, first_seen, severity/risk_score, dst ip/port/protocol, plus stable dimensions for Metabase.

C) quarantined_files (error tracking)
	•	Primary key: id
	•	Stores: filename, error_type, error_message, error_details_json, scanner_type, office_id, quarantined_at
	•	Purpose: dead-letter queue for troubleshooting failed ingestions

This split keeps Metabase fast for "current exposure" dashboards while preserving history.

5.3 Upsert behavior

Requirement: The ingester must upsert into exposures_current:
	•	On conflict, update:
	•	last_seen, status, severity, risk_score, event_action, updated_at, and optional service/resource info if present.
	•	Never overwrite previously-known non-null values with null unless the new event explicitly indicates removal/reset.

Implementation guidance
	•	Use SQLAlchemy dialect upsert helpers where available (Postgres/SQLite explicitly support on_conflict_do_update).  ￼
	•	DuckDB supports INSERT … ON CONFLICT DO UPDATE semantics.  ￼

DuckDB concurrency constraint (important for your docker-compose reality)
	•	DuckDB is great for analytics, but typical deployments have single-writer semantics across processes (file lock for writes). Plan ingestion as one writer service (single container/replica) with optional internal batching/queueing.  ￼

Performance note
	•	Avoid row-by-row insert loops. Batch inserts/upserts in chunks (e.g., 200–2,000) per transaction. DuckDB docs warn that many individual INSERT statements are inefficient.  ￼

⸻

6) Transformer Requirements (JSON/XML → Canonical Model)

6.1 JSON transformer
	•	Accept dicts (already JSON-decoded) and raw JSON strings.
	•	Map scanner-specific keys → canonical keys using a registry:
	•	scanner_type -> mapping function
	•	Must produce canonical dict that passes Pydantic validation.

6.2 XML transformer (secure parsing)

Requirement: XML parsing must be safe against malicious payloads (XXE, entity expansion bombs).
	•	Use defusedxml as the parsing backend (drop-in hardened variants).  ￼
	•	Enforce size limits and max depth (practical DoS guard).

6.3 Dedupe and stable IDs

Requirement: Generate deterministic identifiers when scanners don’t provide them.
	•	event.id: UUIDv7/UUIDv4 per observation (unique).
	•	exposure.id: deterministic hash of stable fields, e.g.:
	•	office_id | asset_id | dst_ip | dst_port | protocol | exposure.class | resource.identifier?
	•	correlation.dedupe_key: hash of the fields you use to define “same finding”.

⸻

7) Security Requirements
	•	Data minimization: never store secrets / full HTTP bodies / SMB file listings. Store only:
	•	metadata (status code, server header, title),
	•	evidence_hash of sensitive snippets (as your schema suggests).
	•	Strict input validation: reject extra fields (forbid) and invalid enums/types (strict mode).  ￼
	•	Safe XML parsing: defusedxml only.  ￼
	•	SQL injection: all DB writes via SQLAlchemy bound parameters (no string concatenation).
	•	Least privilege: DB user used by ingestion has write access only to required tables; Metabase user is read-only.
	•	Operational hardening (DuckDB-specific if you ever accept user SQL): lock down configuration after setup (relevant if you let untrusted SQL run).  ￼

⸻

8) Reliability & Observability Requirements
	•	Idempotency: re-processing same event must not create duplicates in exposures_current.
	•	Auto-initialization: database tables are automatically created on first run (zero manual setup).
	•	Dead-letter handling: invalid payloads go to a quarantine log/table with validation errors (Pydantic error details are good).  ￼
	•	Metrics:
	•	ingestion rate, validation failures, upsert latency, batch sizes,
	•	number of "open" exposures per office, per class.

⸻

9) Testing Requirements (sanity, security, performance)

9.1 Unit tests (fast)
	•	Model validation:
	•	valid minimal unknown-port event passes,
	•	invalid enum values fail,
	•	extra keys fail (schema drift detector).
	•	Transformer:
	•	JSON mapping for each scanner type,
	•	XML parsing rejects unsafe constructs (XXE/entity expansion).
	•	Dedupe:
	•	same input → same exposure.id,
	•	different port/protocol → different exposure.id.

9.2 Integration tests (DB)

Run the same suite against:
	•	DuckDB (current)
	•	Postgres (future swap test)

Assertions:
	•	Upsert updates last_seen, not first_seen.
	•	Null-handling: existing non-null fields not wiped by missing optional fields.

9.3 Performance sanity
	•	Batch ingest 10k synthetic events:
	•	total time under defined budget,
	•	no excessive memory growth,
	•	stable upsert throughput.

⸻

Sanity Check on This SRS (does it hold water?)

✅ Consistency with your schema goals
	•	Strict enums + strict typing + forbid extras matches your “keep metrics consistent, prevent drift” requirement.  ￼
	•	Extensibility is handled by keeping exposure.class stable and allowing future detail in a secondary field (subclass) rather than expanding the enum every week.

✅ Testability

Every major requirement is testable:
	•	Validation outcomes (pass/fail)
	•	Deterministic ID generation
	•	Upsert semantics (before/after row state)
	•	XML security behavior

✅ Operational realism (DuckDB)

This SRS explicitly accounts for DuckDB’s write-lock/concurrency model: ingestion must be a single writer service (one container replica) with batching. If you scale ingestion horizontally later, you’ll want to swap the backing store or add a queue/aggregator.  ￼

✅ Security posture
	•	XML safety is addressed with defusedxml and the known insecurity of stdlib XML parsing is acknowledged.  ￼
	•	Data minimization aligns with your evidence-hash idea (good call: proves existence without storing secrets).

⚠️ Two subtle gaps to fix (so you don’t get bitten later)
	1.	Uniqueness key ambiguity
Your schema says exposure.id is “stable across observations,” but not whether it’s stable across offices vs global. The SRS resolves this by recommending (office_id, exposure_id) uniqueness for exposures_current. That’s the safer default.
	2.	Null-overwrite rule during upsert
Without an explicit rule, upserts often overwrite populated columns with null when later scanners omit optional fields. The SRS includes “don’t clobber non-null with null unless explicit,” which is crucial for multi-scanner ingestion.