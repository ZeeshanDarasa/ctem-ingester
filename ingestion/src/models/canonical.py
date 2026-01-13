"""
Canonical Pydantic v2 models for Exposure Events.
Implements strict validation matching the proposed schema.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator
from typing_extensions import Self


# Enums for strict validation
class EventKind(str, Enum):
    ALERT = "alert"
    STATE = "state"
    EVENT = "event"


class EventAction(str, Enum):
    EXPOSURE_OPENED = "exposure_opened"
    EXPOSURE_OBSERVED = "exposure_observed"
    EXPOSURE_RESOLVED = "exposure_resolved"
    EXPOSURE_SUPPRESSED = "exposure_suppressed"


class ExposureClass(str, Enum):
    HTTP_CONTENT_LEAK = "http_content_leak"
    VCS_PROTOCOL_EXPOSED = "vcs_protocol_exposed"
    FILESHARE_EXPOSED = "fileshare_exposed"
    REMOTE_ADMIN_EXPOSED = "remote_admin_exposed"
    DB_EXPOSED = "db_exposed"
    CONTAINER_API_EXPOSED = "container_api_exposed"
    DEBUG_PORT_EXPOSED = "debug_port_exposed"
    SERVICE_ADVERTISED_MDNS = "service_advertised_mdns"
    EGRESS_TUNNEL_INDICATOR = "egress_tunnel_indicator"
    UNKNOWN_SERVICE_EXPOSED = "unknown_service_exposed"


class ExposureStatus(str, Enum):
    OPEN = "open"
    OBSERVED = "observed"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class Transport(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"


class NetworkDirection(str, Enum):
    INTERNAL = "internal"
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    UNKNOWN = "unknown"


class ServiceAuth(str, Enum):
    UNKNOWN = "unknown"
    REQUIRED = "required"
    NOT_REQUIRED = "not_required"


class ServiceBindScope(str, Enum):
    LOOPBACK_ONLY = "loopback_only"
    LOCAL_SUBNET = "local_subnet"
    ANY = "any"
    UNKNOWN = "unknown"


class ResourceType(str, Enum):
    HTTP_PATH = "http_path"
    SMB_SHARE = "smb_share"
    NFS_EXPORT = "nfs_export"
    REPO = "repo"
    API_ENDPOINT = "api_endpoint"
    MDNS_SERVICE = "mdns_service"
    DOMAIN = "domain"


class DataClassification(str, Enum):
    SOURCE_CODE = "source_code"
    SECRETS = "secrets"
    PII = "pii"
    CREDENTIALS = "credentials"
    INTERNAL_ONLY = "internal_only"
    UNKNOWN = "unknown"


class ProbeResult(str, Enum):
    SUCCESS = "success"
    FAIL = "fail"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"


# Nested Models
class EventCorrelation(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    scan_run_id: Optional[str] = None
    scan_policy_id: Optional[str] = None
    dedupe_key: Optional[str] = None


class Event(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    id: str
    kind: EventKind
    category: List[str]
    type: List[str]
    action: EventAction
    severity: int = Field(ge=0, le=100)
    
    created: Optional[datetime] = None
    ingested: Optional[datetime] = None
    reason: Optional[str] = None
    risk_score: Optional[float] = Field(default=None, ge=0, le=100)
    correlation: Optional[EventCorrelation] = None
    
    @field_validator('severity')
    @classmethod
    def validate_severity(cls, v: int) -> int:
        if not 0 <= v <= 100:
            raise ValueError('severity must be between 0 and 100')
        return v
    
    @field_validator('risk_score')
    @classmethod
    def validate_risk_score(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and not 0 <= v <= 100:
            raise ValueError('risk_score must be between 0 and 100')
        return v


class Office(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    id: str
    name: str
    region: Optional[str] = None
    timezone: Optional[str] = None
    network_zone: Optional[str] = None
    ssid: Optional[str] = None
    vlan: Optional[str] = None
    subnet: Optional[str] = None


class Scanner(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    id: str
    type: str
    version: Optional[str] = None
    ip: Optional[str] = None
    hostname: Optional[str] = None


class Asset(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    id: str
    hostname: Optional[str] = None
    ip: Optional[List[str]] = None
    mac: Optional[str] = None
    os: Optional[str] = None
    device_type: Optional[str] = None
    managed: Optional[bool] = None


class Owner(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    user_id: Optional[str] = None
    email: Optional[str] = None
    team: Optional[str] = None


class Target(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    asset: Asset
    owner: Optional[Owner] = None


class VectorSource(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    ip: Optional[str] = None


class VectorDestination(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    ip: Optional[str] = None
    port: Optional[int] = Field(default=None, ge=0, le=65535)
    
    @field_validator('port')
    @classmethod
    def validate_port(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and not 0 <= v <= 65535:
            raise ValueError('port must be between 0 and 65535')
        return v


class Vector(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    transport: Transport
    protocol: str
    src: Optional[VectorSource] = None
    dst: Optional[VectorDestination] = None
    network_direction: Optional[NetworkDirection] = None
    community_id: Optional[str] = None


class Service(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    tls: Optional[bool] = None
    auth: Optional[ServiceAuth] = None
    bind_scope: Optional[ServiceBindScope] = None


class Resource(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    type: Optional[ResourceType] = None
    identifier: Optional[str] = None
    evidence_hash: Optional[str] = None


class Exposure(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    id: str
    class_: ExposureClass = Field(alias="class")
    status: ExposureStatus
    vector: Vector
    service: Optional[Service] = None
    resource: Optional[Resource] = None
    data_class: Optional[List[DataClassification]] = None
    confidence: Optional[float] = Field(default=None, ge=0, le=1)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    
    @field_validator('confidence')
    @classmethod
    def validate_confidence(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and not 0 <= v <= 1:
            raise ValueError('confidence must be between 0 and 1')
        return v
    
    @model_validator(mode='after')
    def validate_timestamps(self) -> Self:
        if self.first_seen and self.last_seen:
            if self.last_seen < self.first_seen:
                raise ValueError('last_seen must be >= first_seen')
        return self
    
    @model_validator(mode='after')
    def validate_port_requirement(self) -> Self:
        # Port required for tcp/udp when class indicates port exposure
        if self.vector.transport in [Transport.TCP, Transport.UDP]:
            port_required_classes = [
                ExposureClass.FILESHARE_EXPOSED,
                ExposureClass.REMOTE_ADMIN_EXPOSED,
                ExposureClass.DB_EXPOSED,
                ExposureClass.CONTAINER_API_EXPOSED,
                ExposureClass.DEBUG_PORT_EXPOSED,
                ExposureClass.UNKNOWN_SERVICE_EXPOSED,
                ExposureClass.HTTP_CONTENT_LEAK,
                ExposureClass.VCS_PROTOCOL_EXPOSED,
            ]
            if self.class_ in port_required_classes:
                if not self.vector.dst or self.vector.dst.port is None:
                    raise ValueError(
                        f'port required for {self.vector.transport.value} '
                        f'with class {self.class_.value}'
                    )
        return self


class HTTPEvidence(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    status_code: Optional[int] = None
    title: Optional[str] = None
    server_header: Optional[str] = None


class EvidenceItem(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    probe: Optional[str] = None
    target: Optional[str] = None
    result: Optional[ProbeResult] = None
    http: Optional[HTTPEvidence] = None
    raw_hash: Optional[str] = None


class Disposition(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    ticket: Optional[str] = None
    owner: Optional[str] = None
    sla: Optional[str] = None
    notes: Optional[str] = None


class ExposureEventModel(BaseModel):
    """
    Root canonical model for an Exposure Event.
    Enforces strict validation matching the JSON schema.
    """
    model_config = ConfigDict(strict=True, extra="forbid")
    
    schema_version: str
    timestamp: datetime = Field(alias="@timestamp")
    event: Event
    office: Office
    scanner: Scanner
    target: Target
    exposure: Exposure
    evidence: Optional[List[EvidenceItem]] = None
    disposition: Optional[Disposition] = None
    
    @model_validator(mode='after')
    def validate_status_action_alignment(self) -> Self:
        """Ensure status and action are aligned"""
        if self.exposure.status == ExposureStatus.RESOLVED:
            if self.event.action != EventAction.EXPOSURE_RESOLVED:
                raise ValueError(
                    'exposure.status=resolved requires event.action=exposure_resolved'
                )
        if self.exposure.status == ExposureStatus.SUPPRESSED:
            if self.event.action != EventAction.EXPOSURE_SUPPRESSED:
                raise ValueError(
                    'exposure.status=suppressed requires event.action=exposure_suppressed'
                )
        return self
