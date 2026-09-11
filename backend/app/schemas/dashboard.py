from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field

RiskLevel = Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
VPNStatus = Literal['CONNECTED', 'DISCONNECTED', 'CONNECTING']
Severity = Literal['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

class VPNState(BaseModel):
    status: VPNStatus
    endpoint_a: str
    endpoint_a_ip: str = ''
    endpoint_b: str
    endpoint_b_ip: str = ''
    tunnel: str
    uptime_seconds: int = Field(ge=0)
    protocol: str
    encryption: str

class Metrics(BaseModel):
    packets_per_second: float = Field(ge=0)
    bytes_per_second: float = Field(ge=0)
    total_packets: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    active_flows: int = Field(ge=0)
    average_packet_size: float = Field(ge=0)
    inbound_bps: float = Field(ge=0)
    outbound_bps: float = Field(ge=0)

class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    description: str
    reason: str

class SecurityState(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    anomaly_detected: bool
    findings: list[Finding] = []

class SecurityEvent(BaseModel):
    timestamp: datetime
    type: str
    title: str
    severity: Severity
    description: str

class HistoryPoint(BaseModel):
    timestamp: datetime
    packets_per_second: float = Field(ge=0)
    bytes_per_second: float = Field(ge=0)
    risk_score: int = Field(ge=0, le=100)
    inbound_bps: float = Field(ge=0)
    outbound_bps: float = Field(ge=0)

class DashboardState(BaseModel):
    timestamp: datetime
    vpn: VPNState
    metrics: Metrics
    security: SecurityState
    events: list[SecurityEvent]
    history: list[HistoryPoint]
    mode: Literal['MOCK', 'REAL']
