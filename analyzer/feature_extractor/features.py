from dataclasses import dataclass


@dataclass(frozen=True)
class FlowFeatures:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str

    packet_count: int
    total_bytes: int
    flow_duration_seconds: float

    min_packet_size: int
    max_packet_size: int
    avg_packet_size: float
    packet_size_std: float

    packets_per_second: float
    bytes_per_second: float

    forward_packet_count: int
    backward_packet_count: int
    forward_bytes: int
    backward_bytes: int

    min_inter_arrival_seconds: float
    max_inter_arrival_seconds: float
    avg_inter_arrival_seconds: float
    inter_arrival_std: float
