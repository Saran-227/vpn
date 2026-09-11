from dataclasses import dataclass
from typing import Optional

from analyzer.feature_extractor.packet_reader import PacketRecord


@dataclass(frozen=True)
class FlowKey:
    endpoint_a_ip: str
    endpoint_a_port: Optional[int]
    endpoint_b_ip: str
    endpoint_b_port: Optional[int]
    protocol: str


@dataclass
class FlowRecord:
    flow_id: str
    key: FlowKey
    first_timestamp: float
    last_timestamp: float
    forward_packet_count: int = 0
    backward_packet_count: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0


def _endpoint_sort_key(
    ip: Optional[str],
    port: Optional[int],
) -> tuple[str, int]:
    return ip or "", -1 if port is None else port


def _create_flow_key(packet: PacketRecord) -> FlowKey:
    source = (packet.src_ip, packet.src_port)
    destination = (packet.dst_ip, packet.dst_port)

    if _endpoint_sort_key(*source) <= _endpoint_sort_key(*destination):
        endpoint_a = source
        endpoint_b = destination
    else:
        endpoint_a = destination
        endpoint_b = source

    return FlowKey(
        endpoint_a_ip=endpoint_a[0] or "",
        endpoint_a_port=endpoint_a[1],
        endpoint_b_ip=endpoint_b[0] or "",
        endpoint_b_port=endpoint_b[1],
        protocol=packet.protocol,
    )


def _is_forward(packet: PacketRecord, key: FlowKey) -> bool:
    if packet.src_ip == key.endpoint_a_ip and packet.dst_ip == key.endpoint_b_ip:
        if packet.src_port is None and packet.dst_port is None:
            return True

        return (
            packet.src_port == key.endpoint_a_port
            and packet.dst_port == key.endpoint_b_port
        )

    return False

def _find_fragment_flow(
    packet: PacketRecord,
    flows: dict[FlowKey, FlowRecord],
) -> FlowRecord | None:
    if packet.src_ip is None or packet.dst_ip is None:
        return None

    if packet.src_port is not None or packet.dst_port is not None:
        return None

    for key, flow in flows.items():
        if key.protocol != packet.protocol:
            continue

        if (
            packet.src_ip == key.endpoint_a_ip
            and packet.dst_ip == key.endpoint_b_ip
        ) or (
            packet.src_ip == key.endpoint_b_ip
            and packet.dst_ip == key.endpoint_a_ip
        ):
            return flow

    return None


def build_flows(packets: list[PacketRecord]) -> list[FlowRecord]:
    flows: dict[FlowKey, FlowRecord] = {}

    for packet in packets:
        if packet.src_ip is None or packet.dst_ip is None:
            continue

        key = _create_flow_key(packet)

        fragment_flow = _find_fragment_flow(packet, flows)

        if fragment_flow is not None:
            flow = fragment_flow
        else:
            if key not in flows:
                flow_id = f"flow_{len(flows) + 1}"
                flows[key] = FlowRecord(
                    flow_id=flow_id,
                    key=key,
                    first_timestamp=packet.timestamp,
                    last_timestamp=packet.timestamp,
                )

            flow = flows[key]

        flow.first_timestamp = min(
            flow.first_timestamp,
            packet.timestamp,
        )

        flow.last_timestamp = max(
            flow.last_timestamp,
            packet.timestamp,
        )

        if _is_forward(packet, flow.key):
            flow.forward_packet_count += 1
            flow.forward_bytes += packet.length
        else:
            flow.backward_packet_count += 1
            flow.backward_bytes += packet.length

    return list(flows.values())
