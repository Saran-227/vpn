import math

from analyzer.feature_extractor.features import FlowFeatures
from analyzer.feature_extractor.flow_builder import FlowRecord
from analyzer.feature_extractor.packet_reader import PacketRecord


def extract_flow_features(
    flow: FlowRecord,
    packets: list[PacketRecord] | None = None,
) -> FlowFeatures:
    if packets is not None:
        flow_packets = [
            packet
            for packet in packets
            if (
                (
                    packet.src_ip == flow.key.endpoint_a_ip
                    and packet.src_port == flow.key.endpoint_a_port
                    and packet.dst_ip == flow.key.endpoint_b_ip
                    and packet.dst_port == flow.key.endpoint_b_port
                    and packet.protocol == flow.key.protocol
                )
                or (
                    packet.src_ip == flow.key.endpoint_b_ip
                    and packet.src_port == flow.key.endpoint_b_port
                    and packet.dst_ip == flow.key.endpoint_a_ip
                    and packet.dst_port == flow.key.endpoint_a_port
                    and packet.protocol == flow.key.protocol
                )
                or (
                    getattr(flow, "packets", None)
                    and packet in flow.packets
                )
            )
        ]
    elif getattr(flow, "packets", None):
        flow_packets = flow.packets
    else:
        flow_packets = []

    if not flow_packets:
        raise ValueError(f"No packets found for flow: {flow.flow_id}")

    sizes = [packet.length for packet in flow_packets]

    packet_count = len(flow_packets)
    total_bytes = sum(sizes)

    flow_duration_seconds = (
        max(packet.timestamp for packet in flow_packets)
        - min(packet.timestamp for packet in flow_packets)
    )

    min_packet_size = min(sizes)
    max_packet_size = max(sizes)
    avg_packet_size = total_bytes / packet_count

    variance = sum(
        (size - avg_packet_size) ** 2
        for size in sizes
    ) / packet_count

    packet_size_std = math.sqrt(variance)

    if flow_duration_seconds > 0:
        packets_per_second = packet_count / flow_duration_seconds
        bytes_per_second = total_bytes / flow_duration_seconds
    else:
        packets_per_second = 0.0
        bytes_per_second = 0.0

    timestamps = sorted(packet.timestamp for packet in flow_packets)

    if len(timestamps) > 1:
        inter_arrivals = [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
        ]

        min_inter_arrival_seconds = min(inter_arrivals)
        max_inter_arrival_seconds = max(inter_arrivals)
        avg_inter_arrival_seconds = sum(inter_arrivals) / len(inter_arrivals)

        iat_variance = sum(
            (value - avg_inter_arrival_seconds) ** 2
            for value in inter_arrivals
        ) / len(inter_arrivals)

        inter_arrival_std = math.sqrt(iat_variance)
    else:
        min_inter_arrival_seconds = 0.0
        max_inter_arrival_seconds = 0.0
        avg_inter_arrival_seconds = 0.0
        inter_arrival_std = 0.0

    return FlowFeatures(
        flow_id=flow.flow_id,
        src_ip=flow.key.endpoint_a_ip,
        dst_ip=flow.key.endpoint_b_ip,
        src_port=flow.key.endpoint_a_port,
        dst_port=flow.key.endpoint_b_port,
        protocol=flow.key.protocol,
        packet_count=packet_count,
        total_bytes=total_bytes,
        flow_duration_seconds=flow_duration_seconds,
        min_packet_size=min_packet_size,
        max_packet_size=max_packet_size,
        avg_packet_size=avg_packet_size,
        packet_size_std=packet_size_std,
        packets_per_second=packets_per_second,
        bytes_per_second=bytes_per_second,
        forward_packet_count=flow.forward_packet_count,
        backward_packet_count=flow.backward_packet_count,
        forward_bytes=flow.forward_bytes,
        backward_bytes=flow.backward_bytes,
        min_inter_arrival_seconds=min_inter_arrival_seconds,
        max_inter_arrival_seconds=max_inter_arrival_seconds,
        avg_inter_arrival_seconds=avg_inter_arrival_seconds,
        inter_arrival_std=inter_arrival_std,
    )

def extract_features_from_packets(
    packets: list[PacketRecord],
) -> list[FlowFeatures]:
    from analyzer.feature_extractor.flow_builder import build_flows

    flows = build_flows(packets)

    return [
        extract_flow_features(flow, packets)
        for flow in flows
    ]
