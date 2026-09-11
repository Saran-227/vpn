import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from analyzer.feature_extractor.packet_reader import read_pcap
from analyzer.feature_extractor.flow_builder import build_flows
from analyzer.feature_extractor.feature_extractor import extract_features_from_packets
from analyzer.feature_extractor.exporter import export_features_to_csv


def main():
    if len(sys.argv) != 2:
        print("Usage: python scripts/analyze_pcap.py <pcap_path>")
        sys.exit(1)

    pcap_path = Path(sys.argv[1])

    if not pcap_path.exists():
        print(f"PCAP file not found: {pcap_path}")
        sys.exit(1)

    packets = list(read_pcap(pcap_path))
    flows = build_flows(packets)
    features = extract_features_from_packets(packets)

    output_path = (
        pcap_path.parent
        / f"{pcap_path.stem}_features.csv"
    )

    export_features_to_csv(features, output_path)

    print(f"PCAP: {pcap_path}")
    print(f"Packets: {len(packets)}")
    print(f"Flows: {len(flows)}")
    print(f"Features: {len(features)}")
    print(f"Output: {output_path}")

    print("\nFlow summary:")

    for feature in features:
        print(
            f"{feature.flow_id}: "
            f"{feature.protocol} "
            f"packets={feature.packet_count} "
            f"bytes={feature.total_bytes} "
            f"duration={feature.flow_duration_seconds:.6f}s"
        )


if __name__ == "__main__":
    main()
