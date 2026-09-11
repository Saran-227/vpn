from scapy.all import Ether, IP, UDP, Raw, wrpcap


packets = [
    Ether(
        src="02:00:00:00:00:01",
        dst="02:00:00:00:00:02",
    ) / IP(
        src="192.0.2.1",
        dst="192.0.2.2",
    ) / UDP(
        sport=4500,
        dport=4500,
    ) / Raw(
        b"\x00" * 140
    ),

    Ether(
        src="02:00:00:00:00:02",
        dst="02:00:00:00:00:01",
    ) / IP(
        src="192.0.2.2",
        dst="192.0.2.1",
    ) / UDP(
        sport=4500,
        dport=4500,
    ) / Raw(
        b"\x00" * 180
    ),
]


wrpcap(
    "analyzer/sample_data/nat_t_test.pcap",
    packets,
)

print("Created analyzer/sample_data/nat_t_test.pcap")
