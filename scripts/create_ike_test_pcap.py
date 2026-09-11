from scapy.all import Ether, IP, UDP, Raw, wrpcap

packets = [
    Ether(
        src="02:00:00:00:00:01",
        dst="02:00:00:00:00:02",
    ) / IP(
        src="192.0.2.1",
        dst="192.0.2.2",
    ) / UDP(
        sport=500,
        dport=500,
    ) / Raw(
        b"\x00" * 128
    ),

    Ether(
        src="02:00:00:00:00:02",
        dst="02:00:00:00:00:01",
    ) / IP(
        src="192.0.2.2",
        dst="192.0.2.1",
    ) / UDP(
        sport=500,
        dport=500,
    ) / Raw(
        b"\x00" * 160
    ),
]

wrpcap(
    "analyzer/sample_data/ike_test.pcap",
    packets,
)

print("Created analyzer/sample_data/ike_test.pcap")
