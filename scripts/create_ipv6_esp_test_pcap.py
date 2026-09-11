from scapy.all import Ether, IPv6, ESP, Raw, wrpcap

packets = [
    Ether(
        src="02:00:00:00:00:01",
        dst="02:00:00:00:00:02",
    ) / IPv6(
        src="2001:db8::1",
        dst="2001:db8::2",
    ) / ESP(
        spi=0x1001,
        seq=1,
    ) / Raw(b"A" * 32),

    Ether(
        src="02:00:00:00:00:02",
        dst="02:00:00:00:00:01",
    ) / IPv6(
        src="2001:db8::2",
        dst="2001:db8::1",
    ) / ESP(
        spi=0x1001,
        seq=2,
    ) / Raw(b"B" * 48),
]

wrpcap(
    "analyzer/sample_data/ipv6_esp_test.pcap",
    packets,
)

print("Created analyzer/sample_data/ipv6_esp_test.pcap")
