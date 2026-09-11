from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from scapy.all import (
    Ether,
    ICMP,
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    IP,
    IPv6,
    PcapReader,
    Raw,
    TCP,
    UDP,
    ESP,
)


@dataclass(frozen=True)
class PacketRecord:
    timestamp: float
    length: int
    src_ip: Optional[str]
    dst_ip: Optional[str]
    protocol: str
    src_port: Optional[int]
    dst_port: Optional[int]


def _get_ip_addresses(packet) -> tuple[Optional[str], Optional[str]]:
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst

    if packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst

    return None, None


def _get_protocol(packet) -> str:
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ICMPv6EchoRequest) or packet.haslayer(ICMPv6EchoReply):
        return "ICMPv6"
    if packet.haslayer(ESP):
        return "ESP"

    if packet.haslayer(IP):
        ip = packet[IP]
        if ip.proto == 6:
            return "TCP"
        if ip.proto == 17:
            return "UDP"
        if ip.proto == 1:
            return "ICMP"
        if ip.proto == 50:
            return "ESP"
        return "IP"

    if packet.haslayer(IPv6):
        return "IPv6"
    if packet.haslayer(Raw):
        return "RAW"
    if packet.haslayer(Ether):
        return "ETHERNET"
    return "UNKNOWN"

def _get_ports(packet) -> tuple[Optional[int], Optional[int]]:
    if packet.haslayer(TCP):
        return int(packet[TCP].sport), int(packet[TCP].dport)

    if packet.haslayer(UDP):
        return int(packet[UDP].sport), int(packet[UDP].dport)

    return None, None


def packet_to_record(packet) -> PacketRecord:
    src_ip, dst_ip = _get_ip_addresses(packet)
    src_port, dst_port = _get_ports(packet)

    return PacketRecord(
        timestamp=float(packet.time),
        length=len(packet),
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=_get_protocol(packet),
        src_port=src_port,
        dst_port=dst_port,
    )


def _validate_pcap_header(path: Path) -> None:
    with path.open("rb") as file:
        magic = file.read(4)

    valid_magic_numbers = {
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
        b"\x0a\x0d\x0d\x0a",
    }

    if magic not in valid_magic_numbers:
        raise ValueError(f"Invalid PCAP/PCAPNG file: {path}")


def read_pcap(pcap_path: str | Path) -> Iterator[PacketRecord]:
    path = Path(pcap_path)

    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    if not path.is_file():
        raise ValueError(f"PCAP path is not a file: {path}")

    _validate_pcap_header(path)

    try:
        with PcapReader(str(path)) as reader:
            for packet in reader:
                yield packet_to_record(packet)
    except Exception as exc:
        raise ValueError(f"Failed to read PCAP file: {path}") from exc
