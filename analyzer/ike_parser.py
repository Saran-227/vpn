#!/usr/bin/env python3
"""
SIH26160 IPsec Protocol Analyzer - Deterministic IKE Protocol Parser
Parses unencrypted IKEv1 (ISAKMP) and IKEv2 negotiation packets from PCAPNG captures.
Extracts cryptographic proposals, Diffie-Hellman groups, PRFs, and flags mid-stream ESP wiretaps.
"""

import os
import sys
from scapy.all import rdpcap, IP, UDP, ESP, ISAKMP
import scapy.contrib.ikev2 as ikev2_layer


# Transform Type ID mappings (RFC 7296 for IKEv2)
IKEV2_TRANSFORM_TYPES = {
    1: "Encryption",
    2: "PRF",
    3: "Integrity",
    4: "Diffie-Hellman Group",
    5: "Extended Sequence Numbers"
}

# RFC 7296 / IANA Transform IDs
ENCR_NAMES = {
    "1": "DES-IV64", "2": "DES", "3": "3DES-CBC", "12": "AES-CBC",
    "13": "AES-CTR", "18": "AES-CCM-8", "19": "AES-CCM-12", "20": "AES-CCM-16",
    "28": "AES-GCM-8", "29": "AES-GCM-12", "30": "AES-GCM-16", "31": "ChaCha20-Poly1305"
}

PRF_NAMES = {
    "1": "PRF_HMAC_MD5", "2": "PRF_HMAC_SHA1", "4": "PRF_AES128_XCBC",
    "5": "PRF_HMAC_SHA2_256", "6": "PRF_HMAC_SHA2_384", "7": "PRF_HMAC_SHA2_512"
}

INTEG_NAMES = {
    "1": "AUTH_HMAC_MD5_96", "2": "AUTH_HMAC_SHA1_96", "12": "AUTH_HMAC_SHA2_256_128",
    "13": "AUTH_HMAC_SHA2_384_192", "14": "AUTH_HMAC_SHA2_512_256"
}

DH_NAMES = {
    "1": "768-bit MODP (Group 1)", "2": "1024-bit MODP (Group 2)", "5": "1536-bit MODP (Group 5)",
    "14": "2048-bit MODP (Group 14)", "15": "3072-bit MODP (Group 15)", "16": "4096-bit MODP (Group 16)",
    "19": "256-bit Random ECP / NIST P-256 (Group 19)", "20": "384-bit Random ECP / NIST P-384 (Group 20)",
    "21": "521-bit Random ECP / NIST P-521 (Group 21)", "31": "Curve25519 (Group 31)"
}


def parse_ikev2_transforms(trans_list):
    """
    Parses IKEv2 transforms linked list or array into clean dict with human names.
    """
    suite = {
        "encryption": None,
        "key_length": None,
        "integrity": None,
        "prf": None,
        "dh_group": None,
        "dh_group_num": None
    }
    
    curr = trans_list
    while curr:
        ttype = getattr(curr, 'transform_type', None)
        tid = str(getattr(curr, 'transform_id', ''))
        klen = getattr(curr, 'key_length', None)

        # Scapy represents transform_type as integer or enum
        if ttype in [1, "Encryption", "ENCR"]:
            suite["encryption"] = ENCR_NAMES.get(tid, tid)
            if klen:
                suite["key_length"] = int(klen)
        elif ttype in [2, "PRF"]:
            suite["prf"] = PRF_NAMES.get(tid, tid)
        elif ttype in [3, "Integrity", "INTEG"]:
            suite["integrity"] = INTEG_NAMES.get(tid, tid)
        elif ttype in [4, "GroupDesc", "D-H Group", "DH"]:
            suite["dh_group"] = DH_NAMES.get(tid, tid)
            try:
                suite["dh_group_num"] = int(tid)
            except Exception:
                if "2048" in tid or "14" in tid: suite["dh_group_num"] = 14
                elif "1024" in tid or "2" in tid: suite["dh_group_num"] = 2
                elif "768" in tid or "1" in tid: suite["dh_group_num"] = 1
                elif "19" in tid or "256" in tid: suite["dh_group_num"] = 19
                elif "20" in tid or "384" in tid: suite["dh_group_num"] = 20


        # Follow next payload link
        if hasattr(curr, 'payload') and 'Transform' in type(curr.payload).__name__:
            curr = curr.payload
        else:
            break

    return suite


def parse_ikev1_transforms(trans_obj):
    """
    Parses IKEv1 (ISAKMP) transform attributes list.
    """
    suite = {
        "encryption": None,
        "key_length": None,
        "integrity": None,
        "prf": None,
        "dh_group": None,
        "dh_group_num": None,
        "auth_method": None,
        "lifetime_sec": None
    }

    attrs = getattr(trans_obj, 'transforms', [])
    for item in attrs:
        if isinstance(item, tuple) and len(item) == 2:
            attr_name, attr_val = item
            if attr_name == 'Encryption':
                suite['encryption'] = str(attr_val)
            elif attr_name == 'KeyLength':
                suite['key_length'] = int(attr_val)
            elif attr_name == 'Hash':
                suite['integrity'] = str(attr_val)
                suite['prf'] = str(attr_val)
            elif attr_name == 'GroupDesc':
                suite['dh_group'] = str(attr_val)
                if '1024' in str(attr_val):
                    suite['dh_group_num'] = 2
                elif '768' in str(attr_val):
                    suite['dh_group_num'] = 1
                elif '2048' in str(attr_val):
                    suite['dh_group_num'] = 14
                elif '1536' in str(attr_val):
                    suite['dh_group_num'] = 5
            elif attr_name == 'Authentication':
                suite['auth_method'] = str(attr_val)
            elif attr_name == 'LifeDuration':
                suite['lifetime_sec'] = int(attr_val)

    return suite


def parse_ipsec_pcap(pcap_path):
    """
    Deterministically parses an IPsec PCAPNG file.
    Extracts IKE handshake parameters, or flags ESP-only stream.
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"File not found: {pcap_path}")

    packets = rdpcap(pcap_path)
    if not packets:
        return {"error": "Empty PCAP"}

    res = {
        "pcap_file": os.path.basename(pcap_path),
        "total_packets": len(packets),
        "handshake_detected": False,
        "ike_version": None,
        "exchange_type": None,
        "initiator_spi": None,
        "responder_spi": None,
        "nat_traversal": False,
        "proposals": [],
        "esp_stream_summary": {
            "total_esp_packets": 0,
            "unique_spis": [],
            "seq_range": {}
        }
    }

    esp_spis = set()
    esp_seqs = {}
    total_esp = 0

    for pkt in packets:
        # Check NAT-Traversal UDP 4500
        if UDP in pkt and (pkt[UDP].sport == 4500 or pkt[UDP].dport == 4500):
            res["nat_traversal"] = True

        # ESP tracking
        if ESP in pkt:
            total_esp += 1
            try:
                spi_hex = hex(int(pkt[ESP].spi))
                seq = int(pkt[ESP].seq)
                esp_spis.add(spi_hex)
                if spi_hex not in esp_seqs:
                    esp_seqs[spi_hex] = {"min_seq": seq, "max_seq": seq, "count": 1}
                else:
                    esp_seqs[spi_hex]["min_seq"] = min(esp_seqs[spi_hex]["min_seq"], seq)
                    esp_seqs[spi_hex]["max_seq"] = max(esp_seqs[spi_hex]["max_seq"], seq)
                    esp_seqs[spi_hex]["count"] += 1
            except Exception:
                pass
        elif IP in pkt and pkt[IP].proto == 50:
            total_esp += 1

        # Check IKEv2
        if pkt.haslayer('IKEv2') and not res["handshake_detected"]:
            res["handshake_detected"] = True
            res["ike_version"] = 2
            ike = pkt['IKEv2']
            res["exchange_type"] = f"{getattr(ike, 'exch_type', 34)} (IKE_SA_INIT)"
            if hasattr(ike, 'init_cookie'):
                res["initiator_spi"] = ike.init_cookie.hex() if isinstance(ike.init_cookie, bytes) else str(ike.init_cookie)
            if hasattr(ike, 'resp_cookie'):
                res["responder_spi"] = ike.resp_cookie.hex() if isinstance(ike.resp_cookie, bytes) else str(ike.resp_cookie)

            if pkt.haslayer('IKEv2_SA'):
                sa = pkt['IKEv2_SA']
                prop = getattr(sa, 'prop', None)
                if prop and hasattr(prop, 'trans'):
                    suite = parse_ikev2_transforms(prop.trans)
                    res["proposals"].append(suite)

        # Check IKEv1 (ISAKMP)
        elif pkt.haslayer('ISAKMP') and not res["handshake_detected"]:
            ike = pkt['ISAKMP']
            v = getattr(ike, 'version', 0x10)
            major = (v >> 4) & 0x0F
            if major == 1:
                res["handshake_detected"] = True
                res["ike_version"] = 1
                res["exchange_type"] = f"{getattr(ike, 'exch_type', 2)} (Main/Aggressive Mode)"
                if hasattr(ike, 'init_cookie'):
                    res["initiator_spi"] = ike.init_cookie.hex() if isinstance(ike.init_cookie, bytes) else str(ike.init_cookie)
                if hasattr(ike, 'resp_cookie'):
                    res["responder_spi"] = ike.resp_cookie.hex() if isinstance(ike.resp_cookie, bytes) else str(ike.resp_cookie)

                if pkt.haslayer('ISAKMP_payload_SA'):
                    sa = pkt['ISAKMP_payload_SA']
                    prop = getattr(sa, 'prop', None)
                    if prop and hasattr(prop, 'trans'):
                        suite = parse_ikev1_transforms(prop.trans)
                        res["proposals"].append(suite)

    res["esp_stream_summary"]["total_esp_packets"] = total_esp
    res["esp_stream_summary"]["unique_spis"] = list(esp_spis)
    res["esp_stream_summary"]["seq_range"] = esp_seqs

    return res


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m analyzer.ike_parser <pcap_file>")
        sys.exit(1)
    
    import json
    out = parse_ipsec_pcap(sys.argv[1])
    print(json.dumps(out, indent=2))
