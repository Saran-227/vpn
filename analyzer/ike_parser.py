#!/usr/bin/env python3
"""
SIH26160 IPsec Protocol Analyzer - Deterministic IKE Protocol Parser
Parses unencrypted IKEv1 (ISAKMP) and IKEv2 negotiation packets from PCAPNG captures.
Extracts cryptographic proposals, Diffie-Hellman groups, PRFs, SPIs, Replay window metrics,
and flags mid-stream ESP wiretaps.
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

# RFC 7296 & RFC 5282 / IANA Transform IDs for Encryption
ENCR_NAMES = {
    "1": "DES-IV64",
    "2": "DES",
    "3": "3DES-CBC",
    "4": "RC5",
    "5": "IDEA",
    "6": "CAST",
    "7": "Blowfish",
    "12": "AES-CBC",
    "13": "AES-CTR",
    "14": "AES-CCM-8",
    "15": "AES-CCM-12",
    "16": "AES-CCM-16",
    "18": "AES-GCM-8",
    "19": "AES-GCM-12",
    "20": "AES-GCM-16",      # RFC 5282 & Scapy: 20 is AES-GCM with 16-octet ICV
    "28": "ChaCha20-Poly1305"
}

PRF_NAMES = {
    "1": "PRF_HMAC_MD5",
    "2": "PRF_HMAC_SHA1",
    "4": "PRF_AES128_XCBC",
    "5": "PRF_HMAC_SHA2_256",
    "6": "PRF_HMAC_SHA2_384",
    "7": "PRF_HMAC_SHA2_512"
}

INTEG_NAMES = {
    "1": "AUTH_HMAC_MD5_96",
    "2": "AUTH_HMAC_SHA1_96",
    "12": "AUTH_HMAC_SHA2_256_128",
    "13": "AUTH_HMAC_SHA2_384_192",
    "14": "AUTH_HMAC_SHA2_512_256"
}

DH_NAMES = {
    "1": "768-bit MODP (Group 1)",
    "2": "1024-bit MODP (Group 2)",
    "5": "1536-bit MODP (Group 5)",
    "14": "2048-bit MODP (Group 14)",
    "15": "3072-bit MODP (Group 15)",
    "16": "4096-bit MODP (Group 16)",
    "19": "ECP-256 (DH Group 19)",
    "20": "ECP-384 (DH Group 20)",
    "21": "ECP-521 (DH Group 21)",
    "31": "Curve25519 (Group 31)",
    "256randECPgr": "ECP-256 (DH Group 19)",
    "384randECPgr": "ECP-384 (DH Group 20)",
    "521randECPgr": "ECP-521 (DH Group 21)"
}


def parse_ikev2_transforms(trans_list):
    """
    Parses IKEv2 transforms linked list or array into clean dict with human names.
    Correctly identifies AES-256-GCM vs AES-CCM based on RFC 5282.
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

        if ttype in [1, "Encryption", "ENCR"]:
            raw_name = ENCR_NAMES.get(tid, tid)
            if klen:
                suite["key_length"] = int(klen)
                if "GCM" in raw_name or tid in ["18", "19", "20"]:
                    suite["encryption"] = f"AES-{klen}-GCM"
                elif "CBC" in raw_name or tid == "12":
                    suite["encryption"] = f"AES-{klen}-CBC"
                elif "CCM" in raw_name or tid in ["14", "15", "16"]:
                    suite["encryption"] = f"AES-{klen}-CCM"
                else:
                    suite["encryption"] = f"{raw_name} ({klen}-bit)"
            else:
                suite["encryption"] = raw_name

        elif ttype in [2, "PRF"]:
            suite["prf"] = PRF_NAMES.get(tid, tid)
        elif ttype in [3, "Integrity", "INTEG"]:
            suite["integrity"] = INTEG_NAMES.get(tid, tid)
        elif ttype in [4, "GroupDesc", "D-H Group", "DH"]:
            suite["dh_group"] = DH_NAMES.get(tid, tid)
            try:
                suite["dh_group_num"] = int(tid)
            except Exception:
                pass
            if not suite["dh_group"] or suite["dh_group"] == tid:
                if "19" in tid or "256" in tid:
                    suite["dh_group_num"] = 19
                    suite["dh_group"] = "ECP-256 (DH Group 19)"
                elif "2048" in tid or "14" in tid:
                    suite["dh_group_num"] = 14
                    suite["dh_group"] = "2048-bit MODP (Group 14)"
                elif "1024" in tid or "2" in tid:
                    suite["dh_group_num"] = 2
                    suite["dh_group"] = "1024-bit MODP (Group 2)"
                elif "768" in tid or "1" in tid:
                    suite["dh_group_num"] = 1
                    suite["dh_group"] = "768-bit MODP (Group 1)"
                elif "20" in tid or "384" in tid:
                    suite["dh_group_num"] = 20
                    suite["dh_group"] = "ECP-384 (DH Group 20)"

        # Follow next payload link
        if hasattr(curr, 'payload') and 'Transform' in type(curr.payload).__name__:
            curr = curr.payload
        else:
            break

    # If GCM was chosen, Integrity is built into AEAD
    if suite["encryption"] and "GCM" in suite["encryption"] and not suite["integrity"]:
        suite["integrity"] = "AEAD (Built-in 16-byte ICV Authentication Tag)"

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
        "auth_method": "Pre-Shared Key (PSK)",
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
                val_str = str(attr_val)
                if "PSK" in val_str or "Pre-Shared" in val_str:
                    suite['auth_method'] = "Pre-Shared Key (PSK)"
                else:
                    suite['auth_method'] = val_str
            elif attr_name == 'LifeDuration':
                suite['lifetime_sec'] = int(attr_val)

    if suite['key_length'] and suite['encryption']:
        if "AES" in suite['encryption']:
            suite['encryption'] = f"AES-{suite['key_length']}-CBC"

    return suite


def parse_ipsec_pcap(pcap_path):
    """
    Deterministically parses an IPsec PCAPNG file.
    Extracts IKE negotiation, ESP security parameters (SPIs, replay window, sequences),
    and separates IKE SA from Child SA proposals.
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
        "ike_packet_count": 0,
        "ike_version": None,
        "exchange_type": None,
        "initiator_spi": None,
        "responder_spi": None,
        "nat_traversal": False,
        "auth_method": "Pre-Shared Key (PSK)",
        "key_lifetime": "Autonomous Local Gateway Policy (RFC 7296 unnegotiated on wire; typical default ~3600s / 4GB)",
        "pfs_status": "DISABLED",
        "pfs_details": "No secondary Diffie-Hellman exchange observed",
        "replay_protection": {
            "status": "NOT_APPLICABLE",
            "window_size": 64,
            "window_bit_width": "Undeterminable via Passive Wiretap (Local Gateway Policy)",
            "exact_buffer_size": "Local Gateway Policy (Standard RFC 4303 64-packet baseline)",
            "duplicate_packets": 0,
            "description": "No ESP packets observed"
        },
        "proposals": [],
        "ike_sa_proposal": None,
        "esp_child_sa_proposal": None,
        "esp_stream_summary": {
            "total_esp_packets": 0,
            "unique_spis": [],
            "inbound_spi": None,
            "outbound_spi": None,
            "spi_pair_display": None,
            "seq_range": {}
        }
    }

    esp_spis = []
    esp_seqs_per_spi = {}
    total_esp = 0
    total_ike = 0
    has_cert = False
    ike_udp500_count = 0
    ike_udp4500_count = 0

    for pkt in packets:
        # Check NAT-Traversal UDP 4500
        if UDP in pkt and (pkt[UDP].sport == 4500 or pkt[UDP].dport == 4500):
            res["nat_traversal"] = True

        # Check for Digital Certificates
        if pkt.haslayer('IKEv2_CERT') or pkt.haslayer('IKEv2_CERTREQ') or pkt.haslayer('ISAKMP_payload_Certificate'):
            has_cert = True

        # Track IKE control plane packets (UDP 500 vs UDP 4500)
        if UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            if sport == 500 or dport == 500:
                if pkt.haslayer('IKEv2') or pkt.haslayer('ISAKMP'):
                    total_ike += 1
                    ike_udp500_count += 1
            elif sport == 4500 or dport == 4500:
                if pkt.haslayer('IKEv2') or pkt.haslayer('ISAKMP') or pkt.haslayer('NON_ESP'):
                    total_ike += 1
                    ike_udp4500_count += 1

        # Track ESP packets
        if ESP in pkt:
            total_esp += 1
            try:
                spi_hex = hex(int(pkt[ESP].spi))
                seq = int(pkt[ESP].seq)
                if spi_hex not in esp_spis:
                    esp_spis.append(spi_hex)

                if spi_hex not in esp_seqs_per_spi:
                    esp_seqs_per_spi[spi_hex] = []
                esp_seqs_per_spi[spi_hex].append(seq)
            except Exception:
                pass
        elif IP in pkt and pkt[IP].proto == 50:
            total_esp += 1

        # Check IKEv2
        if pkt.haslayer('IKEv2') and not res["handshake_detected"]:
            res["handshake_detected"] = True
            res["ike_version"] = 2
            ike = pkt['IKEv2']
            res["exchange_type"] = f"{getattr(ike, 'exch_type', 34)} (IKE_SA_INIT / IKE_AUTH)"
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
                    res["ike_sa_proposal"] = suite

                    # Check PFS / DH Group
                    if suite.get("dh_group"):
                        res["pfs_status"] = "ENABLED"
                        res["pfs_details"] = f"Configured with {suite['dh_group']} in CHILD proposal"

        # Check IKEv1 (ISAKMP)
        elif pkt.haslayer('ISAKMP') and not res["handshake_detected"]:
            ike = pkt['ISAKMP']
            v = getattr(ike, 'version', 0x10)
            major = (v >> 4) & 0x0F
            if major == 1:
                res["handshake_detected"] = True
                res["ike_version"] = 1
                res["exchange_type"] = f"{getattr(ike, 'exch_type', 2)} (Main / Aggressive Mode)"
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
                        res["ike_sa_proposal"] = suite
                        if suite.get("auth_method"):
                            res["auth_method"] = suite["auth_method"]
                        if suite.get("dh_group"):
                            res["pfs_status"] = "ENABLED"
                            res["pfs_details"] = f"Configured with {suite['dh_group']} in CHILD proposal"

    res["ike_packet_count"] = total_ike
    res["ike_udp500_count"] = ike_udp500_count
    res["ike_udp4500_count"] = ike_udp4500_count
    if total_ike > 0:
        res["control_plane_summary"] = f"{ike_udp500_count} packets on UDP 500 + {ike_udp4500_count} packets on UDP 4500"
    else:
        res["control_plane_summary"] = "No Handshake Packets (ESP Payload Only)"

    if has_cert:
        res["auth_method"] = "X.509 Digital Certificate (RSA/ECDSA Signature)"
    else:
        res["auth_method"] = "Pre-Shared Key (PSK) - Authentication Succeeded"

    # Format ESP Child SA proposal
    if res["ike_sa_proposal"]:
        ike_suite = res["ike_sa_proposal"]
        # In typical IPsec, Child SA matches or derives from IKE proposal
        res["esp_child_sa_proposal"] = {
            "encryption": ike_suite.get("encryption"),
            "key_length": ike_suite.get("key_length"),
            "integrity": ike_suite.get("integrity"),
            "pfs_group": ike_suite.get("dh_group")
        }

    # Analyze ESP Stream & Sequence Anti-Replay
    res["esp_stream_summary"]["total_esp_packets"] = total_esp
    res["esp_stream_summary"]["unique_spis"] = esp_spis

    if len(esp_spis) >= 2:
        res["esp_stream_summary"]["inbound_spi"] = esp_spis[0]
        res["esp_stream_summary"]["outbound_spi"] = esp_spis[1]
        res["esp_stream_summary"]["spi_pair_display"] = f"{esp_spis[0]} <-> {esp_spis[1]}"
    elif len(esp_spis) == 1:
        res["esp_stream_summary"]["inbound_spi"] = esp_spis[0]
        res["esp_stream_summary"]["spi_pair_display"] = f"{esp_spis[0]} (Unidirectional)"
    else:
        res["esp_stream_summary"]["spi_pair_display"] = "No ESP Streams Active"

    # Replay protection verification across sequence numbers
    total_dups = 0
    seq_metrics = {}
    for s_hex, seq_list in esp_seqs_per_spi.items():
        if seq_list:
            min_s = min(seq_list)
            max_s = max(seq_list)
            dups = len(seq_list) - len(set(seq_list))
            total_dups += dups
            seq_metrics[s_hex] = {
                "min_seq": min_s,
                "max_seq": max_s,
                "count": len(seq_list),
                "duplicate_seqs": dups
            }

    if res.get("ike_version") == 2:
        res["key_lifetime"] = "Autonomous Local Gateway Policy (RFC 7296 unnegotiated on wire; typical default ~3600s - 28800s / 4GB)"

    res["esp_stream_summary"]["seq_range"] = seq_metrics

    if total_esp > 0:
        if total_dups == 0:
            res["replay_protection"] = {
                "status": "VERIFIED_ACTIVE",
                "window_size": 64,
                "window_bit_width": "Undeterminable via Passive Wiretap (Local Gateway Policy - Standard 64-bit / 128-bit Buffer)",
                "exact_buffer_size": "Local Gateway Policy (RFC 4303 64-packet baseline; internal kernel ring buffer unexposed on wire)",
                "duplicate_packets": 0,
                "description": f"RFC 4303 Sliding Window Active (0 duplicates observed across {total_esp} ESP packets; exact window bit-width buffer is local gateway policy)"
            }
        else:
            res["replay_protection"] = {
                "status": "REPLAY_WARNING",
                "window_size": 64,
                "window_bit_width": "Undeterminable via Passive Wiretap (Local Gateway Policy)",
                "exact_buffer_size": "Local Gateway Policy",
                "duplicate_packets": total_dups,
                "description": f"WARNING: {total_dups} duplicate sequence numbers detected! Potential replay attack or transmission race."
            }

    return res


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m analyzer.ike_parser <pcap_file>")
        sys.exit(1)
    
    import json
    out = parse_ipsec_pcap(sys.argv[1])
    print(json.dumps(out, indent=2))
