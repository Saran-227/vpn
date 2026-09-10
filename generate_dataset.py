#!/usr/bin/env python3
"""
Host-side Master Dataset Orchestrator for SIH26160.
Generates an authentic, labeled .pcapng dataset covering:
- Exhaustive protocol permutations (IKEv1/v2, Tunnel/Transport, AES-GCM, AES-CBC, 3DES, DH Groups, PFS)
- Realistic network imperfections (tc-netem jitter, loss, out-of-order reordering, MTU truncation)
- Multiple application traffic profiles (VoIP, Video, Web, Chat, Email, Bulk, ICMP, Mixed)
- Authentic real-world scenarios (including missing handshakes / ESP-only traces)
- Granular ground-truth JSON metadata with NIST SP 800-77 compliance scoring.
"""

import subprocess
import argparse
import datetime
import time
import json
import uuid
import random
import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "dataset", "raw_pcapng")
COMPOSE_FILE = os.path.join(BASE_DIR, "testbed", "docker-compose.yml")

def run_cmd(cmd, check=True):
    """Executes a command on the host."""
    res = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed ({res.returncode}): {cmd}\nStderr: {res.stderr}\nStdout: {res.stdout}")
    return res.returncode == 0, res.stdout, res.stderr

def run_docker_exec(container, cmd):
    """Executes a command inside a specific running container."""
    docker_cmd = f"docker exec {container} {cmd}"
    return run_cmd(docker_cmd, check=False)

def ensure_testbed_running():
    """Builds and launches testbed containers if not already active."""
    print("[Orchestrator] Checking Docker testbed containers...")
    _, out, _ = run_cmd("docker ps --format '{{.Names}}'", check=False)
    running = out.strip().split("\n")
    
    if "vpn-initiator" not in running or "vpn-responder" not in running:
        print("[Orchestrator] Starting IPsec testbed containers via docker compose...")
        run_cmd(f"docker compose -f \"{COMPOSE_FILE}\" up -d --build")
        print("[Orchestrator] Waiting for containers to initialize...")
        time.sleep(3)
    
    # Ensure responder background traffic sink is running
    print("[Orchestrator] Ensuring responder traffic listeners are active...")
    run_docker_exec("vpn-responder", "pkill -f traffic_generator.py")
    run_docker_exec("vpn-responder", "nohup python3 /scripts/traffic_generator.py --mode responder > /tmp/responder.log 2>&1 &")
    time.sleep(1)
    print("[Orchestrator] Testbed is ready.")

def evaluate_nist_compliance(cipher_suite):
    """
    Evaluates cryptographic parameters against NIST SP 800-77 Rev. 1 guidelines.
    Returns: status ('PASS', 'WARNING', 'FAIL'), score (0-100), and list of violations.
    """
    violations = []
    score = 100
    
    ike_enc = cipher_suite.get("ike_encryption", "").lower()
    esp_enc = cipher_suite.get("esp_encryption", "").lower()
    integrity = cipher_suite.get("integrity", "").lower()
    dh = cipher_suite.get("dh_group", 14)
    pfs = cipher_suite.get("pfs_enabled", True)
    
    # Check encryption algorithms
    if "3des" in ike_enc or "3des" in esp_enc or "des" in ike_enc or "des" in esp_enc:
        violations.append("3DES/DES encryption is obsolete and vulnerable to Sweet32 attack (NIST SP 800-77 Rev. 1 Section 3.1).")
        score -= 50
    elif "aes" not in ike_enc and "chacha20" not in ike_enc:
        violations.append("Non-standard or legacy cipher algorithm detected.")
        score -= 30

    # Check integrity / hashes
    if "md5" in integrity:
        violations.append("MD5 integrity hashing is cryptographically broken with known collision vulnerabilities.")
        score -= 40
    elif "sha1" in integrity:
        violations.append("SHA-1 is deprecated by NIST; SHA-2 or AEAD (GCM) is required.")
        score -= 25

    # Check Diffie-Hellman Group
    if dh in [1, 2]: # MODP-768, MODP-1024
        violations.append(f"Diffie-Hellman Group {dh} provides < 2048-bit key exchange strength, violating NIST requirements.")
        score -= 35
    elif dh == 5: # MODP-1536
        violations.append("DH Group 5 (1536-bit) is considered legacy by NIST.")
        score -= 15

    # Check PFS
    if not pfs:
        violations.append("Perfect Forward Secrecy (PFS) is disabled; compromise of long-term key compromises all past sessions.")
        score -= 15

    score = max(0, min(100, score))
    status = "PASS" if score >= 80 else ("WARNING" if score >= 50 else "CRITICAL_FAIL")
    return {"status": status, "score": score, "violations": violations}


def run_single_capture_experiment(experiment):
    """Executes a complete test run and produces a labeled .pcapng file."""
    run_id = f"{experiment['id']}_{int(time.time())}"
    pcap_filename = f"{run_id}.pcapng"
    pcap_container_path = f"/shared/dataset/{pcap_filename}"
    pcap_host_path = os.path.join(DATASET_DIR, pcap_filename)
    json_host_path = os.path.join(DATASET_DIR, f"{run_id}.json")

    print(f"\n=======================================================")
    print(f"[*] RUNNING: {experiment['name']}")
    print(f"    Mode: {experiment['mode'].upper()} | IKE: {experiment['ike_version'].upper()} | Traffic: {experiment['traffic'].upper()}")
    print(f"    Ciphers: IKE={experiment['ike_cipher']} | ESP={experiment['esp_cipher']}")
    print(f"    Imperfections: Loss={experiment['netem']['loss_pct']}% | Delay={experiment['netem']['delay_ms']}ms ± {experiment['netem']['jitter_ms']}ms | Handshake Captured: {experiment['has_handshake']}")
    print(f"=======================================================")

    # 1. Clear any prior IPsec state and netem impairments
    run_docker_exec("vpn-initiator", "python3 /scripts/ipsec_manager.py --role initiator --action stop")
    run_docker_exec("vpn-responder", "python3 /scripts/ipsec_manager.py --role responder --action stop")
    run_docker_exec("vpn-initiator", "python3 /scripts/netem_controller.py --clear")

    # 2. Configure IPsec on Responder
    run_docker_exec("vpn-responder", 
        f"python3 /scripts/ipsec_manager.py --role responder --action setup "
        f"--ike-version {experiment['ike_version']} --mode {experiment['mode']} "
        f"--ike-cipher {experiment['ike_cipher']} --esp-cipher {experiment['esp_cipher']} "
        f"{'--nat-t' if experiment.get('nat_t') else ''}"
    )

    # 3. Configure IPsec on Initiator
    run_docker_exec("vpn-initiator", 
        f"python3 /scripts/ipsec_manager.py --role initiator --action setup "
        f"--ike-version {experiment['ike_version']} --mode {experiment['mode']} "
        f"--ike-cipher {experiment['ike_cipher']} --esp-cipher {experiment['esp_cipher']} "
        f"{'--nat-t' if experiment.get('nat_t') else ''}"
    )

    # 4. Apply Network Imperfections via tc-netem
    netem = experiment["netem"]
    run_docker_exec("vpn-initiator",
        f"python3 /scripts/netem_controller.py --delay {netem['delay_ms']} "
        f"--jitter {netem['jitter_ms']} --loss {netem['loss_pct']} "
        f"--reorder {netem['reorder_pct']} --mtu {netem['mtu']}"
    )

    # 5. Handle Handshake vs Mid-Stream Scenario
    # If has_handshake is False (simulating passive mid-stream intercept), bring tunnel UP FIRST
    if not experiment["has_handshake"]:
        print("[Orchestrator] Establishing tunnel prior to capture (ESP-only wiretap simulation)...")
        run_docker_exec("vpn-initiator", "ipsec up vpn-link")
        time.sleep(2)

    # 6. Start Packet Capture on Initiator interface
    print(f"[Orchestrator] Starting capture to {pcap_container_path}...")
    run_cmd(f"docker exec -d vpn-initiator tcpdump -i eth0 -s 0 -w {pcap_container_path} -Z root", check=False)
    time.sleep(1)

    # If has_handshake is True, bring up tunnel NOW so handshake is recorded in capture
    if experiment["has_handshake"]:
        print("[Orchestrator] Initiating IKE handshake across active capture...")
        run_docker_exec("vpn-initiator", "ipsec up vpn-link")
        time.sleep(2)


    # 7. Generate Inner Encrypted Application Traffic
    noise_flag = "--noise" if experiment.get("background_noise") else ""
    duration = experiment.get("duration", 8)
    print(f"[Orchestrator] Injecting {experiment['traffic']} traffic for {duration}s...")
    run_docker_exec("vpn-initiator", 
        f"python3 /scripts/traffic_generator.py --mode client --target-ip 172.28.0.3 "
        f"--traffic {experiment['traffic']} --duration {duration} {noise_flag}"
    )

    # 8. Stop Packet Capture
    time.sleep(1)
    run_docker_exec("vpn-initiator", "pkill -2 tcpdump") # SIGINT to flush cleanly
    time.sleep(1)

    # 9. Verify and Read Stats
    _, stats_out, _ = run_docker_exec("vpn-initiator", f"python3 /scripts/capture_worker.py --action stats --output {pcap_container_path}")
    try:
        stats = json.loads(stats_out.strip())
    except Exception:
        stats = {"total_packets": 0, "ike_packets": 0, "esp_packets": 0}

    # 10. Compute NIST Compliance
    compliance = evaluate_nist_compliance(experiment["crypto"])

    # 11. Build Ground-Truth Annotation Metadata
    metadata = {
        "capture_id": run_id,
        "pcap_file": pcap_filename,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "experiment_name": experiment["name"],
        "protocol_stack": {
            "ipsec_protocol": "ESP",
            "ike_version": 2 if experiment["ike_version"] == "ikev2" else 1,
            "operating_mode": experiment["mode"],
            "nat_traversal": bool(experiment.get("nat_t", False)),
            "encapsulation": "UDP_4500" if experiment.get("nat_t") else "IP_PROTO_50"
        },
        "crypto_suite": experiment["crypto"],
        "traffic_profile": {
            "primary_class": experiment["traffic"],
            "is_mixed": experiment["traffic"] == "mixed"
        },
        "network_imperfections": {
            "has_handshake": experiment["has_handshake"],
            "latency_base_ms": netem["delay_ms"],
            "jitter_ms": netem["jitter_ms"],
            "packet_loss_pct": netem["loss_pct"],
            "reorder_pct": netem["reorder_pct"],
            "mtu": netem["mtu"],
            "background_noise": bool(experiment.get("background_noise", False))
        },
        "nist_sp800_77_compliance": compliance,
        "capture_statistics": stats
    }

    # 12. Save JSON Metadata
    with open(json_host_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"[+] SUCCESS: Capture recorded!")
    print(f"    File: {pcap_filename} ({stats.get('file_size_bytes', 0)} bytes)")
    print(f"    Total Packets: {stats['total_packets']} | IKE: {stats['ike_packets']} | ESP: {stats['esp_packets']}")
    print(f"    NIST SP 800-77 Status: {compliance['status']} (Score: {compliance['score']}/100)")
    return metadata


def build_experiment_matrix(profile="smoke"):
    """
    Constructs the test matrix based on requested profile:
    - smoke: 2 varied tests (validates pipeline)
    - quick: 8 tests covering primary ciphers, modes, and traffic types
    - full: complete exhaustive permutations
    """
    clean_net = {"delay_ms": 0, "jitter_ms": 0, "loss_pct": 0.0, "reorder_pct": 0.0, "mtu": 1500}
    wan_net = {"delay_ms": 25, "jitter_ms": 8, "loss_pct": 1.5, "reorder_pct": 1.0, "mtu": 1500}
    lossy_net = {"delay_ms": 60, "jitter_ms": 20, "loss_pct": 4.0, "reorder_pct": 2.0, "mtu": 1400}

    experiments = []

def build_massive_matrix():
    """
    Constructs an exhaustive, highly realistic 120-capture permutation matrix
    balanced across all 8 traffic classes, 6 cryptographic suites, 4 network
    impairment profiles, and operational edge-cases (mid-stream wiretaps, NAT-T).
    """
    traffic_classes = ["voip", "video", "web", "chat", "email", "bulk", "icmp", "mixed"]
    
    crypto_suites = [
        {
            "name": "AES-256-GCM (NIST SP 800-77 Standard)",
            "ike_version": "ikev2",
            "ike_cipher": "aes256-sha256-modp2048",
            "esp_cipher": "aes256gcm16-modp2048",
            "crypto": {
                "ike_encryption": "AES_CBC_256",
                "esp_encryption": "AES_GCM_16_256",
                "integrity": "HMAC_SHA2_256_128",
                "prf": "PRF_HMAC_SHA2_256",
                "dh_group": 14,
                "pfs_enabled": True
            }
        },
        {
            "name": "AES-128-GCM (AEAD Modern High-Throughput)",
            "ike_version": "ikev2",
            "ike_cipher": "aes128-sha256-modp2048",
            "esp_cipher": "aes128gcm16",
            "crypto": {
                "ike_encryption": "AES_CBC_128",
                "esp_encryption": "AES_GCM_16_128",
                "integrity": "HMAC_SHA2_256_128",
                "prf": "PRF_HMAC_SHA2_256",
                "dh_group": 14,
                "pfs_enabled": False
            }
        },
        {
            "name": "AES-256-CBC HMAC-SHA256 (Enterprise Standard)",
            "ike_version": "ikev2",
            "ike_cipher": "aes256-sha256-modp2048",
            "esp_cipher": "aes256-sha256-modp2048",
            "crypto": {
                "ike_encryption": "AES_CBC_256",
                "esp_encryption": "AES_CBC_256",
                "integrity": "HMAC_SHA2_256_128",
                "prf": "PRF_HMAC_SHA2_256",
                "dh_group": 14,
                "pfs_enabled": True
            }
        },
        {
            "name": "AES-128-CBC HMAC-SHA256 (PFS Disabled)",
            "ike_version": "ikev2",
            "ike_cipher": "aes128-sha256-modp2048",
            "esp_cipher": "aes128-sha256",
            "crypto": {
                "ike_encryption": "AES_CBC_128",
                "esp_encryption": "AES_CBC_128",
                "integrity": "HMAC_SHA2_256_128",
                "prf": "PRF_HMAC_SHA2_256",
                "dh_group": 14,
                "pfs_enabled": False
            }
        },
        {
            "name": "Legacy 3DES-CBC SHA1 (NIST Critical Fail)",
            "ike_version": "ikev1",
            "ike_cipher": "3des-sha1-modp1024",
            "esp_cipher": "3des-sha1",
            "crypto": {
                "ike_encryption": "3DES_CBC",
                "esp_encryption": "3DES_CBC",
                "integrity": "HMAC_SHA1_96",
                "prf": "PRF_HMAC_SHA1",
                "dh_group": 2,
                "pfs_enabled": False
            }
        },
        {
            "name": "Legacy 3DES-CBC MD5 (Sweet32 Vulnerable)",
            "ike_version": "ikev1",
            "ike_cipher": "3des-md5-modp1024",
            "esp_cipher": "3des-md5",
            "crypto": {
                "ike_encryption": "3DES_CBC",
                "esp_encryption": "3DES_CBC",
                "integrity": "HMAC_MD5_96",
                "prf": "PRF_HMAC_MD5",
                "dh_group": 2,
                "pfs_enabled": False
            }
        }
    ]

    netem_profiles = [
        {"name": "clean", "delay_ms": 0, "jitter_ms": 0, "loss_pct": 0.0, "reorder_pct": 0.0, "mtu": 1500},
        {"name": "wan_standard", "delay_ms": 25, "jitter_ms": 6, "loss_pct": 1.0, "reorder_pct": 1.0, "mtu": 1500},
        {"name": "wan_lossy", "delay_ms": 50, "jitter_ms": 15, "loss_pct": 3.0, "reorder_pct": 2.0, "mtu": 1440},
        {"name": "mobile_degraded", "delay_ms": 80, "jitter_ms": 25, "loss_pct": 4.5, "reorder_pct": 2.5, "mtu": 1380}
    ]

    experiments = []
    exp_idx = 1

    # 15 variations per traffic class = 120 total runs
    for traffic in traffic_classes:
        for i in range(15):
            crypto = crypto_suites[i % len(crypto_suites)]
            netem = netem_profiles[(i // 2) % len(netem_profiles)]
            mode = "tunnel" if (i % 2 == 0) else "transport"
            # 20% of flows have mid-stream capture (handshake missing)
            has_handshake = (i % 5 != 0)
            # 20% of flows use NAT-Traversal
            nat_t = (i % 4 == 0) and (mode == "tunnel")
            duration = random.choice([6, 7, 8])

            exp_id = f"exp_{exp_idx:03d}_{traffic}_{mode}_{crypto['crypto']['esp_encryption'].lower()}"
            name = f"[{exp_idx:03d}/120] {traffic.upper()} in {mode.upper()} Mode ({crypto['name']}, {netem['name']})"

            experiments.append({
                "id": exp_id,
                "name": name,
                "ike_version": crypto["ike_version"],
                "mode": mode,
                "ike_cipher": crypto["ike_cipher"],
                "esp_cipher": crypto["esp_cipher"],
                "nat_t": nat_t,
                "crypto": crypto["crypto"],
                "traffic": traffic,
                "netem": netem,
                "has_handshake": has_handshake,
                "background_noise": (i % 3 == 0),
                "duration": duration
            })
            exp_idx += 1

    return experiments


def build_experiment_matrix(profile="smoke"):
    """Constructs the test matrix based on requested profile."""
    if profile == "massive" or profile == "full":
        return build_massive_matrix()

    clean_net = {"delay_ms": 0, "jitter_ms": 0, "loss_pct": 0.0, "reorder_pct": 0.0, "mtu": 1500}
    wan_net = {"delay_ms": 25, "jitter_ms": 8, "loss_pct": 1.5, "reorder_pct": 1.0, "mtu": 1500}
    lossy_net = {"delay_ms": 60, "jitter_ms": 20, "loss_pct": 4.0, "reorder_pct": 2.0, "mtu": 1400}

    experiments = []

    # 1. Modern IKEv2 AES-GCM Tunnel Mode + VoIP
    experiments.append({
        "id": "ikev2_aes256gcm_dh14_tunnel_voip",
        "name": "IKEv2 AES-256-GCM Tunnel Mode with VoIP Stream",
        "ike_version": "ikev2",
        "mode": "tunnel",
        "ike_cipher": "aes256-sha256-modp2048",
        "esp_cipher": "aes256gcm16-modp2048",
        "crypto": {
            "ike_encryption": "AES_CBC_256",
            "esp_encryption": "AES_GCM_16_256",
            "integrity": "HMAC_SHA2_256_128",
            "prf": "PRF_HMAC_SHA2_256",
            "dh_group": 14,
            "pfs_enabled": True
        },
        "traffic": "voip",
        "netem": wan_net,
        "has_handshake": True,
        "background_noise": True,
        "duration": 8
    })

    # 2. Modern IKEv2 AES-128-GCM Transport Mode + Video Streaming
    experiments.append({
        "id": "ikev2_aes128gcm_dh14_transport_video",
        "name": "IKEv2 AES-128-GCM Transport Mode with Video Streaming",
        "ike_version": "ikev2",
        "mode": "transport",
        "ike_cipher": "aes128-sha256-modp2048",
        "esp_cipher": "aes128gcm16",
        "crypto": {
            "ike_encryption": "AES_CBC_128",
            "esp_encryption": "AES_GCM_16_128",
            "integrity": "HMAC_SHA2_256_128",
            "prf": "PRF_HMAC_SHA2_256",
            "dh_group": 14,
            "pfs_enabled": False
        },
        "traffic": "video",
        "netem": lossy_net,
        "has_handshake": True,
        "background_noise": True,
        "duration": 8
    })

    if profile == "smoke":
        return experiments

    # Quick profile: 8 core archetypes
    experiments.append({
        "id": "ikev2_aes256cbc_sha256_dh14_tunnel_web",
        "name": "IKEv2 AES-256-CBC HMAC-SHA256 Tunnel Mode with Web Browsing",
        "ike_version": "ikev2",
        "mode": "tunnel",
        "ike_cipher": "aes256-sha256-modp2048",
        "esp_cipher": "aes256-sha256-modp2048",
        "crypto": {
            "ike_encryption": "AES_CBC_256",
            "esp_encryption": "AES_CBC_256",
            "integrity": "HMAC_SHA2_256_128",
            "prf": "PRF_HMAC_SHA2_256",
            "dh_group": 14,
            "pfs_enabled": True
        },
        "traffic": "web",
        "netem": clean_net,
        "has_handshake": True,
        "background_noise": False,
        "duration": 8
    })

    experiments.append({
        "id": "ikev2_aes128gcm_natt_tunnel_chat",
        "name": "IKEv2 AES-128-GCM NAT-Traversal with WhatsApp/Chat Flow",
        "ike_version": "ikev2",
        "mode": "tunnel",
        "ike_cipher": "aes128-sha256-modp2048",
        "esp_cipher": "aes128gcm16-modp2048",
        "nat_t": True,
        "crypto": {
            "ike_encryption": "AES_CBC_128",
            "esp_encryption": "AES_GCM_16_128",
            "integrity": "HMAC_SHA2_256_128",
            "prf": "PRF_HMAC_SHA2_256",
            "dh_group": 14,
            "pfs_enabled": True
        },
        "traffic": "chat",
        "netem": wan_net,
        "has_handshake": True,
        "background_noise": True,
        "duration": 8
    })

    experiments.append({
        "id": "ikev2_aes256gcm_midstream_esponly_voip",
        "name": "IKEv2 AES-256-GCM Mid-Session Wiretap (Missing Handshake)",
        "ike_version": "ikev2",
        "mode": "tunnel",
        "ike_cipher": "aes256-sha256-modp2048",
        "esp_cipher": "aes256gcm16",
        "crypto": {
            "ike_encryption": "AES_CBC_256",
            "esp_encryption": "AES_GCM_16_256",
            "integrity": "HMAC_SHA2_256_128",
            "prf": "PRF_HMAC_SHA2_256",
            "dh_group": 14,
            "pfs_enabled": False
        },
        "traffic": "voip",
        "netem": clean_net,
        "has_handshake": False,
        "background_noise": False,
        "duration": 8
    })

    experiments.append({
        "id": "ikev1_3des_md5_dh2_tunnel_email",
        "name": "Legacy IKEv1 3DES-CBC MD5 DH-Group2 (NIST Critical Fail)",
        "ike_version": "ikev1",
        "mode": "tunnel",
        "ike_cipher": "3des-md5-modp1024",
        "esp_cipher": "3des-md5",
        "crypto": {
            "ike_encryption": "3DES_CBC",
            "esp_encryption": "3DES_CBC",
            "integrity": "HMAC_MD5_96",
            "prf": "PRF_HMAC_MD5",
            "dh_group": 2,
            "pfs_enabled": False
        },
        "traffic": "email",
        "netem": wan_net,
        "has_handshake": True,
        "background_noise": False,
        "duration": 8
    })

    experiments.append({
        "id": "ikev1_3des_sha1_dh2_tunnel_bulk",
        "name": "Legacy IKEv1 3DES-CBC SHA1 DH-Group2 with Bulk Transfer",
        "ike_version": "ikev1",
        "mode": "tunnel",
        "ike_cipher": "3des-sha1-modp1024",
        "esp_cipher": "3des-sha1",
        "crypto": {
            "ike_encryption": "3DES_CBC",
            "esp_encryption": "3DES_CBC",
            "integrity": "HMAC_SHA1_96",
            "prf": "PRF_HMAC_SHA1",
            "dh_group": 2,
            "pfs_enabled": False
        },
        "traffic": "bulk",
        "netem": wan_net,
        "has_handshake": True,
        "background_noise": False,
        "duration": 8
    })

    experiments.append({
        "id": "ikev2_aes256gcm_dh14_tunnel_mixed_lossy",
        "name": "IKEv2 AES-256-GCM Mixed (Web+Chat) on Lossy High-Jitter Link",
        "ike_version": "ikev2",
        "mode": "tunnel",
        "ike_cipher": "aes256-sha256-modp2048",
        "esp_cipher": "aes256gcm16-modp2048",
        "crypto": {
            "ike_encryption": "AES_CBC_256",
            "esp_encryption": "AES_GCM_16_256",
            "integrity": "HMAC_SHA2_256_128",
            "prf": "PRF_HMAC_SHA2_256",
            "dh_group": 14,
            "pfs_enabled": True
        },
        "traffic": "mixed",
        "netem": lossy_net,
        "has_handshake": True,
        "background_noise": True,
        "duration": 10
    })

    return experiments


def main():
    parser = argparse.ArgumentParser(description="Master IPsec Dataset Generator for SIH26160")
    parser.add_argument("--profile", choices=["smoke", "quick", "full", "massive"], default="massive",
                        help="Execution profile: smoke (2), quick (8), full/massive (120 exhaustive captures)")
    args = parser.parse_args()

    os.makedirs(DATASET_DIR, exist_ok=True)
    ensure_testbed_running()

    experiments = build_experiment_matrix(args.profile)
    total_exp = len(experiments)
    print(f"\n[Orchestrator] Prepared {total_exp} dataset generation experiments for profile '{args.profile}'.")

    results = []
    start_time = time.time()
    manifest_path = os.path.join(BASE_DIR, "dataset", "manifest.json")

    for idx, exp in enumerate(experiments, 1):
        elapsed = time.time() - start_time
        avg_per_exp = elapsed / max(1, idx - 1)
        remaining_secs = int(avg_per_exp * (total_exp - idx + 1)) if idx > 1 else int(total_exp * 12)
        rem_m, rem_s = divmod(remaining_secs, 60)
        pct = (idx / total_exp) * 100

        print(f"\n==========================================================================")
        print(f">>> [{idx}/{total_exp}] ({pct:.1f}%) | Elapsed: {int(elapsed//60)}m {int(elapsed%60)}s | ETA: {rem_m}m {rem_s}s")
        print(f"==========================================================================")

        try:
            res = run_single_capture_experiment(exp)
            results.append(res)
        except Exception as e:
            print(f"[!] Warning: Experiment {exp['id']} had error: {e}. Skipping and continuing...")

        # Incremental manifest save after each run
        with open(manifest_path, "w") as f:
            json.dump({
                "last_updated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "profile": args.profile,
                "completed_captures": len(results),
                "total_planned": total_exp,
                "captures": results
            }, f, indent=2)

        time.sleep(1.5)

    total_time = int(time.time() - start_time)
    print("\n==========================================================================")
    print(f"[+] MASSIVE DATASET GENERATION COMPLETE!")
    print(f"    Total Successful PCAPNG Files: {len(results)}/{total_exp}")
    print(f"    Total Elapsed Time: {total_time // 60}m {total_time % 60}s")
    print(f"    Dataset Location: {DATASET_DIR}")
    print(f"    Manifest: {manifest_path}")
    print("==========================================================================\n")



if __name__ == "__main__":
    main()
