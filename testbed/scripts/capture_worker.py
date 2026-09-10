#!/usr/bin/env python3
"""
Packet Sniffer & Ground-Truth Annotation Worker.
Captures network traffic on container interfaces to .pcapng files
and outputs rich ground-truth JSON metadata.
"""

import subprocess
import argparse
import time
import json
import os
import sys

def start_capture(interface, output_path):
    """Starts asynchronous tcpdump capture in .pcapng or .pcap format."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    # Using tcpdump with pcap format (compatible with pcapng / Wireshark)
    cmd = [
        "tcpdump", "-i", interface, "-s", "0", "-w", output_path, "-U"
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Give tcpdump half a second to initialize the libpcap ring buffer
    time.sleep(0.5)
    return proc

def stop_capture(proc):
    """Gracefully terminates tcpdump process."""
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    time.sleep(0.5)

def analyze_capture_stats(pcap_path):
    """Analyzes captured file to count packets and verify presence of IKE and ESP frames."""
    total_packets = 0
    ike_packets = 0
    esp_packets = 0

    if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) == 0:
        return {"total_packets": 0, "ike_packets": 0, "esp_packets": 0}

    # Count with tshark or tcpdump -r
    cmd = f"tcpdump -r {pcap_path} -nn -q 2>/dev/null"
    res = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    lines = res.stdout.strip().split("\n") if res.stdout.strip() else []
    
    total_packets = len(lines)
    for line in lines:
        if "500" in line or "4500" in line or "ISAKMP" in line:
            ike_packets += 1
        elif "ESP(" in line or "proto ESP" in line:
            esp_packets += 1

    return {
        "total_packets": total_packets,
        "ike_packets": ike_packets,
        "esp_packets": esp_packets,
        "file_size_bytes": os.path.getsize(pcap_path)
    }

def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer Worker")
    parser.add_argument("--action", choices=["start", "stop", "stats"], required=True)
    parser.add_argument("--interface", default="eth0")
    parser.add_argument("--output", required=True)
    
    args = parser.parse_args()

    if args.action == "stats":
        stats = analyze_capture_stats(args.output)
        print(json.dumps(stats, indent=2))

if __name__ == "__main__":
    main()
