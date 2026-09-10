#!/usr/bin/env python3
"""
Linux Traffic Control (tc-netem) Imperfections Controller.
Injects real-world network degradations into container interfaces:
- Latency & Gaussian Jitter
- Packet Loss & Drops
- Out-of-order Packet Reordering
- Packet Duplication & Bit Corruption
- MTU Truncation (inducing ESP fragmentation)
"""

import subprocess
import argparse
import sys

def run_cmd(cmd):
    """Executes a shell command and returns output."""
    res = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    return res.returncode == 0, res.stdout, res.stderr

def clear_netem(interface="eth0"):
    """Removes all netem impairment qdiscs from the interface."""
    run_cmd(f"tc qdisc del dev {interface} root 2>/dev/null")
    run_cmd(f"ip link set dev {interface} mtu 1500 2>/dev/null")
    print(f"[Netem] Cleared all impairments on {interface}.")

def apply_netem(interface="eth0", delay_ms=0, jitter_ms=0, loss_pct=0.0, reorder_pct=0.0, dup_pct=0.0, mtu=1500):
    """Applies combined network impairments using tc-netem."""
    clear_netem(interface)
    
    parts = []
    if delay_ms > 0:
        if jitter_ms > 0:
            parts.append(f"delay {delay_ms}ms {jitter_ms}ms distribution normal")
        else:
            parts.append(f"delay {delay_ms}ms")
            
    if loss_pct > 0.0:
        parts.append(f"loss {loss_pct}%")
        
    if reorder_pct > 0.0 and delay_ms > 0:
        parts.append(f"reorder {reorder_pct}% 50%")
        
    if dup_pct > 0.0:
        parts.append(f"duplicate {dup_pct}%")
        
    if parts:
        netem_cmd = f"tc qdisc add dev {interface} root netem " + " ".join(parts)
        ok, out, err = run_cmd(netem_cmd)
        if not ok:
            print(f"[Netem Error] Failed to apply netem: {err}")
            return False
        print(f"[Netem] Applied: {netem_cmd}")
        
    if mtu != 1500:
        ok, out, err = run_cmd(f"ip link set dev {interface} mtu {mtu}")
        if ok:
            print(f"[Netem] Set MTU to {mtu} on {interface}")
            
    return True

def main():
    parser = argparse.ArgumentParser(description="Linux tc-netem Network Imperfections Controller")
    parser.add_argument("--interface", default="eth0", help="Target network interface (default: eth0)")
    parser.add_argument("--clear", action="store_true", help="Clear all impairments")
    parser.add_argument("--delay", type=int, default=0, help="Base latency in ms")
    parser.add_argument("--jitter", type=int, default=0, help="Latency jitter in ms")
    parser.add_argument("--loss", type=float, default=0.0, help="Packet loss percentage")
    parser.add_argument("--reorder", type=float, default=0.0, help="Packet reordering percentage")
    parser.add_argument("--dup", type=float, default=0.0, help="Packet duplication percentage")
    parser.add_argument("--mtu", type=int, default=1500, help="Interface MTU (default: 1500)")

    args = parser.parse_args()

    if args.clear:
        clear_netem(args.interface)
        return

    apply_netem(
        interface=args.interface,
        delay_ms=args.delay,
        jitter_ms=args.jitter,
        loss_pct=args.loss,
        reorder_pct=args.reorder,
        dup_pct=args.dup,
        mtu=args.mtu
    )

if __name__ == "__main__":
    main()
