#!/usr/bin/env python3
"""
SIH26160 IPsec Traffic Analysis - Advanced Feature Extraction Engine
Extracts 48 temporal, spatial, directional, spectral, entropy, and concurrency features
from encrypted IPsec PCAPNG captures using sliding time windows.
"""

import os
import sys
import glob
import json
import argparse
import numpy as np
import pandas as pd
from scipy import stats
from scapy.all import rdpcap, IP, UDP, ESP


NUMERIC_FEATURES = [
    # Volume & Rate Features (5)
    'pkt_count', 'byte_count', 'duration_sec', 'byte_rate', 'pkt_rate',
    # Packet Length Distribution & Fine-Grained Percentiles (11)
    'pkt_len_mean', 'pkt_len_std', 'pkt_len_min', 'pkt_len_max',
    'pkt_len_median', 'pkt_len_q05', 'pkt_len_q10', 'pkt_len_q25', 'pkt_len_q75', 'pkt_len_q90', 'pkt_len_q95',
    # Shape, Entropy & Sequence Autocorrelation (4)
    'pkt_len_skew', 'pkt_len_kurtosis', 'pkt_len_entropy', 'pkt_len_autocorr',
    # Inter-Arrival Time (IAT) Statistics & Pacing (11)
    'iat_mean', 'iat_std', 'iat_min', 'iat_max',
    'iat_q10', 'iat_q25', 'iat_q50', 'iat_q75', 'iat_q90', 'iat_entropy', 'burstiness_coeff',
    # Burstiness & Idle Dynamics (3)
    'idle_ratio', 'burst_count', 'burst_mean_pkts',
    # Directional & Asymmetry Dynamics (6)
    'fwd_pkt_ratio', 'fwd_byte_ratio', 'bwd_pkt_ratio', 'bwd_byte_ratio',
    'fwd_bwd_iat_ratio', 'fwd_bwd_byte_skew',
    # Concurrency, Bimodality & Protocol Archetypes (6)
    'small_pkt_ratio', 'med_pkt_ratio', 'large_pkt_ratio', 'bimodal_index',
    'tcp_like_ack_ratio', 'mtu_saturation_ratio',
    # ESP / Tunnel Health Indicators (2)
    'esp_spi_count', 'seq_gap_rate'
]

FEATURE_COLUMNS = [
    # Session / Window metadata
    'capture_id', 'window_idx', 'is_full_session',
] + NUMERIC_FEATURES + [
    # Ground Truth Labels
    'label_class', 'label_mode', 'label_ike', 'label_crypto', 'label_nist', 'is_mixed'
]


def extract_packet_metadata(packets):
    """
    Extract raw lightweight metadata array from Scapy packets:
    (timestamp, wire_len, is_forward, is_esp, spi, seq_num)
    """
    records = []
    if not packets:
        return records

    first_time = float(packets[0].time)

    for pkt in packets:
        try:
            t = float(pkt.time) - first_time
            wire_len = len(pkt)
            is_fwd = 1
            is_esp = 0
            spi = 0
            seq_num = 0

            if IP in pkt:
                ip = pkt[IP]
                # Check if traffic originates from initiator 172.28.0.2
                if ip.src == "172.28.0.2":
                    is_fwd = 1
                elif ip.dst == "172.28.0.2":
                    is_fwd = 0

            # Detect ESP layer directly or inside UDP 4500
            if ESP in pkt:
                is_esp = 1
                try:
                    spi = int(pkt[ESP].spi)
                    seq_num = int(pkt[ESP].seq)
                except Exception:
                    pass
            elif IP in pkt and pkt[IP].proto == 50:
                is_esp = 1

            records.append((t, wire_len, is_fwd, is_esp, spi, seq_num))
        except Exception:
            continue

    return records


def compute_shannon_entropy(data, bins=10):
    """Computes Shannon entropy over histogram bins."""
    if len(data) < 2:
        return 0.0
    counts, _ = np.histogram(data, bins=bins)
    probs = counts[counts > 0] / len(data)
    return float(-np.sum(probs * np.log2(probs)))


def compute_window_features(records, window_idx, is_full_session, labels):
    """
    Computes 48 advanced statistical features for a slice of packet records.
    """
    if not records:
        return None

    # Arrays
    times = np.array([r[0] for r in records], dtype=np.float64)
    lens = np.array([r[1] for r in records], dtype=np.float64)
    fwds = np.array([r[2] for r in records], dtype=np.int32)
    esps = np.array([r[3] for r in records], dtype=np.int32)
    spis = [r[4] for r in records if r[3] == 1 and r[4] != 0]
    seqs = [r[5] for r in records if r[3] == 1]

    pkt_count = len(records)
    byte_count = float(np.sum(lens))
    duration = float(times[-1] - times[0]) if pkt_count > 1 else 0.001
    duration = max(duration, 0.001)

    byte_rate = byte_count / duration
    pkt_rate = pkt_count / duration

    # 1. Packet Length Distribution & Fine-Grained Percentiles
    pkt_len_mean = float(np.mean(lens))
    pkt_len_std = float(np.std(lens)) if pkt_count > 1 else 0.0
    pkt_len_min = float(np.min(lens))
    pkt_len_max = float(np.max(lens))
    pkt_len_median = float(np.median(lens))
    pkt_len_q05 = float(np.percentile(lens, 5))
    pkt_len_q10 = float(np.percentile(lens, 10))
    pkt_len_q25 = float(np.percentile(lens, 25))
    pkt_len_q75 = float(np.percentile(lens, 75))
    pkt_len_q90 = float(np.percentile(lens, 90))
    pkt_len_q95 = float(np.percentile(lens, 95))

    # Skewness & Kurtosis
    if pkt_count > 2 and pkt_len_std > 1e-6:
        try:
            pkt_len_skew = float(stats.skew(lens))
            pkt_len_kurtosis = float(stats.kurtosis(lens))
            if np.isnan(pkt_len_skew): pkt_len_skew = 0.0
            if np.isnan(pkt_len_kurtosis): pkt_len_kurtosis = 0.0
        except Exception:
            pkt_len_skew = 0.0
            pkt_len_kurtosis = 0.0
    else:
        pkt_len_skew = 0.0
        pkt_len_kurtosis = 0.0

    # Shannon Entropy of packet lengths
    pkt_len_entropy = compute_shannon_entropy(lens, bins=12)

    # Lag-1 Autocorrelation of packet sizes (detects request-response alternation)
    if pkt_count > 3 and pkt_len_std > 1e-5:
        try:
            ac = np.corrcoef(lens[:-1], lens[1:])[0, 1]
            pkt_len_autocorr = float(ac) if not np.isnan(ac) else 0.0
        except Exception:
            pkt_len_autocorr = 0.0
    else:
        pkt_len_autocorr = 0.0

    # 2. Inter-Arrival Times (IAT) & Pacing Statistics
    if pkt_count > 1:
        iats = np.diff(times)
        iats = np.clip(iats, 0.0, 10.0)
        iat_mean = float(np.mean(iats))
        iat_std = float(np.std(iats))
        iat_min = float(np.min(iats))
        iat_max = float(np.max(iats))
        iat_q10 = float(np.percentile(iats, 10))
        iat_q25 = float(np.percentile(iats, 25))
        iat_q50 = float(np.percentile(iats, 50))
        iat_q75 = float(np.percentile(iats, 75))
        iat_q90 = float(np.percentile(iats, 90))
        iat_entropy = compute_shannon_entropy(iats, bins=10)
        burstiness_coeff = float(iat_std / (iat_mean + 1e-6))

        # Idle dynamics (fraction of window in gaps > 50ms)
        idle_time = float(np.sum(iats[iats > 0.050]))
        idle_ratio = float(idle_time / duration)

        # Burst dynamics (clusters of packets with IAT < 5ms)
        burst_mask = iats < 0.005
        burst_clusters = np.split(burst_mask, np.where(~burst_mask)[0])
        valid_bursts = [len(c) + 1 for c in burst_clusters if np.any(c)]
        burst_count = len(valid_bursts)
        burst_mean_pkts = float(np.mean(valid_bursts)) if valid_bursts else 1.0
    else:
        iat_mean = 0.0
        iat_std = 0.0
        iat_min = 0.0
        iat_max = 0.0
        iat_q10 = 0.0
        iat_q25 = 0.0
        iat_q50 = 0.0
        iat_q75 = 0.0
        iat_q90 = 0.0
        iat_entropy = 0.0
        burstiness_coeff = 0.0
        idle_ratio = 0.0
        burst_count = 0
        burst_mean_pkts = 1.0

    # 3. Directional & Asymmetry Dynamics
    fwd_mask = (fwds == 1)
    bwd_mask = (fwds == 0)
    fwd_count = np.sum(fwd_mask)
    bwd_count = np.sum(bwd_mask)

    fwd_pkt_ratio = float(fwd_count / pkt_count)
    bwd_pkt_ratio = float(bwd_count / pkt_count)

    fwd_bytes = float(np.sum(lens[fwd_mask])) if fwd_count > 0 else 0.0
    bwd_bytes = float(np.sum(lens[bwd_mask])) if bwd_count > 0 else 0.0
    fwd_byte_ratio = float(fwd_bytes / max(byte_count, 1.0))
    bwd_byte_ratio = float(bwd_bytes / max(byte_count, 1.0))
    fwd_bwd_byte_skew = float((fwd_bytes - bwd_bytes) / max(byte_count, 1.0))

    if fwd_count > 1 and bwd_count > 1:
        fwd_iats = np.diff(times[fwd_mask])
        bwd_iats = np.diff(times[bwd_mask])
        fwd_iat_m = np.mean(fwd_iats) if len(fwd_iats) > 0 else 1.0
        bwd_iat_m = np.mean(bwd_iats) if len(bwd_iats) > 0 else 1.0
        fwd_bwd_iat_ratio = float(fwd_iat_m / (bwd_iat_m + 1e-6))
    else:
        fwd_bwd_iat_ratio = 1.0

    # 4. Concurrency, Bimodality & Archetypes
    small_pkts = lens < 250.0       # VoIP audio frames, chat, TCP ACKs
    med_pkts = (lens >= 250.0) & (lens <= 900.0)  # Web text/JSON, small video
    large_pkts = lens > 900.0       # Full MTU downloads, video frames

    small_pkt_ratio = float(np.sum(small_pkts) / pkt_count)
    med_pkt_ratio = float(np.sum(med_pkts) / pkt_count)
    large_pkt_ratio = float(np.sum(large_pkts) / pkt_count)

    # Pure TCP-like ACK ratio (wire size 40-75 bytes)
    ack_like_pkts = (lens >= 40.0) & (lens <= 75.0)
    tcp_like_ack_ratio = float(np.sum(ack_like_pkts) / pkt_count)

    # MTU saturation ratio (packets >= 1350 bytes)
    mtu_pkts = lens >= 1350.0
    mtu_saturation_ratio = float(np.sum(mtu_pkts) / pkt_count)

    # Bimodality Index
    n_small = np.sum(small_pkts)
    n_large = np.sum(large_pkts)
    if n_small > 0 and n_large > 0 and pkt_len_std > 1e-5:
        mean_small = np.mean(lens[small_pkts])
        mean_large = np.mean(lens[large_pkts])
        bimodal_index = float(abs(mean_large - mean_small) / (pkt_len_std + 1e-5))
    else:
        bimodal_index = 0.0

    # 5. ESP / Tunnel Indicators
    esp_spi_count = len(set(spis))
    if len(seqs) > 1:
        seq_arr = np.array(seqs, dtype=np.int64)
        seq_diffs = np.diff(seq_arr)
        gaps = np.sum(seq_diffs != 1)
        seq_gap_rate = float(gaps / len(seq_diffs))
    else:
        seq_gap_rate = 0.0

    row = {
        'capture_id': labels.get('capture_id', 'unknown'),
        'window_idx': window_idx,
        'is_full_session': int(is_full_session),
        # Volume & Rates
        'pkt_count': pkt_count,
        'byte_count': byte_count,
        'duration_sec': duration,
        'byte_rate': byte_rate,
        'pkt_rate': pkt_rate,
        # Length Distribution
        'pkt_len_mean': pkt_len_mean,
        'pkt_len_std': pkt_len_std,
        'pkt_len_min': pkt_len_min,
        'pkt_len_max': pkt_len_max,
        'pkt_len_median': pkt_len_median,
        'pkt_len_q05': pkt_len_q05,
        'pkt_len_q10': pkt_len_q10,
        'pkt_len_q25': pkt_len_q25,
        'pkt_len_q75': pkt_len_q75,
        'pkt_len_q90': pkt_len_q90,
        'pkt_len_q95': pkt_len_q95,
        # Shape & Entropy
        'pkt_len_skew': pkt_len_skew,
        'pkt_len_kurtosis': pkt_len_kurtosis,
        'pkt_len_entropy': pkt_len_entropy,
        'pkt_len_autocorr': pkt_len_autocorr,
        # IAT Statistics
        'iat_mean': iat_mean,
        'iat_std': iat_std,
        'iat_min': iat_min,
        'iat_max': iat_max,
        'iat_q10': iat_q10,
        'iat_q25': iat_q25,
        'iat_q50': iat_q50,
        'iat_q75': iat_q75,
        'iat_q90': iat_q90,
        'iat_entropy': iat_entropy,
        'burstiness_coeff': burstiness_coeff,
        # Burst Dynamics
        'idle_ratio': idle_ratio,
        'burst_count': burst_count,
        'burst_mean_pkts': burst_mean_pkts,
        # Directional & Asymmetry
        'fwd_pkt_ratio': fwd_pkt_ratio,
        'fwd_byte_ratio': fwd_byte_ratio,
        'bwd_pkt_ratio': bwd_pkt_ratio,
        'bwd_byte_ratio': bwd_byte_ratio,
        'fwd_bwd_iat_ratio': fwd_bwd_iat_ratio,
        'fwd_bwd_byte_skew': fwd_bwd_byte_skew,
        # Concurrency & Archetypes
        'small_pkt_ratio': small_pkt_ratio,
        'med_pkt_ratio': med_pkt_ratio,
        'large_pkt_ratio': large_pkt_ratio,
        'bimodal_index': bimodal_index,
        'tcp_like_ack_ratio': tcp_like_ack_ratio,
        'mtu_saturation_ratio': mtu_saturation_ratio,
        # ESP
        'esp_spi_count': esp_spi_count,
        'seq_gap_rate': seq_gap_rate,
        # Labels
        'label_class': labels.get('primary_class', 'unknown'),
        'label_mode': labels.get('operating_mode', 'unknown'),
        'label_ike': labels.get('ike_version', 'unknown'),
        'label_crypto': labels.get('crypto_suite', 'unknown'),
        'label_nist': labels.get('nist_status', 'PASS'),
        'is_mixed': int(labels.get('is_mixed', False))
    }
    return row


def process_capture_file(pcap_path, window_size=1.5, step_size=0.75):
    """
    Processes one pcapng file and its associated JSON metadata.
    """
    json_path = pcap_path.replace('.pcapng', '.json')
    if not os.path.exists(json_path):
        return []

    try:
        with open(json_path, 'r') as jf:
            meta = json.load(jf)
    except Exception as e:
        print(f"[-] Error reading {json_path}: {e}")
        return []

    labels = {
        'capture_id': meta.get('capture_id', os.path.basename(pcap_path).replace('.pcapng', '')),
        'primary_class': meta.get('traffic_profile', {}).get('primary_class', 'unknown'),
        'is_mixed': meta.get('traffic_profile', {}).get('is_mixed', False),
        'operating_mode': meta.get('protocol_stack', {}).get('operating_mode', 'unknown'),
        'ike_version': f"ikev{meta.get('protocol_stack', {}).get('ike_version', 2)}",
        'crypto_suite': meta.get('crypto_suite', {}).get('esp_encryption', 'unknown'),
        'nist_status': meta.get('nist_sp800_77_compliance', {}).get('status', 'PASS')
    }

    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[-] Error parsing packets from {pcap_path}: {e}")
        return []

    if not packets:
        return []

    records = extract_packet_metadata(packets)
    if not records:
        return []

    rows = []

    # 1. Full session feature row (window_idx = -1)
    full_row = compute_window_features(records, window_idx=-1, is_full_session=True, labels=labels)
    if full_row:
        rows.append(full_row)

    # 2. Sliding time-window feature rows
    start_t = records[0][0]
    end_t = records[-1][0]
    total_dur = end_t - start_t

    if total_dur >= 0.5:
        curr_start = 0.0
        w_idx = 0
        while curr_start < total_dur:
            curr_end = curr_start + window_size
            w_recs = [r for r in records if curr_start <= r[0] < curr_end]
            if len(w_recs) >= 3:
                w_row = compute_window_features(w_recs, window_idx=w_idx, is_full_session=False, labels=labels)
                if w_row:
                    rows.append(w_row)
            curr_start += step_size
            w_idx += 1

    return rows


def extract_features_from_dataset(dataset_dir, output_csv, window_size=1.5, step_size=0.75, max_workers=4):
    """
    Iterates through all .pcapng files in dataset_dir and exports features.csv
    """
    pcap_files = sorted(glob.glob(os.path.join(dataset_dir, "*.pcapng")))
    print(f"[*] Found {len(pcap_files)} PCAPNG captures in {dataset_dir}")
    if not pcap_files:
        print("[-] No captures found!")
        return

    all_rows = []
    print(f"[*] Extracting 48 advanced features (window={window_size}s, step={step_size}s)...")

    completed = 0
    total = len(pcap_files)

    for pf in pcap_files:
        try:
            rows = process_capture_file(pf, window_size, step_size)
            all_rows.extend(rows)
            completed += 1
            if completed % 15 == 0 or completed == total:
                print(f"[+] Processed [{completed:3d}/{total:3d}] files -> {len(all_rows)} total feature windows")
        except Exception as e:
            print(f"[-] Failed processing {pf}: {e}")

    df = pd.DataFrame(all_rows, columns=FEATURE_COLUMNS)
    os.makedirs(os.path.dirname(os.path.abspath(output_csv)), exist_ok=True)
    df.to_csv(output_csv, index=False)
    print(f"\n[SUCCESS] Feature extraction completed!")
    print(f"          Total feature vectors generated: {len(df)}")
    print(f"          Output saved to: {output_csv}")
    print("\nClass distribution:")
    print(df['label_class'].value_counts())
    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SIH26160 IPsec Advanced Feature Extractor")
    parser.add_argument("--dataset-dir", default="dataset/raw_pcapng", help="Path to raw pcapng captures")
    parser.add_argument("--output", default="dataset/features.csv", help="Output CSV path")
    parser.add_argument("--window", type=float, default=1.5, help="Window size in seconds")
    parser.add_argument("--step", type=float, default=0.75, help="Window step size in seconds")
    args = parser.parse_args()

    extract_features_from_dataset(args.dataset_dir, args.output, args.window, args.step)
