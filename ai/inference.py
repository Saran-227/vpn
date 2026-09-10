#!/usr/bin/env python3
"""
SIH26160 IPsec Traffic Analysis - Inference & Traffic De-Multiplexing Engine
Performs real-time AI classification on arbitrary encrypted .pcapng files.
Outputs predicted profile, confidence score, full probability distribution,
operational mode (Tunnel vs Transport), and concurrent application breakdown.
"""

import os
import sys
import json
import argparse
import numpy as np
import pandas as pd
import joblib

from features.extractor import process_capture_file, NUMERIC_FEATURES, compute_window_features, extract_packet_metadata
from scapy.all import rdpcap


class IPsecClassifier:
    def __init__(self, models_dir="models"):
        self.models_dir = models_dir
        self.traffic_model = joblib.load(os.path.join(models_dir, "traffic_classifier.joblib"))
        self.mode_model = joblib.load(os.path.join(models_dir, "mode_classifier.joblib"))
        self.le_class = joblib.load(os.path.join(models_dir, "label_encoder_class.joblib"))
        self.le_mode = joblib.load(os.path.join(models_dir, "label_encoder_mode.joblib"))
        with open(os.path.join(models_dir, "feature_columns.json"), "r") as f:
            self.features = json.load(f)

    def predict_pcap(self, pcap_path, window_size=1.5, step_size=0.75):
        """
        Runs multi-class classification and concurrent traffic decomposition.
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        packets = rdpcap(pcap_path)
        if not packets:
            return {"error": "Empty PCAP file"}

        records = extract_packet_metadata(packets)
        if not records:
            return {"error": "No IP/ESP packets found in capture"}

        # Extract session-level features
        dummy_labels = {'capture_id': os.path.basename(pcap_path)}
        session_feat = compute_window_features(records, window_idx=-1, is_full_session=True, labels=dummy_labels)
        if not session_feat:
            return {"error": "Failed to compute session features"}

        # Format input vector
        x_session = np.array([[session_feat.get(col, 0.0) for col in self.features]], dtype=np.float64)
        x_session = np.nan_to_num(x_session, nan=0.0, posinf=0.0, neginf=0.0)

        # 1. Operational Mode Prediction (Tunnel vs Transport)
        mode_idx = self.mode_model.predict(x_session)[0]
        mode_probs = self.mode_model.predict_proba(x_session)[0]
        predicted_mode = self.le_mode.inverse_transform([mode_idx])[0]
        mode_conf = float(mode_probs[mode_idx])

        # 2. Multi-Class Traffic Profile Prediction
        class_idx = self.traffic_model.predict(x_session)[0]
        class_probs = self.traffic_model.predict_proba(x_session)[0]
        predicted_class = self.le_class.inverse_transform([class_idx])[0]
        class_conf = float(class_probs[class_idx])

        # Probabilities for each class
        prob_dist = {}
        for cls_name, prob in zip(self.le_class.classes_, class_probs):
            prob_dist[cls_name] = round(float(prob), 4)

        # Sort classes by probability
        ranked_classes = sorted(prob_dist.items(), key=lambda x: x[1], reverse=True)
        top1_class, top1_prob = ranked_classes[0]
        top2_class, top2_prob = ranked_classes[1]

        # Concurrency / De-multiplexing Analysis:
        # Detect if multiple applications are actively interleaved inside the tunnel
        is_concurrent = False
        concurrent_apps = []

        if top1_class == 'mixed':
            is_concurrent = True
            concurrent_apps = [ranked_classes[1][0], ranked_classes[2][0]]
        elif top2_prob >= 0.20:
            # Significant secondary traffic presence
            is_concurrent = True
            concurrent_apps = [top1_class, top2_class]
        else:
            concurrent_apps = [top1_class]

        # 3. Windowed Temporal Breakdown (Timeline Slices)
        timeline = []
        start_t = records[0][0]
        end_t = records[-1][0]
        total_dur = max(end_t - start_t, 0.001)

        if total_dur >= 0.5:
            curr_start = 0.0
            w_idx = 0
            while curr_start < total_dur:
                curr_end = curr_start + window_size
                w_recs = [r for r in records if curr_start <= r[0] < curr_end]
                if len(w_recs) >= 3:
                    w_feat = compute_window_features(w_recs, window_idx=w_idx, is_full_session=False, labels=dummy_labels)
                    if w_feat:
                        x_win = np.array([[w_feat.get(col, 0.0) for col in self.features]], dtype=np.float64)
                        x_win = np.nan_to_num(x_win, nan=0.0, posinf=0.0, neginf=0.0)
                        w_cls_idx = self.traffic_model.predict(x_win)[0]
                        w_cls_probs = self.traffic_model.predict_proba(x_win)[0]
                        w_pred = self.le_class.inverse_transform([w_cls_idx])[0]
                        w_conf = float(w_cls_probs[w_cls_idx])
                        timeline.append({
                            "window_idx": w_idx,
                            "time_offset_sec": round(curr_start, 2),
                            "duration_sec": round(min(window_size, total_dur - curr_start), 2),
                            "packet_count": len(w_recs),
                            "predicted_class": w_pred,
                            "confidence": round(w_conf, 4)
                        })
                curr_start += step_size
                w_idx += 1

        result = {
            "pcap_file": os.path.basename(pcap_path),
            "total_packets": len(packets),
            "session_duration_sec": round(session_feat['duration_sec'], 2),
            "average_bytes_sec": round(session_feat['byte_rate'], 1),
            "traffic_classification": {
                "predicted_primary_profile": predicted_class,
                "confidence_score": round(class_conf, 4),
                "is_concurrent_traffic": is_concurrent,
                "active_applications": concurrent_apps,
                "probability_distribution": prob_dist,
                "ranked_classes": [{"class": c, "probability": p} for c, p in ranked_classes]
            },
            "operational_mode": {
                "predicted_mode": predicted_mode,
                "confidence_score": round(mode_conf, 4)
            },
            "key_flow_metrics": {
                "mean_packet_length": round(session_feat['pkt_len_mean'], 1),
                "packet_length_std": round(session_feat['pkt_len_std'], 1),
                "mean_iat_ms": round(session_feat['iat_mean'] * 1000, 2),
                "burstiness_index": round(session_feat['burstiness_coeff'], 2),
                "small_packet_ratio": round(session_feat['small_pkt_ratio'], 3),
                "large_packet_ratio": round(session_feat['large_pkt_ratio'], 3),
                "bimodal_index": round(session_feat['bimodal_index'], 2),
                "esp_spi_count": session_feat['esp_spi_count'],
                "sequence_gap_rate": round(session_feat['seq_gap_rate'], 4)
            },
            "temporal_window_breakdown": timeline[:10]  # First 10 time slices
        }
        return result


def main():
    parser = argparse.ArgumentParser(description="SIH26160 IPsec Traffic Inference Engine")
    parser.add_argument("--pcap", required=True, help="Path to input .pcapng file")
    parser.add_argument("--models-dir", default="models", help="Directory containing trained models")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    classifier = IPsecClassifier(models_dir=args.models_dir)
    res = classifier.predict_pcap(args.pcap)

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print("\n=======================================================")
        print(f"  AI TRAFFIC INFERENCE REPORT: {res.get('pcap_file')}")
        print("=======================================================")
        print(f"Packets Analyzed: {res.get('total_packets')} | Duration: {res.get('session_duration_sec')}s | Throughput: {res.get('average_bytes_sec')} B/s\n")
        
        tc = res.get('traffic_classification', {})
        print(f"Predicted Profile : {tc.get('predicted_primary_profile').upper()} (Confidence: {tc.get('confidence_score')*100:.1f}%)")
        print(f"Concurrent Traffic: {'YES' if tc.get('is_concurrent_traffic') else 'NO'}")
        print(f"Active Apps       : {', '.join(tc.get('active_applications', []))}")
        
        op = res.get('operational_mode', {})
        print(f"Operating Mode    : {op.get('predicted_mode').upper()} (Confidence: {op.get('confidence_score')*100:.1f}%)\n")

        print("Probability Distribution:")
        for r in tc.get('ranked_classes', []):
            bar = '#' * int(r['probability'] * 30)
            print(f"  {r['class']:8s} : {r['probability']*100:5.1f}% | {bar}")

        print("\nKey Flow Statistics:")
        kf = res.get('key_flow_metrics', {})
        print(f"  Mean Pkt Size  : {kf.get('mean_packet_length')} B (+/- {kf.get('packet_length_std')} B)")
        print(f"  Mean IAT       : {kf.get('mean_iat_ms')} ms (Burstiness: {kf.get('burstiness_index')})")
        print(f"  Small/Large Pkt: {kf.get('small_packet_ratio')*100:.1f}% small / {kf.get('large_packet_ratio')*100:.1f}% large")
        print(f"  Bimodal Index  : {kf.get('bimodal_index')} (Concurrency signature)")


if __name__ == "__main__":
    main()
