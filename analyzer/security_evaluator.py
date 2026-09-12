#!/usr/bin/env python3
"""
SIH26160 IPsec Protocol Analyzer - NIST SP 800-77 Rev. 1 Security Evaluator
Evaluates negotiated cryptographic suites against NIST SP 800-77 Rev. 1 and NSA CNSA Suite standards.
Computes quantitative Risk Scores (0-100), identifies CWEs/CVEs, and produces actionable defense advisories.
"""

import os
import sys
import json
import argparse

from analyzer.ike_parser import parse_ipsec_pcap
from ai.inference import IPsecClassifier


class NISTSecurityEvaluator:
    """
    Automated Cryptographic Compliance Evaluator based on NIST SP 800-77 Rev. 1
    (Guide to IPsec VPNs) and NIST SP 800-131A Rev. 2 (Transitioning Cryptographic Algorithms).
    """

    def evaluate_pcap(self, pcap_path, models_dir="models"):
        """
        Executes end-to-end security assessment:
          1. Deterministic IKE Protocol Parsing
          2. NIST SP 800-77 Cryptographic Compliance Audit
          3. AI Encrypted Traffic Classification & De-multiplexing
        """
        # 1. Deterministic IKE parsing
        ike_data = parse_ipsec_pcap(pcap_path)
        
        # 2. Cryptographic Security Assessment
        crypto_assessment = self._audit_crypto_parameters(ike_data)

        # 3. AI Traffic Profile Inference
        try:
            classifier = IPsecClassifier(models_dir=models_dir)
            ai_inference = classifier.predict_pcap(pcap_path)
        except Exception as e:
            ai_inference = {"error": f"AI inference failed: {str(e)}"}

        esp_summary = ike_data.get("esp_stream_summary", {})
        report = {
            "pcap_file": os.path.basename(pcap_path),
            "executive_summary": {
                "compliance_status": crypto_assessment["compliance_status"],
                "risk_score": crypto_assessment["risk_score"],
                "risk_level": crypto_assessment["risk_level"],
                "nist_sp800_77_posture": crypto_assessment["posture_label"],
                "handshake_observed": ike_data.get("handshake_detected", False),
                "predicted_application": ai_inference.get("traffic_classification", {}).get("display_profile") or ai_inference.get("traffic_classification", {}).get("predicted_primary_profile", "unknown"),
                "is_concurrent": ai_inference.get("traffic_classification", {}).get("is_concurrent_traffic", False),
                "active_apps": ai_inference.get("traffic_classification", {}).get("active_applications", []),
                "operational_mode": ai_inference.get("operational_mode", {}).get("predicted_mode", "unknown"),
                "mode_confidence": ai_inference.get("operational_mode", {}).get("confidence_score", 0.0),
                "total_packets": ike_data.get("total_packets", 0),
                "ike_packets": ike_data.get("ike_packet_count", 0),
                "esp_packets": esp_summary.get("total_esp_packets", 0),
                "session_duration_sec": ai_inference.get("session_duration_sec", 0.0),
                "active_payload_duration_sec": ai_inference.get("active_payload_duration_sec", 0.0),
                "control_plane_summary": ike_data.get("control_plane_summary", "N/A"),
                "active_spis": esp_summary.get("unique_spis", []),
                "spi_pair": esp_summary.get("spi_pair_display", "None Observed"),
                "auth_method": ike_data.get("auth_method", "Pre-Shared Key (PSK) - Authentication Succeeded"),
                "key_lifetime": ike_data.get("key_lifetime", "Autonomous Local Gateway Policy (RFC 7296 unnegotiated on wire; typical default ~3600s / 4GB)"),
                "pfs_status": ike_data.get("pfs_status", "DISABLED"),
                "pfs_details": ike_data.get("pfs_details", "No secondary DH exchange"),
                "replay_protection": ike_data.get("replay_protection", {}).get("description", "N/A"),
                "replay_window_width": ike_data.get("replay_protection", {}).get("window_bit_width", "Undeterminable via Passive Wiretap (Local Gateway Policy)")
            },
            "cryptographic_audit": crypto_assessment,
            "ike_protocol_details": ike_data,
            "ai_traffic_intelligence": ai_inference
        }
        return report

    def _audit_crypto_parameters(self, ike_data):
        score = 100
        violations = []
        warnings = []
        recommendations = []

        if not ike_data.get("handshake_detected"):
            # Mid-stream ESP wiretap case
            return {
                "compliance_status": "UNVERIFIED_HANDSHAKE",
                "risk_score": 50,
                "risk_level": "MEDIUM",
                "posture_label": "MID-STREAM ESP WIRETAP (NO IKE INTERCEPTED)",
                "violations": [
                    {
                        "vuln_id": "VULN-UNVERIFIED-SESSION",
                        "title": "Unobserved Key Exchange (Mid-Stream ESP Only)",
                        "severity": "MEDIUM",
                        "cwe": "CWE-311",
                        "description": "The packet capture intercepted ongoing ESP traffic mid-stream. The Phase 1 IKE negotiation was not observed on the wire, precluding cryptographic suite verification.",
                        "remediation": "Deploy continuous wiretap capture at session initialization or verify gateway configuration out-of-band."
                    }
                ],
                "recommendations": [
                    "Perform endpoint auditing of strongSwan / IPsec configuration files (`/etc/ipsec.conf` or `/etc/swanctl/`).",
                    "Monitor for subsequent IKE re-keying events (RFC 7296 CREATE_CHILD_SA) to capture future proposals."
                ]
            }

        proposals = ike_data.get("proposals", [])
        if not proposals:
            return {
                "compliance_status": "UNKNOWN",
                "risk_score": 50,
                "risk_level": "MEDIUM",
                "posture_label": "INCOMPLETE IKE PROPOSAL",
                "violations": [],
                "recommendations": []
            }

        # Check proposal 0
        prop = proposals[0]
        enc = str(prop.get("encryption", "")).upper()
        klen = prop.get("key_length")
        integ = str(prop.get("integrity", "")).upper()
        prf = str(prop.get("prf", "")).upper()
        dh_num = prop.get("dh_group_num")
        dh_name = str(prop.get("dh_group", ""))
        ike_ver = ike_data.get("ike_version")

        # 1. Protocol Version Audit
        if ike_ver == 1:
            score -= 20
            violations.append({
                "vuln_id": "VULN-LEGACY-IKEV1",
                "title": "Deprecated IKEv1 Protocol (RFC 9395)",
                "severity": "HIGH",
                "cwe": "CWE-327",
                "description": "IKEv1 is officially deprecated by the IETF (RFC 9395). Main Mode and Aggressive Mode are vulnerable to offline PSK dictionary attacks, lack DoS cookie protection, and lack integrated NAT-T support.",
                "remediation": "Migrate VPN gateway configurations to IKEv2 (RFC 7296)."
            })

        # 2. Encryption Cipher Audit (NIST SP 800-77 Section 3.1)
        if any(bad in enc for bad in ["3DES", "DES", "BLOWFISH", "RC5", "CAST"]):
            score -= 60
            violations.append({
                "vuln_id": "VULN-SWEET32-CIPHER",
                "title": f"Critical Weak Cipher: {enc} (Sweet32 Vulnerable)",
                "severity": "CRITICAL",
                "cwe": "CWE-327",
                "description": f"Cipher {enc} uses a 64-bit block size vulnerable to birthday collision attacks (Sweet32 - CVE-2016-2183), allowing plaintext recovery in high-volume tunnels. Banned by NIST SP 800-131A.",
                "remediation": "Immediately replace with AES-256-GCM or AES-128-GCM (NIST SP 800-77 compliant AEAD)."
            })
        elif "AES-CBC" in enc:
            if klen == 128:
                score -= 10
                warnings.append("AES-128-CBC is legacy baseline. AES-256-GCM is strongly recommended.")
            # Check for AEAD vs separate integrity
            if "SHA2" not in integ and "SHA384" not in integ and "SHA512" not in integ:
                score -= 25
                violations.append({
                    "vuln_id": "VULN-INSECURE-CBC-INTEG",
                    "title": "AES-CBC Missing Robust SHA-2 Integrity",
                    "severity": "HIGH",
                    "cwe": "CWE-327",
                    "description": "AES-CBC without strong SHA-2 MAC introduces padding oracle attack vulnerabilities (e.g. Lucky Thirteen - CVE-2013-0169).",
                    "remediation": "Transition to modern Authenticated Encryption with Associated Data (AEAD) such as AES-GCM."
                })
        elif "GCM" in enc or "POLY1305" in enc:
            recommendations.append("Authenticated Encryption with Associated Data (AEAD) is active (NIST SP 800-77 Preferred).")

        # 3. Hash / PRF / Integrity Audit
        if any(bad in integ or bad in prf for bad in ["MD5"]):
            score -= 50
            violations.append({
                "vuln_id": "VULN-BROKEN-MD5",
                "title": "Broken MD5 Cryptographic Hash in Use",
                "severity": "CRITICAL",
                "cwe": "CWE-328",
                "description": "MD5 hash algorithm is cryptographically broken with practical collision attacks. Completely banned by NIST SP 800-131A.",
                "remediation": "Upgrade PRF and integrity algorithms to HMAC-SHA-256 or HMAC-SHA-384."
            })
        elif any(bad in integ or bad in prf for bad in ["SHA1", "SHA_1", "SHA "]):
            score -= 30
            violations.append({
                "vuln_id": "VULN-SHATTERED-SHA1",
                "title": "Deprecated SHA-1 Integrity/PRF (SHAttered Vulnerable)",
                "severity": "HIGH",
                "cwe": "CWE-328",
                "description": "SHA-1 has demonstrated practical chosen-prefix collisions (SHAttered attack). Deprecated by NIST SP 800-131A for all federal uses.",
                "remediation": "Upgrade to SHA-256, SHA-384, or SHA-512."
            })

        # 4. Diffie-Hellman Key Exchange Audit (NIST SP 800-77 Table 1)
        if dh_num in [1, "1"] or "768" in dh_name:
            score -= 50
            violations.append({
                "vuln_id": "VULN-LOGJAM-DH1",
                "title": "Broken Diffie-Hellman Group 1 (768-bit MODP)",
                "severity": "CRITICAL",
                "cwe": "CWE-326",
                "description": "768-bit MODP offers less than 67 bits of security and can be factored in hours on consumer hardware.",
                "remediation": "Upgrade DH Group to Group 14 (MODP-2048) or Group 19 (ECP-256 / NIST P-256)."
            })
        elif dh_num in [2, "2"] or "1024" in dh_name:
            score -= 40
            violations.append({
                "vuln_id": "VULN-LOGJAM-DH2",
                "title": "Insecure Diffie-Hellman Group 2 (1024-bit MODP)",
                "severity": "CRITICAL",
                "cwe": "CWE-326",
                "description": "1024-bit MODP offers ~80 bits of security, vulnerable to state-sponsored precomputation attacks (Logjam attack). Deprecated by NIST in 2013.",
                "remediation": "Upgrade DH Group to Group 14 (MODP-2048) minimum or Group 19 (ECP-256)."
            })
        elif dh_num in [5, "5"] or "1536" in dh_name:
            score -= 20
            violations.append({
                "vuln_id": "VULN-WEAK-DH5",
                "title": "Deprecated Diffie-Hellman Group 5 (1536-bit MODP)",
                "severity": "MEDIUM",
                "cwe": "CWE-326",
                "description": "1536-bit MODP does not meet the 112-bit security requirement established by NIST SP 800-57 Part 1.",
                "remediation": "Upgrade to Group 14 (2048-bit) or Group 19 (ECP-256)."
            })
        elif dh_num in [14, 15, 16, 19, 20, 21, 31] or any(g in dh_name for g in ["2048", "3072", "4096", "ECP", "Curve25519"]):
            recommendations.append(f"Diffie-Hellman Group '{dh_name}' complies with NIST SP 800-77 Rev. 1 requirements.")

        # Final score normalization
        score = max(0, min(100, score))

        if score >= 85:
            status = "PASS"
            level = "LOW"
            posture = "COMPLIANT (SECURE DEFENSE POSTURE)"
        elif score >= 60:
            status = "WARNING"
            level = "MEDIUM"
            posture = "NON-COMPLIANT WITH WARNINGS (DEPRECATED CIPHERS)"
        else:
            status = "FAIL"
            level = "CRITICAL"
            posture = "CRITICAL COMPLIANCE FAILURE (ACTIVE EXPLOIT RISK)"

        return {
            "compliance_status": status,
            "risk_score": score,
            "risk_level": level,
            "posture_label": posture,
            "violations": violations,
            "warnings": warnings,
            "recommendations": recommendations,
            "negotiated_suite": {
                "encryption": enc,
                "key_length": klen,
                "integrity": integ,
                "prf": prf,
                "dh_group": dh_name or f"Group {dh_num}",
                "auth_method": ike_data.get("auth_method", "Pre-Shared Key (PSK) - Authentication Succeeded"),
                "key_lifetime": ike_data.get("key_lifetime", "Autonomous Local Gateway Policy (RFC 7296 unnegotiated on wire; typical default ~3600s / 4GB)"),
                "pfs_status": ike_data.get("pfs_status", "DISABLED"),
                "pfs_details": ike_data.get("pfs_details", "None"),
                "spi_pair": ike_data.get("esp_stream_summary", {}).get("spi_pair_display", "None Observed"),
                "replay_protection": ike_data.get("replay_protection", {}).get("description", "N/A"),
                "replay_window_width": ike_data.get("replay_protection", {}).get("window_bit_width", "Undeterminable via Passive Wiretap (Local Gateway Policy)"),
                "control_plane": ike_data.get("control_plane_summary", "N/A"),
                "ike_sa_proposal": ike_data.get("ike_sa_proposal"),
                "esp_child_sa_proposal": ike_data.get("esp_child_sa_proposal")
            }
        }


def print_audit_report(report):
    exec_sum = report.get("executive_summary", {})
    audit = report.get("cryptographic_audit", {})
    ai = report.get("ai_traffic_intelligence", {})
    tc = ai.get("traffic_classification", {})

    print("\n" + "="*70)
    print("      NATIONAL TECHNICAL RESEARCH ORGANISATION (NTRO) - CYBER DEFENSE")
    print("      IPsec VPN Protocol Security Assessment & AI Traffic Intelligence")
    print("="*70)
    print(f"Target PCAP:     {report.get('pcap_file')}")
    print(f"Total Packets:   {exec_sum.get('total_packets')} ({exec_sum.get('esp_packets')} ESP + {exec_sum.get('ike_packets')} IKE)")
    print(f"Session Duration:{ai.get('session_duration_sec', 0)}s (Active Payload: {ai.get('active_payload_duration_sec', 0)}s)")
    print(f"Control Plane:   {exec_sum.get('control_plane_summary')}")
    print(f"Active SPIs:     {exec_sum.get('spi_pair')}")
    print(f"Security Score:  {exec_sum.get('risk_score')}/100")
    print(f"Compliance:      {exec_sum.get('compliance_status')} [{exec_sum.get('risk_level')} RISK]")
    print(f"Security Posture:{exec_sum.get('nist_sp800_77_posture')}")
    print("-"*70)
    
    print("\n[+] CRYPTOGRAPHIC AUDIT (NIST SP 800-77 Rev. 1):")
    suite = audit.get("negotiated_suite", {})
    ike_prop = suite.get("ike_sa_proposal") or {}
    esp_prop = suite.get("esp_child_sa_proposal") or {}

    ike_cipher = ike_prop.get("encryption", suite.get("encryption", "N/A"))
    esp_cipher = esp_prop.get("encryption", suite.get("encryption", "N/A"))

    print(f"  IKE SA Cipher (Phase 1): {ike_cipher} (Key: {ike_prop.get('key_length', suite.get('key_length', 'N/A'))} bits)")
    print(f"  ESP SA Cipher (Phase 2): {esp_cipher} (Key: {esp_prop.get('key_length', suite.get('key_length', 'N/A'))} bits)")
    print(f"  Authentication Method  : {suite.get('auth_method')}")
    print(f"  Key Lifetime / Rekeying: {suite.get('key_lifetime')}")
    print(f"  Integrity / MAC Tag    : {suite.get('integrity')}")
    print(f"  PRF Function           : {suite.get('prf')}")
    print(f"  Diffie-Hellman Group   : {suite.get('dh_group')}")
    print(f"  Forward Secrecy (PFS)  : {suite.get('pfs_status')} ({suite.get('pfs_details')})")
    print(f"  Anti-Replay Window     : {suite.get('replay_protection')}")
    print(f"  Replay Buffer Bit-Width: {suite.get('replay_window_width')}")
    print(f"  Handshake Breakdown    : {suite.get('control_plane')}")

    vulns = audit.get("violations", [])
    if vulns:
        print(f"\n[!] IDENTIFIED THREATS & VULNERABILITIES ({len(vulns)}):")
        for idx, v in enumerate(vulns, 1):
            print(f"  {idx}. [{v['severity']}] {v['title']} ({v['cwe']})")
            print(f"     Description: {v['description']}")
            print(f"     Remediation: {v['remediation']}\n")
    else:
        print("\n[+] ZERO KNOWN CRYPTOGRAPHIC VULNERABILITIES DETECTED.")

    print("\n[+] AI ENCRYPTED TRAFFIC INTELLIGENCE:")
    pred_traffic = tc.get('display_profile') or tc.get('predicted_primary_profile', '').upper()
    print(f"  Predicted Traffic : {pred_traffic} (Confidence: {tc.get('confidence_score', 0)*100:.1f}%)")
    print(f"  Concurrent Flow   : {'YES (Multi-Application Multiplexing)' if tc.get('is_concurrent_traffic') else 'NO'}")
    print(f"  Active Apps       : {', '.join(tc.get('active_applications', []))}")
    print(f"  Tunnel Mode       : {exec_sum.get('operational_mode', '').upper()} (Confidence: {exec_sum.get('mode_confidence', 0)*100:.1f}%)")

    fdr = ai.get("flow_dynamics_reconciliation")
    if fdr:
        print("\n[+] FLOW DYNAMICS & PAYLOAD RECONCILIATION:")
        print(f"  Status            : {fdr.get('status')}")
        dyn = fdr.get('observed_wiretap_dynamics', {})
        print(f"  Observed Dynamics : Mean {dyn.get('mean_packet_size_b')}B, Std ±{dyn.get('size_dispersion_std_b')}B")
        print(f"  Payload Breakdown : {dyn.get('small_voice_frames_pct')}% Voice (<250B) + {dyn.get('large_mtu_frames_pct')}% MTU Data (>900B)")
        print(f"  Resolution        : {fdr.get('resolution')}")

    print("\nProbability Vector:")
    for r in tc.get('ranked_classes', [])[:4]:
        bar = '#' * int(r['probability'] * 25)
        print(f"  {r['class']:8s} : {r['probability']*100:5.1f}% | {bar}")
    print("="*70 + "\n")


def main():
    parser = argparse.ArgumentParser(description="SIH26160 NIST SP 800-77 Security Evaluator")
    parser.add_argument("--pcap", required=True, help="Path to .pcapng file")
    parser.add_argument("--models-dir", default="models", help="Trained models directory")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    evaluator = NISTSecurityEvaluator()
    report = evaluator.evaluate_pcap(args.pcap, models_dir=args.models_dir)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_audit_report(report)


if __name__ == "__main__":
    main()
