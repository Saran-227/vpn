# Problem Statement SIH26160: AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

- **Problem Statement ID:** SIH26160
- **Title:** AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
- **Organization / Department:** National Technical Research Organisation (NTRO)
- **Category:** Software
- **Theme:** Blockchain & Cybersecurity
- **Reference URL:** https://sih.euome.com/SIH26160

---

## 1. Official Problem Description (NTRO)

### Background
Virtual Private Networks (VPNs) are fundamental to secure communication over untrusted networks. Among the available VPN technologies, IPsec is widely adopted across enterprise, government, military, and cloud infrastructures because of its ability to provide confidentiality, integrity, and authentication.

However, the security of an IPsec deployment depends on multiple factors, including the chosen cryptographic algorithms, authentication mechanisms, key exchange protocols, and operational mode (Tunnel or Transport). Misconfigurations, outdated cipher suites, improper key management, or protocol implementation flaws can significantly weaken the overall security posture.

Traditional protocol analysis tools provide packet-level visibility but often require expert interpretation. There is a growing need for intelligent systems capable of automatically analyzing IPsec deployments, identifying protocol characteristics, assessing security risks, and generating actionable recommendations.

### Description
Design and develop an AI-driven protocol analysis platform capable of automatically analysing IPsec VPN deployments established under different security configurations. The platform should inspect captured traffic or live network streams, identify protocol characteristics, infer VPN operating modes, evaluate cryptographic configurations, and generate an automated security assessment report.

The solution should assist analysts in understanding the security posture of IPsec deployments without requiring manual packet inspection.

### Core Tasks Breakdown
- **a) VPN Testbed Generation:** Develop a laboratory environment capable of establishing IPsec VPNs using multiple configurations. Variations include:
  - Tunnel Mode & Transport Mode
  - Encryption: AES-128, AES-256, AES-GCM, AES-CBC + HMAC
  - Key Exchange: Different DH Groups (Diffie-Hellman)
  - Perfect Forward Secrecy (PFS): Enabled / Disabled
  - Protocols: IPv4 and IPv6 communication
  - Traffic Types: VoIP, WhatsApp, E-mail, Web-browsing, ICMP, Video streaming, etc.
- **b) Traffic Capture:** Acquire network traces using tools such as Wireshark, TCP-dump, and Custom packet capture utilities. Captured dataset should include:
  - IKE negotiation
  - ESP packets
  - AH packets (optional)
  - Normal communication
- **c) AI-Based Protocol Identification:** Develop an AI engine capable of automatically identifying:
  - IPsec protocol
  - IKE version
  - Tunnel Mode vs. Transport Mode
  - Encryption algorithm
  - Authentication algorithm
  - Key exchange method
  - Security Association (SA) characteristics
  - Predict Type of traffic inside ESP-IPsec
- **d) Security Assessment:** Automatically evaluate:
  - Cryptographic strength
  - Configuration compliance
  - Security Association parameters
  - Key lifetime
  - Replay protection
  - Forward Secrecy configuration
  - Cipher suite strength
  - Metadata exposure
- **e) Output & Expected Deliverables:**
  - Comprehensive security score, traffic analysis, and metadata inference
  - Automatically generated Executive Report & Technical Report
  - Risk Score & Threat Matrix
  - AI Confidence Score
  - Working software prototype
  - AI classification engine
  - Interactive dashboard
  - Demonstration video & Technical documentation
  - Dataset used for training/testing

---

## 2. System Architecture & Technical Blueprint

### Recommended Approach: Hybrid Architecture
1. **Deterministic Dissection Engine:**
   - Parses unencrypted IKE handshakes (`UDP 500/4500`, `IKE_SA_INIT`, `ISAKMP`) using PyShark / Scapy to extract exact cipher suites, DH groups, PRF, and SA parameters with 100% mathematical precision.
2. **Encrypted ESP ML Feature Engine:**
   - Extracts 29 statistical flow features (packet size histograms, inter-arrival times, burstiness, directional byte ratios) from encrypted ESP packets (IP Protocol 50) where Deep Packet Inspection (DPI) is mathematically impossible without keys.
   - Dual-stage model: Random Forest / XGBoost for Tunnel vs. Transport mode inference, and 1D-CNN / XGBoost for inner payload classification (VoIP, Video, Web, Email, ICMP).
3. **Security Audit & Compliance Engine:**
   - Automatically cross-references cipher suites and SA parameters against **NIST SP 800-77 Rev. 1** (Guide to IPsec VPNs) and **NSA CNSA 2.0**.
   - Flags deprecated/weak primitives (DES, 3DES, MD5, SHA-1, DH groups < 14, disabled PFS).
   - Generates quantitative Risk Score (0-100), Threat Matrix, and NIST Compliance status.
4. **Presentation & Reporting Layer:**
   - Modern React.js UI dashboard with real-time stream visualizers, flow breakdown, confidence gauges, and risk heatmaps.
   - Automated PDF report generator (Executive summary + Technical deep-dive with remediation steps).

---

## 3. Technology Stack

| Layer | Selected Technology | Purpose |
|---|---|---|
| **Testbed Environment** | Docker + strongSwan (`swanctl`) | Automated multi-configuration IPsec tunnel generator |
| **Packet Dissection** | Python 3.12 + PyShark + Scapy | IKE/ESP/AH packet capture and proposal parsing |
| **AI / ML Engine** | PyTorch (1D-CNN) + XGBoost + Scikit-Learn | Encrypted ESP traffic classification & mode prediction |
| **Backend API** | FastAPI + Uvicorn | Asynchronous processing, streaming WebSocket, REST API |
| **Frontend Dashboard**| React + Vite + TailwindCSS + Recharts | Interactive analyst workspace and threat visualization |
| **Storage / Cache** | SQLite (Local/Demo) / PostgreSQL | Flow metadata, audit logs, and compliance records |
| **Reporting** | ReportLab (Python) | High-precision Executive & Technical PDF export |

---

## 4. Key Constraints & Design Principles

1. **Air-Gapped / Offline-Ready:** Operational environments for NTRO require zero external cloud API dependencies. All models, rules, and scripts run fully local.
2. **Deterministic vs. AI Separation:**
   - **Never use AI to guess IKE parameters** when they exist in plaintext packet headers (prevent hallucinations).
   - **Use AI specifically where payloads are encrypted** (traffic fingerprinting and missing handshake recovery).
3. **Fail-Safe Security Scoring:** If parameters are missing or uncertain, the framework assigns conservative warning flags rather than falsely declaring an insecure link as passing.
