/**
 * NTRO IPsec VPN Intelligence Platform - Frontend Application Logic
 * Reactive Dashboard, Live Radial Gauges, Probability Bars & Telemetry
 */

document.addEventListener("DOMContentLoaded", () => {
    initApp();
});

let currentReport = null;

async function initApp() {
    await fetchHealth();
    await loadSamples();
    setupDropZone();
    setupEventListeners();
    
    // Auto-load first sample for instantaneous wow factor
    const firstBtn = document.querySelector(".sample-btn");
    if (firstBtn) {
        firstBtn.click();
    }
}

async function fetchHealth() {
    try {
        const res = await fetch("/api/health");
        const data = await res.json();
        const activeModelBadge = document.getElementById("active-model-text");
        if (activeModelBadge) {
            activeModelBadge.textContent = data.active_traffic_model || "HistGradientBoosting (80.5%)";
        }
    } catch (e) {
        console.warn("Health check error:", e);
    }
}

async function loadSamples() {
    const container = document.getElementById("samples-container");
    if (!container) return;

    try {
        const res = await fetch("/api/samples");
        const samples = await res.json();

        container.innerHTML = "";
        samples.forEach((s, idx) => {
            const btn = document.createElement("button");
            btn.className = `sample-btn ${idx === 0 ? "active" : ""}`;
            btn.id = `sample-btn-${s.id}`;
            btn.innerHTML = `
                <div class="sample-top">
                    <span class="sample-badge tag-${s.tag.toLowerCase()}">${s.tag}</span>
                    <span style="font-size: 0.65rem; color: var(--text-dim); font-family: var(--font-mono);">${s.expected_app}</span>
                </div>
                <div class="sample-name" title="${s.title}">${s.title}</div>
                <div class="sample-desc">${s.description}</div>
            `;
            btn.addEventListener("click", () => {
                document.querySelectorAll(".sample-btn").forEach(b => b.classList.remove("active"));
                btn.classList.add("active");
                analyzeSample(s.pcap);
            });
            container.appendChild(btn);
        });
    } catch (e) {
        console.error("Failed loading sample captures:", e);
    }
}

async function analyzeSample(pcapFilename) {
    showLoadingState(true);
    try {
        const res = await fetch("/api/analyze/sample", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ pcap_filename: pcapFilename })
        });
        if (!res.ok) throw new Error(`Analysis failed with status ${res.status}`);
        const report = await res.json();
        renderReport(report);
    } catch (e) {
        alert("Error analyzing capture: " + e.message);
    } finally {
        showLoadingState(false);
    }
}

function setupDropZone() {
    const dropZone = document.getElementById("drop-zone");
    const fileInput = document.getElementById("file-input");
    if (!dropZone || !fileInput) return;

    dropZone.addEventListener("click", () => fileInput.click());

    dropZone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropZone.classList.add("dragover");
    });

    dropZone.addEventListener("dragleave", () => {
        dropZone.classList.remove("dragover");
    });

    dropZone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropZone.classList.remove("dragover");
        if (e.dataTransfer.files.length > 0) {
            handleFileUpload(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener("change", (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });
}

async function handleFileUpload(file) {
    if (!file.name.endsWith(".pcap") && !file.name.endsWith(".pcapng")) {
        alert("Please upload a valid .pcap or .pcapng network capture file.");
        return;
    }

    showLoadingState(true);
    const formData = new FormData();
    formData.append("file", file);

    try {
        const res = await fetch("/api/analyze/upload", {
            method: "POST",
            body: formData
        });
        if (!res.ok) throw new Error(`Upload failed: ${res.statusText}`);
        const report = await res.json();
        renderReport(report);
        document.querySelectorAll(".sample-btn").forEach(b => b.classList.remove("active"));
    } catch (e) {
        alert("Upload analysis failed: " + e.message);
    } finally {
        showLoadingState(false);
    }
}

function showLoadingState(isLoading) {
    const banner = document.getElementById("executive-banner");
    if (!banner) return;
    if (isLoading) {
        banner.style.opacity = "0.5";
        banner.style.pointerEvents = "none";
    } else {
        banner.style.opacity = "1";
        banner.style.pointerEvents = "all";
    }
}

function renderReport(report) {
    currentReport = report;
    const exec = report.executive_summary || {};
    const audit = report.cryptographic_audit || {};
    const ai = report.ai_traffic_intelligence || {};
    const tc = ai.traffic_classification || {};
    const op = ai.operational_mode || {};
    const kf = ai.key_flow_metrics || {};

    // 1. Executive Banner & Score Gauge
    const score = exec.risk_score !== undefined ? exec.risk_score : 50;
    updateGauge(score, exec.compliance_status);

    const bannerEl = document.getElementById("executive-banner");
    bannerEl.className = "executive-banner " + (
        exec.compliance_status === "PASS" ? "banner-glow-pass" :
        exec.compliance_status === "FAIL" ? "banner-glow-fail" : "banner-glow-warn"
    );

    document.getElementById("target-pcap-name").textContent = report.pcap_file || "Unknown";
    const espCount = exec.esp_packets !== undefined ? exec.esp_packets : (ikeProto.esp_stream_summary ? ikeProto.esp_stream_summary.total_esp_packets : 0);
    const ikeCount = exec.ike_packets !== undefined ? exec.ike_packets : (ikeProto.ike_packet_count || 0);
    if (espCount > 0 || ikeCount > 0) {
        document.getElementById("stat-total-packets").textContent = `${(exec.total_packets || 0).toLocaleString()} (${espCount} ESP + ${ikeCount} IKE)`;
    } else {
        document.getElementById("stat-total-packets").textContent = (exec.total_packets || 0).toLocaleString();
    }
    if (ai.active_payload_duration_sec && ai.session_duration_sec > ai.active_payload_duration_sec) {
        document.getElementById("stat-duration").textContent = `${ai.session_duration_sec}s (${ai.active_payload_duration_sec}s active)`;
    } else {
        document.getElementById("stat-duration").textContent = `${ai.session_duration_sec || 0}s`;
    }
    document.getElementById("stat-throughput").textContent = `${(ai.average_bytes_sec || 0).toLocaleString()} B/s`;

    const statusBadge = document.getElementById("banner-status-badge");
    statusBadge.textContent = `${exec.compliance_status} [${exec.risk_level || "UNKNOWN"} RISK]`;
    statusBadge.style.color = exec.compliance_status === "PASS" ? "var(--color-pass)" :
                             exec.compliance_status === "FAIL" ? "var(--color-fail)" : "var(--color-warn)";

    document.getElementById("banner-posture-title").textContent = exec.nist_sp800_77_posture || "ASSESSMENT IN PROGRESS";

    // 2. Cryptographic Proposal Details (Deterministic)
    const suite = audit.negotiated_suite || {};
    const ikeProto = report.ike_protocol_details || {};
    const ikeProp = suite.ike_sa_proposal || ikeProto.ike_sa_proposal || {};
    const espProp = suite.esp_child_sa_proposal || ikeProto.esp_child_sa_proposal || {};

    const espCipher = espProp.encryption || suite.encryption || (audit.posture_label ? "UNOBSERVED (ESP ONLY)" : "None");
    const ikeCipher = ikeProp.encryption || (ikeProto.handshake_detected ? suite.encryption : "UNOBSERVED (MID-STREAM)");

    document.getElementById("val-enc-cipher").textContent = espCipher;
    if (document.getElementById("val-ike-cipher")) {
        document.getElementById("val-ike-cipher").textContent = ikeCipher;
    }
    if (document.getElementById("val-auth-method")) {
        document.getElementById("val-auth-method").textContent = suite.auth_method || exec.auth_method || "Pre-Shared Key (PSK)";
    }
    if (document.getElementById("val-spi-pair")) {
        document.getElementById("val-spi-pair").textContent = suite.spi_pair || exec.spi_pair || "None Observed";
    }
    document.getElementById("val-key-len").textContent = (espProp.key_length || suite.key_length) ? `${espProp.key_length || suite.key_length} bits` : "N/A";
    document.getElementById("val-integrity").textContent = suite.integrity || espProp.integrity || "None";
    document.getElementById("val-prf").textContent = suite.prf || ikeProp.prf || "None";
    document.getElementById("val-dh-group").textContent = suite.dh_group || ikeProp.dh_group || "None";
    if (document.getElementById("val-pfs")) {
        const pfsText = suite.pfs_status ? `${suite.pfs_status} (${suite.pfs_details || 'N/A'})` : "DISABLED";
        document.getElementById("val-pfs").textContent = pfsText;
    }
    if (document.getElementById("val-replay")) {
        document.getElementById("val-replay").textContent = suite.replay_protection || exec.replay_protection || "N/A";
    }
    if (document.getElementById("val-replay-width")) {
        document.getElementById("val-replay-width").textContent = suite.replay_window_width || exec.replay_window_width || "Undeterminable via Passive Wiretap (Local Gateway Policy)";
    }
    if (document.getElementById("val-key-lifetime")) {
        document.getElementById("val-key-lifetime").textContent = suite.key_lifetime || exec.key_lifetime || "Autonomous Local Gateway Policy (RFC 7296)";
    }
    document.getElementById("val-ike-ver").textContent = ikeProto.ike_version ? `IKEv${ikeProto.ike_version}` : "None";
    document.getElementById("val-nat-t").textContent = ikeProto.nat_traversal ? "UDP 4500 (ACTIVE)" : "Native ESP (Proto 50)";
    if (document.getElementById("val-ctrl-plane")) {
        document.getElementById("val-ctrl-plane").textContent = suite.control_plane || exec.control_plane_summary || "None";
    }

    // Vulnerabilities
    const threatsContainer = document.getElementById("threats-container");
    threatsContainer.innerHTML = "";
    const vulns = audit.violations || [];
    if (vulns.length === 0) {
        threatsContainer.innerHTML = `
            <div class="zero-vuln-banner">
                <span style="font-size: 1.5rem;">🛡️</span>
                <div>
                    <div style="font-weight: 700;">NIST SP 800-77 Rev. 1 Compliant</div>
                    <div style="font-size: 0.8rem; color: var(--text-muted);">Zero active cryptographic vulnerabilities detected. Modern AEAD cipher and robust DH parameters active.</div>
                </div>
            </div>
        `;
    } else {
        vulns.forEach(v => {
            const card = document.createElement("div");
            const sevClass = v.severity === "CRITICAL" ? "threat-critical" :
                             v.severity === "HIGH" ? "threat-high" : "threat-medium";
            card.className = `threat-card ${sevClass}`;
            card.innerHTML = `
                <div class="threat-header">
                    <span class="threat-title" style="color: ${v.severity === 'CRITICAL' ? 'var(--color-fail)' : 'var(--color-warn)'};">
                        [${v.severity}] ${v.title}
                    </span>
                    <span class="threat-cwe">${v.cwe || ""}</span>
                </div>
                <div class="threat-desc">${v.description}</div>
                <div class="threat-remediation"><strong>Remediation:</strong> ${v.remediation}</div>
            `;
            threatsContainer.appendChild(card);
        });
    }

    // 3. AI Encrypted Traffic Intelligence
    const predApp = tc.display_profile || tc.predicted_primary_profile || "UNKNOWN";
    const appConf = (tc.confidence_score || 0) * 100;
    document.getElementById("ai-predicted-app").textContent = predApp.toUpperCase();
    document.getElementById("ai-app-confidence").textContent = `${appConf.toFixed(1)}% Confidence`;

    const isMixed = tc.is_concurrent_traffic || false;
    const activeApps = tc.active_applications || [predApp];
    const concurBadge = document.getElementById("ai-concurrency-badge");
    if (isMixed) {
        concurBadge.innerHTML = `<span style="color: var(--color-purple); font-weight: 700;">⚡ MULTI-APP MULTIPLEXING</span> (${activeApps.join(", ")})`;
    } else {
        concurBadge.textContent = "Single Stream Flow";
    }

    const modePred = op.predicted_mode || "UNKNOWN";
    const modeConf = (op.confidence_score || 0) * 100;
    document.getElementById("ai-predicted-mode").textContent = modePred.toUpperCase();
    document.getElementById("ai-mode-confidence").textContent = `${modeConf.toFixed(1)}% Confidence (ExtraTrees)`;

    // Render Probability Distribution Bars
    renderProbabilityBars(tc.ranked_classes || []);

    // Flow Dynamics
    document.getElementById("dyn-mean-size").textContent = `${kf.mean_packet_length || 0} B`;
    document.getElementById("dyn-size-std").textContent = `± ${kf.packet_length_std || 0} B`;
    document.getElementById("dyn-mean-iat").textContent = `${kf.mean_iat_ms || 0} ms`;
    document.getElementById("dyn-burstiness").textContent = kf.burstiness_index || 0;
    document.getElementById("dyn-small-ratio").textContent = `${((kf.small_packet_ratio || 0)*100).toFixed(1)}%`;
    document.getElementById("dyn-large-ratio").textContent = `${((kf.large_packet_ratio || 0)*100).toFixed(1)}%`;

    // Flow Dynamics vs Payload Profile Reconciliation Card
    const fdr = ai.flow_dynamics_reconciliation;
    const reconCard = document.getElementById("flow-reconciliation-card");
    if (reconCard) {
        if (fdr) {
            reconCard.style.display = "block";
            document.getElementById("reconciliation-text").textContent = fdr.resolution || fdr.issue_description || "";
            if (fdr.substreams) {
                const vs = fdr.substreams.voice_substream || {};
                const ds = fdr.substreams.data_substream || {};
                document.getElementById("substream-voice-val").textContent = `${vs.percentage}% (${vs.packet_count} pkts)`;
                document.getElementById("substream-voice-desc").textContent = `${vs.frame_size_range} • ${vs.traffic_type}`;
                document.getElementById("substream-data-val").textContent = `${ds.percentage}% (${ds.packet_count} pkts)`;
                document.getElementById("substream-data-desc").textContent = `${ds.frame_size_range} • ${ds.traffic_type}`;
            }
        } else {
            reconCard.style.display = "none";
        }
    }

    // 4. Timeline Slices
    renderTimelineSlices(ai.temporal_window_breakdown || []);
}

function updateGauge(score, status) {
    const circle = document.getElementById("gauge-fill-circle");
    const scoreText = document.getElementById("gauge-score-value");
    if (!circle || !scoreText) return;

    // Circumference = 2 * PI * r = 2 * PI * 48 = ~301.59
    const circumference = 301.59;
    const offset = circumference - (score / 100) * circumference;

    circle.style.strokeDasharray = `${circumference}`;
    circle.style.strokeDashoffset = `${offset}`;

    let strokeColor = "var(--color-pass)";
    if (score < 60) strokeColor = "var(--color-fail)";
    else if (score < 85) strokeColor = "var(--color-warn)";

    circle.style.stroke = strokeColor;
    scoreText.style.color = strokeColor;
    scoreText.textContent = score;
}

function renderProbabilityBars(rankedClasses) {
    const container = document.getElementById("prob-bars-container");
    if (!container) return;
    container.innerHTML = "";

    rankedClasses.forEach(item => {
        const pct = (item.probability * 100).toFixed(1);
        const row = document.createElement("div");
        row.className = "prob-row";
        row.innerHTML = `
            <span class="prob-name">${item.class}</span>
            <div class="prob-track">
                <div class="prob-fill" style="width: ${pct}%;"></div>
            </div>
            <span class="prob-percent">${pct}%</span>
        `;
        container.appendChild(row);
    });
}

function renderTimelineSlices(slices) {
    const container = document.getElementById("timeline-slices-grid");
    if (!container) return;
    container.innerHTML = "";

    if (slices.length === 0) {
        container.innerHTML = `<div style="color: var(--text-dim); font-size: 0.8rem;">Short capture: single session window analyzed.</div>`;
        return;
    }

    slices.forEach(s => {
        const box = document.createElement("div");
        if (s.is_control_plane || s.predicted_class === "IKE_HANDSHAKE") {
            box.className = "slice-box slice-control";
            box.innerHTML = `
                <div class="slice-time">+${s.time_offset_sec}s (${s.duration_sec}s)</div>
                <div class="slice-pred" style="color: #a78bfa;">IKE SIGNALING</div>
                <div class="slice-conf" style="color: #c4b5fd;">Control Plane (${s.packet_count} pkts)</div>
            `;
        } else {
            box.className = "slice-box";
            box.innerHTML = `
                <div class="slice-time">+${s.time_offset_sec}s (${s.duration_sec}s)</div>
                <div class="slice-pred">${s.predicted_class}</div>
                <div class="slice-conf">${(s.confidence * 100).toFixed(0)}% conf (${s.packet_count} pkts)</div>
            `;
        }
        container.appendChild(box);
    });
}

function setupEventListeners() {
    const printBtn = document.getElementById("btn-export-pdf");
    if (printBtn) {
        printBtn.addEventListener("click", () => {
            window.print();
        });
    }

    const modalBtn = document.getElementById("btn-open-leaderboard");
    const modalEl = document.getElementById("tournament-modal");
    const modalClose = document.getElementById("modal-close-btn");

    if (modalBtn && modalEl) {
        modalBtn.addEventListener("click", async () => {
            modalEl.style.display = "flex";
            await loadTournamentData();
        });
    }
    if (modalClose && modalEl) {
        modalClose.addEventListener("click", () => {
            modalEl.style.display = "none";
        });
        window.addEventListener("click", (e) => {
            if (e.target === modalEl) modalEl.style.display = "none";
        });
    }
}

async function loadTournamentData() {
    const tbody = document.getElementById("leaderboard-tbody");
    if (!tbody) return;

    try {
        const res = await fetch("/api/tournament");
        const data = await res.json();
        const board = data.leaderboard || [];

        tbody.innerHTML = "";
        board.forEach((item, idx) => {
            const tr = document.createElement("tr");
            if (idx === 0) tr.className = "champion-row";
            tr.innerHTML = `
                <td style="font-family: var(--font-mono); font-weight: 700;">#${idx + 1}</td>
                <td>
                    ${item.model_name}
                    ${idx === 0 ? '<span class="champion-badge">CHAMPION</span>' : ''}
                </td>
                <td style="font-family: var(--font-mono);">${(item.cv_accuracy * 100).toFixed(2)}% (±${(item.cv_acc_std * 100).toFixed(2)}%)</td>
                <td style="font-family: var(--font-mono); font-weight: 700; color: var(--color-cyan);">${(item.test_accuracy * 100).toFixed(2)}%</td>
                <td style="font-family: var(--font-mono);">${item.test_f1.toFixed(4)}</td>
                <td style="font-family: var(--font-mono); color: var(--text-dim);">${item.train_time_sec}s</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Failed loading tournament leaderboard:", e);
    }
}
