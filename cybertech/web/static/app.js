/**
 * Cyber Tech — Frontend Forensic Dashboard Controller
 * Connects to REST API endpoints and updates the interactive security scanner.
 */

document.addEventListener("DOMContentLoaded", () => {
  const sampleListContainer = document.getElementById("sample-list-container");
  const pcapSearch = document.getElementById("pcap-search");
  const scannerPlaceholder = document.getElementById("scanner-placeholder");
  const scannerResults = document.getElementById("scanner-results");

  // Tabs
  const tabPresets = document.getElementById("tab-presets");
  const tabUpload = document.getElementById("tab-upload");
  const viewPresets = document.getElementById("view-presets");
  const viewUpload = document.getElementById("view-upload");

  // Upload elements
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("pcap-file-input");
  const btnBrowseFile = document.getElementById("btn-browse-file");
  const uploadStatus = document.getElementById("upload-status");

  // Buttons
  const btnClearData = document.getElementById("btn-clear-data");
  const btnCopyConfig = document.getElementById("btn-copy-config");
  const btnInfo = document.getElementById("btn-info");
  const modalInfo = document.getElementById("modal-info");
  const modalClose = document.getElementById("modal-close");
  const btnQuickEnterprise = document.getElementById("btn-quick-enterprise");
  const btnQuickAttack = document.getElementById("btn-quick-attack");

  let allSamples = [];
  let currentReport = null;

  // -----------------------------------------------------------------------
  // Tab Switching
  // -----------------------------------------------------------------------
  tabPresets.addEventListener("click", () => {
    tabPresets.classList.add("active");
    tabUpload.classList.remove("active");
    viewPresets.classList.remove("hidden");
    viewUpload.classList.add("hidden");
  });

  tabUpload.addEventListener("click", () => {
    tabUpload.classList.add("active");
    tabPresets.classList.remove("active");
    viewUpload.classList.remove("hidden");
    viewPresets.classList.add("hidden");
  });

  // -----------------------------------------------------------------------
  // Load Preset Forensic Scenarios
  // -----------------------------------------------------------------------
  async function loadSamples() {
    try {
      const res = await fetch("/api/samples");
      allSamples = await res.json();
      renderSamples(allSamples);
    } catch (e) {
      sampleListContainer.innerHTML = `<div class="error-state">Failed to load preset scenarios: ${e.message}</div>`;
    }
  }

  function renderSamples(samples) {
    if (!samples || samples.length === 0) {
      sampleListContainer.innerHTML = `<div class="empty-state">No preset PCAP scenarios found.</div>`;
      return;
    }

    sampleListContainer.innerHTML = "";
    samples.forEach(sample => {
      const card = document.createElement("div");
      card.className = "scenario-card";
      card.dataset.filename = sample.filename;

      let pillClass = "pill-secure";
      if (sample.severity === "CRITICAL") pillClass = "pill-critical";
      else if (sample.severity === "HIGH") pillClass = "pill-high";

      card.innerHTML = `
        <div class="scenario-top">
          <span class="scenario-name">${escapeHtml(sample.name)}</span>
          <span class="scenario-pill ${pillClass}">${sample.severity}</span>
        </div>
        <div class="scenario-desc">${escapeHtml(sample.description)}</div>
      `;

      card.addEventListener("click", () => {
        document.querySelectorAll(".scenario-card").forEach(c => c.classList.remove("active"));
        card.classList.add("active");
        analyzeSample(sample.filename);
      });

      sampleListContainer.appendChild(card);
    });
  }

  // Filter Presets
  pcapSearch.addEventListener("input", (e) => {
    const q = e.target.value.toLowerCase();
    const filtered = allSamples.filter(s => 
      s.name.toLowerCase().includes(q) || 
      s.description.toLowerCase().includes(q) ||
      s.filename.toLowerCase().includes(q)
    );
    renderSamples(filtered);
  });

  // -----------------------------------------------------------------------
  // Run Analysis on Preset Sample
  // -----------------------------------------------------------------------
  async function analyzeSample(filename) {
    showLoading();
    try {
      const res = await fetch("/api/analyze-sample", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename })
      });
      const data = await res.json();
      if (data.error) {
        alert("Analysis Error: " + data.error);
        return;
      }
      renderReport(data);
    } catch (e) {
      alert("Failed to analyze scenario: " + e.message);
    }
  }

  // -----------------------------------------------------------------------
  // PCAP File Upload Handling
  // -----------------------------------------------------------------------
  btnBrowseFile.addEventListener("click", () => fileInput.click());
  dropzone.addEventListener("click", (e) => {
    if (e.target !== btnBrowseFile) fileInput.click();
  });

  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });
  dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      uploadFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files.length > 0) {
      uploadFile(e.target.files[0]);
    }
  });

  async function uploadFile(file) {
    const formData = new FormData();
    formData.append("file", file);

    uploadStatus.classList.remove("hidden");
    uploadStatus.textContent = `Ingesting & analyzing: ${file.name}...`;

    try {
      const res = await fetch("/api/upload", {
        method: "POST",
        body: formData
      });
      const data = await res.json();
      if (data.error) {
        uploadStatus.textContent = `Upload failed: ${data.error}`;
        return;
      }
      uploadStatus.textContent = `Analysis complete: ${file.name}`;
      renderReport(data);
    } catch (e) {
      uploadStatus.textContent = `Error: ${e.message}`;
    }
  }

  // -----------------------------------------------------------------------
  // Render Forensic Report
  // -----------------------------------------------------------------------
  function renderReport(report) {
    currentReport = report;
    scannerPlaceholder.classList.add("hidden");
    scannerResults.classList.remove("hidden");

    const score = report.posture_score || {};
    const risk = report.risk_classification || {};
    const advisory = report.nlp_advisory || {};
    const meta = report.metadata || {};
    const emailMeta = report.email_analysis || {};
    const sTls = report.server_tls || {};
    const cTls = report.client_tls || {};
    const cert = report.certificate || {};
    const bchain = report.blockchain_evidence || {};

    // 1. Score & Grade Dial
    const grade = score.overall_grade || "F";
    const gradeBox = document.getElementById("score-grade-box");
    gradeBox.textContent = grade;

    let gradeColor = "#00e676"; // green
    if (grade === "A" || grade === "A+") gradeColor = "#00e676";
    else if (grade === "B" || grade === "C") gradeColor = "#fbbf24";
    else gradeColor = "#f43f5e";

    gradeBox.style.borderColor = gradeColor;
    gradeBox.style.color = gradeColor;
    gradeBox.style.boxShadow = `0 0 15px ${gradeColor}33`;

    document.getElementById("score-num").textContent = score.overall_score || 0;

    // 2. Risk Overview
    const riskPill = document.getElementById("risk-pill");
    const predRisk = risk.predicted_risk || "EVALUATING";
    riskPill.textContent = predRisk;
    if (predRisk === "SECURE") {
      riskPill.style.background = "rgba(0, 230, 118, 0.15)";
      riskPill.style.color = "#00e676";
    } else if (predRisk === "CRITICAL") {
      riskPill.style.background = "rgba(244, 63, 94, 0.15)";
      riskPill.style.color = "#f43f5e";
    } else {
      riskPill.style.background = "rgba(251, 191, 36, 0.15)";
      riskPill.style.color = "#fbbf24";
    }

    document.getElementById("executive-summary").textContent = advisory.executive_summary || "Session analyzed.";
    document.getElementById("meta-file").textContent = meta.filename || "--";
    document.getElementById("meta-packets").textContent = meta.total_packets || 0;
    document.getElementById("meta-duration").textContent = meta.duration_seconds || 0;

    // 3. Protocol & Downgrade
    document.getElementById("val-protocol").textContent = emailMeta.protocol || "UNKNOWN";
    document.getElementById("val-starttls-offered").textContent = emailMeta.starttls_offered ? "YES" : "NO";
    document.getElementById("val-starttls-initiated").textContent = emailMeta.starttls_initiated ? "YES" : "NO";

    const dgEl = document.getElementById("val-downgrade");
    if (emailMeta.starttls_downgraded) {
      dgEl.textContent = "DETECTED (STRIPPED)";
      dgEl.style.color = "#f43f5e";
    } else {
      dgEl.textContent = "None (Safe)";
      dgEl.style.color = "#00e676";
    }

    const authEl = document.getElementById("val-auth-leak");
    if (emailMeta.plaintext_auth_observed) {
      authEl.textContent = "LEAKED (AUTH LOGIN)";
      authEl.style.color = "#f43f5e";
    } else {
      authEl.textContent = "None (Encrypted)";
      authEl.style.color = "#00e676";
    }

    // 4. Cipher Suite & PFS
    document.getElementById("val-tls-version").textContent = sTls.version || cTls.version || "None";
    document.getElementById("val-cipher-name").textContent = sTls.cipher_name || "None Negotiated";

    const pfs = sTls.cipher_meta?.pfs;
    const pfsEl = document.getElementById("val-pfs");
    if (pfs) {
      pfsEl.textContent = "ENABLED (ECDHE)";
      pfsEl.style.color = "#00e676";
    } else {
      pfsEl.textContent = "DISABLED (Static RSA)";
      pfsEl.style.color = "#f43f5e";
    }

    const enc = sTls.cipher_meta?.enc || "N/A";
    const mac = sTls.cipher_meta?.mac || "N/A";
    document.getElementById("val-enc-mac").textContent = `${enc} / ${mac}`;

    const vulns = sTls.cipher_meta?.vulns || [];
    const cveEl = document.getElementById("val-cve-flags");
    if (vulns.length > 0) {
      cveEl.textContent = vulns.join(", ");
      cveEl.style.color = "#f43f5e";
    } else {
      cveEl.textContent = "None (Clean)";
      cveEl.style.color = "#00e676";
    }

    // 5. X.509 Certificate
    if (cert && cert.subject) {
      document.getElementById("val-cert-subject").textContent = cert.subject.CN || "Unknown Subject";
      document.getElementById("val-cert-issuer").textContent = cert.issuer.CN || "Unknown Issuer";
      document.getElementById("val-cert-bits").textContent = `${cert.public_key_bits || 0} bits (${cert.public_key_algorithm || "Unknown"})`;
      document.getElementById("val-cert-sig").textContent = cert.signature_algorithm || "Unknown";
      document.getElementById("val-cert-valid").textContent = cert.is_expired ? "EXPIRED" : "VALID";
      document.getElementById("val-cert-valid").style.color = cert.is_expired ? "#f43f5e" : "#00e676";
    } else {
      document.getElementById("val-cert-subject").textContent = "No Certificate";
      document.getElementById("val-cert-issuer").textContent = "--";
      document.getElementById("val-cert-bits").textContent = "--";
      document.getElementById("val-cert-sig").textContent = "--";
      document.getElementById("val-cert-valid").textContent = "--";
    }

    // 6. JA3 & Anomaly
    const anomaly = report.anomaly_detection || {};
    document.getElementById("val-anomaly-level").textContent = anomaly.anomaly_level || "NORMAL";
    document.getElementById("val-anomaly-score").textContent = anomaly.anomaly_score || "0.00";
    document.getElementById("val-sni").textContent = cTls.sni || "None";
    document.getElementById("val-ja3-md5").textContent = cTls.ja3_hash || "--";
    document.getElementById("val-ja3-512").textContent = cTls.ja3_512 || "--";

    // 7. Blockchain Evidence Seal
    document.getElementById("seal-block-idx").textContent = `#${bchain.block_index || 1}`;
    document.getElementById("seal-block-hash").textContent = bchain.block_hash || "--";
    document.getElementById("seal-merkle-root").textContent = bchain.merkle_root || "--";
    document.getElementById("mini-block-hash").textContent = bchain.block_hash ? bchain.block_hash.substring(0, 48) + "..." : "Awaiting Ingestion";

    // 8. Remediation Playbook
    const postfixConfig = advisory.hardening_playbook?.postfix || "";
    const dovecotConfig = advisory.hardening_playbook?.dovecot || "";
    document.getElementById("remediation-text").textContent = postfixConfig + "\n" + dovecotConfig;
  }

  function showLoading() {
    scannerPlaceholder.classList.remove("hidden");
    scannerResults.classList.add("hidden");
    scannerPlaceholder.innerHTML = `
      <div class="placeholder-graphic">
        <div class="pulse-indicator" style="width: 24px; height: 24px; margin: 0 auto 16px;"></div>
      </div>
      <h3>Dissecting Packets & Evaluating Cryptographic Handshakes...</h3>
      <p>Running pure-Python stream reassembly, JA3-512 hashing, X.509 ASN.1 parsing, and AI classification.</p>
    `;
  }

  // -----------------------------------------------------------------------
  // Helper Controls
  // -----------------------------------------------------------------------
  btnClearData.addEventListener("click", () => {
    scannerResults.classList.add("hidden");
    scannerPlaceholder.classList.remove("hidden");
    scannerPlaceholder.innerHTML = `
      <div class="placeholder-graphic">
        <svg width="60" height="60" viewBox="0 0 24 24" fill="none" stroke="#334155" stroke-width="1.5">
          <circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>
        </svg>
      </div>
      <h3>Select a Scenario or Upload PCAP to Trigger Real-Time Inspection</h3>
      <p>The forensic engine will reconstruct the TCP session, evaluate cryptographic handshakes, run AI risk classification, and generate the posture score.</p>
    `;
    document.querySelectorAll(".scenario-card").forEach(c => c.classList.remove("active"));
    document.getElementById("mini-block-hash").textContent = "Awaiting Forensic Stream Ingestion...";
  });

  btnCopyConfig.addEventListener("click", () => {
    const text = document.getElementById("remediation-text").textContent;
    navigator.clipboard.writeText(text).then(() => {
      btnCopyConfig.textContent = "Copied!";
      setTimeout(() => { btnCopyConfig.textContent = "Copy Hardened Config"; }, 2000);
    });
  });

  // Quick Action Navbar Buttons
  btnQuickEnterprise.addEventListener("click", () => {
    analyzeSample("enterprise_smtps_hardened.pcap");
  });

  btnQuickAttack.addEventListener("click", () => {
    analyzeSample("mitm_starttls_stripping_attack.pcap");
  });

  // Info Modal
  btnInfo.addEventListener("click", () => modalInfo.classList.remove("hidden"));
  modalClose.addEventListener("click", () => modalInfo.classList.add("hidden"));
  modalInfo.addEventListener("click", (e) => {
    if (e.target === modalInfo) modalInfo.classList.add("hidden");
  });

  function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  // Auto-load presets
  loadSamples();
});
