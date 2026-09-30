/**
 * Cyber Tech — Frontend Forensic Dashboard Controller
 * Connects to REST API endpoints and updates the interactive security scanner.
 */

document.addEventListener("DOMContentLoaded", () => {
  const scenariosRow = document.getElementById("scenarios-row");
  const fileInput = document.getElementById("pcap-file-input");
  const btnUploadTrigger = document.getElementById("btn-upload-trigger");
  const uploadStatus = document.getElementById("upload-status");

  // Navbar Quick Action Buttons
  const btnQuickEnterprise = document.getElementById("btn-quick-enterprise");
  const btnQuickAttack = document.getElementById("btn-quick-attack");

  // Score Criteria Modal Buttons
  const btnScoreCriteria = document.getElementById("btn-score-criteria");
  const modalCriteria = document.getElementById("modal-criteria");
  const modalCriteriaClose = document.getElementById("modal-criteria-close");

  // System Architecture Info Modal Buttons
  const btnInfo = document.getElementById("btn-info");
  const modalInfo = document.getElementById("modal-info");
  const modalInfoClose = document.getElementById("modal-info-close");

  // Copy Syntax Button
  const btnCopySyntax = document.getElementById("btn-copy-syntax");

  let allSamples = [];

  // -----------------------------------------------------------------------
  // Modal Event Listeners
  // -----------------------------------------------------------------------
  if (btnScoreCriteria && modalCriteria) {
    btnScoreCriteria.addEventListener("click", () => {
      modalCriteria.classList.remove("hidden");
    });
  }

  if (modalCriteriaClose && modalCriteria) {
    modalCriteriaClose.addEventListener("click", () => {
      modalCriteria.classList.add("hidden");
    });
  }

  if (btnInfo && modalInfo) {
    btnInfo.addEventListener("click", () => {
      modalInfo.classList.remove("hidden");
    });
  }

  if (modalInfoClose && modalInfo) {
    modalInfoClose.addEventListener("click", () => {
      modalInfo.classList.add("hidden");
    });
  }

  // Close modals when clicking overlay background
  window.addEventListener("click", (e) => {
    if (e.target === modalCriteria) modalCriteria.classList.add("hidden");
    if (e.target === modalInfo) modalInfo.classList.add("hidden");
  });

  // -----------------------------------------------------------------------
  // Load and Render Preset Scenarios
  // -----------------------------------------------------------------------
  async function loadSamples() {
    try {
      const res = await fetch("/api/samples");
      allSamples = await res.json();
      renderScenarioChips(allSamples);

      // Auto-analyze the first hardened sample on page load
      if (allSamples.length > 0) {
        analyzeSample(allSamples[0].filename);
      }
    } catch (e) {
      if (scenariosRow) {
        scenariosRow.innerHTML = `<div class="scenario-loading" style="color:#f43f5e;">Failed to load preset scenarios: ${e.message}</div>`;
      }
    }
  }

  function renderScenarioChips(samples) {
    if (!scenariosRow) return;
    scenariosRow.innerHTML = "";

    samples.forEach((sample, idx) => {
      const chip = document.createElement("div");
      chip.className = `scenario-chip ${idx === 0 ? "active" : ""}`;
      chip.dataset.filename = sample.filename;

      let badgeClass = "chip-secure";
      if (sample.severity === "CRITICAL") badgeClass = "chip-critical";
      else if (sample.severity === "HIGH") badgeClass = "chip-high";

      chip.innerHTML = `
        <div class="scenario-chip-top">
          <span class="scenario-chip-title" title="${escapeHtml(sample.name)}">${escapeHtml(sample.name)}</span>
          <span class="scenario-chip-badge ${badgeClass}">${sample.severity}</span>
        </div>
        <div class="scenario-chip-desc">${escapeHtml(sample.description)}</div>
      `;

      chip.addEventListener("click", () => {
        document.querySelectorAll(".scenario-chip").forEach(c => c.classList.remove("active"));
        chip.classList.add("active");
        analyzeSample(sample.filename);
      });

      scenariosRow.appendChild(chip);
    });
  }

  // -----------------------------------------------------------------------
  // Analysis Trigger via REST API
  // -----------------------------------------------------------------------
  async function analyzeSample(filename) {
    try {
      const res = await fetch("/api/analyze-sample", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename })
      });
      const data = await res.json();
      if (data.error) {
        alert("Forensic Analysis Error: " + data.error);
        return;
      }
      renderReport(data);
    } catch (e) {
      console.error("Analysis execution error:", e);
    }
  }

  // -----------------------------------------------------------------------
  // File Upload Ingestion
  // -----------------------------------------------------------------------
  if (btnUploadTrigger && fileInput) {
    btnUploadTrigger.addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", (e) => {
      if (e.target.files && e.target.files.length > 0) {
        uploadPCAP(e.target.files[0]);
      }
    });
  }

  async function uploadPCAP(file) {
    if (!uploadStatus) return;
    uploadStatus.classList.remove("hidden");
    uploadStatus.textContent = `Ingesting & analyzing capture: ${file.name}...`;

    const formData = new FormData();
    formData.append("file", file);

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
      uploadStatus.textContent = `✓ Forensic analysis completed for: ${file.name}`;
      renderReport(data);
    } catch (e) {
      uploadStatus.textContent = `Upload error: ${e.message}`;
    }
  }

  // -----------------------------------------------------------------------
  // Render Forensic Analysis Report to UI
  // -----------------------------------------------------------------------
  function renderReport(report) {
    if (!report) return;

    const score = report.posture_score || {};
    const risk = report.risk_classification || {};
    const advisory = report.nlp_advisory || {};
    const meta = report.metadata || {};
    const emailMeta = report.email_analysis || {};
    const sTls = report.server_tls || {};
    const cTls = report.client_tls || {};
    const cert = report.certificate || {};
    const bchain = report.blockchain_evidence || {};
    const anomaly = report.anomaly_detection || {};

    // 1. Posture Score & Letter Grade
    const overallScore = score.overall_score || 0;
    const grade = score.overall_grade || "F";
    const gradeEl = document.getElementById("score-grade");
    const scoreNumEl = document.getElementById("score-number");

    if (gradeEl) {
      gradeEl.textContent = grade;
      let color = "#00e676";
      if (grade === "A" || grade === "A+") color = "#00e676";
      else if (grade === "B" || grade === "C") color = "#fbbf24";
      else color = "#f43f5e";

      gradeEl.style.borderColor = color;
      gradeEl.style.color = color;
      gradeEl.style.boxShadow = `0 0 20px ${color}33`;
    }

    if (scoreNumEl) scoreNumEl.textContent = overallScore;

    // 2. Breakdown Progress Bars
    const bk = score.breakdown || {};
    setBar("proto", bk.protocol || 0, 30);
    setBar("cipher", bk.cipher || 0, 25);
    setBar("kex", bk.kex || 0, 25);
    setBar("cert", bk.cert || 0, 20);

    // 3. Risk Badge & Executive Brief
    const riskBadge = document.getElementById("risk-badge");
    const predRisk = risk.predicted_risk || "EVALUATING";
    if (riskBadge) {
      riskBadge.textContent = predRisk;
      if (predRisk === "SECURE") {
        riskBadge.style.background = "rgba(0, 230, 118, 0.15)";
        riskBadge.style.color = "#00e676";
      } else if (predRisk === "CRITICAL") {
        riskBadge.style.background = "rgba(244, 63, 94, 0.15)";
        riskBadge.style.color = "#f43f5e";
      } else {
        riskBadge.style.background = "rgba(251, 191, 36, 0.15)";
        riskBadge.style.color = "#fbbf24";
      }
    }

    setText("executive-summary-text", advisory.executive_summary || "Session analyzed successfully.");
    setText("target-meta", `Target: ${meta.filename || "--"} | Packets: ${meta.total_packets || 0} | Duration: ${meta.duration_seconds || 0}s`);

    // 4. Protocol & STARTTLS State
    setText("val-proto", emailMeta.protocol || "UNKNOWN");
    setText("val-starttls-offered", emailMeta.starttls_offered ? "YES" : "NO");
    setText("val-starttls-initiated", emailMeta.starttls_initiated ? "YES" : "NO");

    const dgEl = document.getElementById("val-downgrade");
    if (dgEl) {
      if (emailMeta.starttls_downgraded) {
        dgEl.textContent = "STRIPPING ATTACK DETECTED";
        dgEl.style.color = "#f43f5e";
      } else {
        dgEl.textContent = "None (Safe Transition)";
        dgEl.style.color = "#00e676";
      }
    }

    const authEl = document.getElementById("val-auth-leak");
    if (authEl) {
      if (emailMeta.plaintext_auth_observed) {
        authEl.textContent = "LEAKED (AUTH LOGIN)";
        authEl.style.color = "#f43f5e";
      } else {
        authEl.textContent = "None (Encrypted Session)";
        authEl.style.color = "#00e676";
      }
    }

    const creds = emailMeta.credentials_leaked || [];
    setText("val-sniffed-creds", creds.length > 0 ? creds.join(", ") : "None Detected");

    // 5. TLS Dissection & Ciphers
    setText("val-tls-version", sTls.version || cTls.version || "None Negotiated");
    setText("val-cipher-name", sTls.cipher_name || "None Selected");

    const pfs = sTls.cipher_meta?.pfs;
    const pfsEl = document.getElementById("val-pfs");
    if (pfsEl) {
      pfsEl.textContent = pfs ? "ENABLED (ECDHE)" : "DISABLED (Static RSA)";
      pfsEl.style.color = pfs ? "#00e676" : "#f43f5e";
    }

    const enc = sTls.cipher_meta?.enc || "N/A";
    const mac = sTls.cipher_meta?.mac || "N/A";
    setText("val-enc-mac", `${enc} / ${mac}`);

    const vulns = sTls.cipher_meta?.vulns || [];
    const cveEl = document.getElementById("val-cve-flags");
    if (cveEl) {
      cveEl.textContent = vulns.length > 0 ? vulns.join(", ") : "None (Clean)";
      cveEl.style.color = vulns.length > 0 ? "#f43f5e" : "#00e676";
    }

    setText("val-ciphers-offered", `${cTls.ciphers_offered_count || 0} suites`);

    // 6. X.509 Certificate Chain
    if (cert && cert.subject) {
      setText("val-cert-subject", cert.subject.CN || "Unknown Subject");
      setText("val-cert-issuer", cert.issuer.CN || "Unknown Issuer");
      setText("val-cert-bits", `${cert.public_key_bits || 0} bits (${cert.public_key_algorithm || "Unknown"})`);
      setText("val-cert-sig", cert.signature_algorithm || "Unknown");
      const validEl = document.getElementById("val-cert-valid");
      if (validEl) {
        validEl.textContent = cert.is_expired ? "EXPIRED" : "VALID";
        validEl.style.color = cert.is_expired ? "#f43f5e" : "#00e676";
      }
      setText("val-cert-sha512", cert.sha512_fingerprint || "--");
    } else {
      setText("val-cert-subject", "No Certificate Handshake");
      setText("val-cert-issuer", "--");
      setText("val-cert-bits", "--");
      setText("val-cert-sig", "--");
      setText("val-cert-valid", "--");
      setText("val-cert-sha512", "--");
    }

    // 7. JA3 & Anomaly Detection
    setText("val-anomaly-level", anomaly.anomaly_level || "NORMAL");
    setText("val-anomaly-score", anomaly.anomaly_score != null ? anomaly.anomaly_score.toFixed(2) : "0.00");
    setText("val-sni", cTls.sni || "None");
    setText("val-ja3-md5", cTls.ja3_hash || "--");
    setText("val-ja3-512", cTls.ja3_512 || "--");
    const reasons = anomaly.reasons || [];
    setText("val-anomaly-reasons", reasons.length > 0 ? reasons.join("; ") : "Baseline nominal");

    // 8. Blockchain Ledger Seal
    setText("bchain-idx", `#${bchain.block_index != null ? bchain.block_index : 1}`);
    setText("bchain-block-hash", bchain.block_hash || "--");
    setText("bchain-merkle-root", bchain.merkle_root || "--");

    // 9. MITRE ATT&CK Threat Mapping
    const mitreTbody = document.getElementById("mitre-tbody");
    if (mitreTbody) {
      const mappings = advisory.mitre_mappings || [];
      if (mappings.length === 0) {
        mitreTbody.innerHTML = `<tr><td colspan="4" style="color: #64748b;">No active adversarial tactics or MITM techniques observed.</td></tr>`;
      } else {
        mitreTbody.innerHTML = mappings.map(m => `
          <tr>
            <td style="font-family: monospace; color: #00ffc2; font-weight: bold;">${escapeHtml(m.id)}</td>
            <td><strong>${escapeHtml(m.name)}</strong></td>
            <td>${escapeHtml(m.tactic)}</td>
            <td>${escapeHtml(m.description)}</td>
          </tr>
        `).join("");
      }
    }

    // 10. Hardening Playbook
    const pfx = advisory.hardening_playbook?.postfix || "";
    const dvc = advisory.hardening_playbook?.dovecot || "";
    setText("config-pre", (pfx + "\n" + dvc).trim());
  }

  // -----------------------------------------------------------------------
  // Helper Utilities
  // -----------------------------------------------------------------------
  function setBar(id, val, max) {
    const textEl = document.getElementById(`score-val-${id}`);
    const barEl = document.getElementById(`bar-${id}`);
    if (textEl) textEl.textContent = `${val}/${max}`;
    if (barEl) {
      const pct = Math.max(0, Math.min(100, (val / max) * 100));
      barEl.style.width = `${pct}%`;
    }
  }

  function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  // Copy Syntax Action
  if (btnCopySyntax) {
    btnCopySyntax.addEventListener("click", () => {
      const text = document.getElementById("config-pre")?.textContent || "";
      navigator.clipboard.writeText(text).then(() => {
        btnCopySyntax.textContent = "Copied!";
        setTimeout(() => { btnCopySyntax.textContent = "Copy Hardened Config"; }, 2000);
      });
    });
  }

  // Navbar Quick Action Buttons
  if (btnQuickEnterprise) {
    btnQuickEnterprise.addEventListener("click", () => {
      analyzeSample("enterprise_smtps_hardened.pcap");
    });
  }

  if (btnQuickAttack) {
    btnQuickAttack.addEventListener("click", () => {
      analyzeSample("mitm_starttls_stripping_attack.pcap");
    });
  }

  // Initial Load
  loadSamples();
});
