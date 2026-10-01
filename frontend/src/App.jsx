import { useState, useEffect } from "react";

function App() {
  useEffect(() => {
  loadDashboardData();
    }, []);
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [dashboardStats, setDashboardStats] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [protectionResult, setProtectionResult] = useState(null);

  const [loading, setLoading] = useState(false);
  const [protecting, setProtecting] = useState(false);
  const [protectionMode, setProtectionMode] = useState("redact");
  const [sharingContext, setSharingContext] = useState("");

  const handleFileChange = (event) => {
    const selectedFile = event.target.files[0];

    if (selectedFile) {
      setFile(selectedFile);
      setResult(null);
      setProtectionResult(null);
    }
  };
  
  const scanFile = async () => {
    if (!file) {
      alert("Please select a file first.");
      return;
    }

    setLoading(true);
    setResult(null);
    setProtectionResult(null);

    const formData = new FormData();
    formData.append("file", file);
    formData.append("mode", protectionMode);

      if (sharingContext) {
        formData.append(
          "sharing_context",
          sharingContext
        );
      }
    try {
      const response = await fetch(
        "http://127.0.0.1:8000/api/upload",
        {
          method: "POST",
          body: formData,
        }
      );

      const data = await response.json();
      setResult(data);
      await loadDashboardData();
    } catch (error) {
      console.error(error);
      alert("Could not connect to PDLR backend.");
    }

    setLoading(false);
  };

const protectFile = async () => {
  if (!file) {
    alert("Please select a file first.");
    return;
  }

  const isImage = file.type.startsWith("image/");
  const isPDF = file.type === "application/pdf";

  if (!isImage && !isPDF) {
    alert(
      "Protection currently supports images and PDFs."
    );
    return;
  }

  setProtecting(true);
  setProtectionResult(null);

  const formData = new FormData();
  formData.append("file", file);

  // Send selected protection mode for images
  if (isImage) {
    formData.append("mode", protectionMode);
  }

  try {
    const endpoint = isImage
      ? "http://127.0.0.1:8000/api/protect"
      : "http://127.0.0.1:8000/api/protect/pdf";

    const response = await fetch(endpoint, {
      method: "POST",
      body: formData,
    });

    if (!response.ok) {
      throw new Error(
        `Protection failed: ${response.status}`
      );
    }

    const data = await response.json();

    setProtectionResult(data);
    await loadDashboardData();

  } catch (error) {
    console.error(error);

    alert(
      "Could not connect to PDLR protection service."
    );
  }

  setProtecting(false);
};

  const getRiskLevel = () => {
    if (!result || result.total_findings === 0) {
      return "LOW";
    }

    if (result.risk?.level) {
      return result.risk.level;
    }

    const hasCritical = result.findings.some(
      (finding) => finding.severity === "Critical"
    );

    if (hasCritical) return "CRITICAL";

    const hasHigh = result.findings.some(
      (finding) => finding.severity === "High"
    );

    if (hasHigh) return "HIGH";

    return "MEDIUM";
  };

  const getRiskClass = () => {
    return `risk-${getRiskLevel().toLowerCase()}`;
  };

  const getFileIcon = () => {
    if (!file) return "📄";

    if (file.type.startsWith("image/")) return "🖼️";

    if (file.type === "application/pdf") return "📕";

    return "📄";
  };
  const loadDashboardData = async () => {
  try {
    const statsResponse = await fetch(
      "http://127.0.0.1:8000/api/dashboard/stats"
    );

    const statsData = await statsResponse.json();

    setDashboardStats(statsData);

    const historyResponse = await fetch(
      "http://127.0.0.1:8000/api/history"
    );

    const historyData = await historyResponse.json();

    setScanHistory(historyData.history || []);

  } catch (error) {
    console.error(
      "Could not load dashboard data:",
      error
    );
  }
};

  return (
    <div className="app">

      {/* ================= NAVBAR ================= */}

      <nav className="navbar">

        <div className="brand">

          <div className="brand-icon">
            🛡️
          </div>

          <div>
            <div className="brand-name">
              PDLR
            </div>

            <div className="brand-subtitle">
              Personal Data Leak Radar
            </div>
          </div>

        </div>

        <div className="nav-links">

          <span
            className="nav-link"
            onClick={() => setShowHistory(false)}
          >
            Dashboard
          </span>

          <span
            className="nav-link"
            onClick={() => setShowHistory(true)}
          >
            Scan History
          </span>

          <span className="nav-link">
            Settings
          </span>

        </div>

      </nav>


      {/* ================= MAIN ================= */}

      <main className="main-content">

        {/* HERO */}

        <section className="hero">

          <div className="hero-badge">
            🔐 PRIVACY FIREWALL
          </div>

          <h1>
            Your data should be safe
            <span>before you share it.</span>
          </h1>

          <p>
            PDLR detects sensitive information, explains the
            risk, protects your file, and verifies that the
            leak is fixed.
          </p>

        </section>
        <section className="dashboard-stats">

  <div className="stat-card">
    <div className="stat-icon">◉</div>

    <div>
      <div className="stat-value">
        {dashboardStats?.total_scans ?? 0}
      </div>

      <div className="stat-label">
        Total Scans
      </div>
    </div>
  </div>


  <div className="stat-card">
    <div className="stat-icon">!</div>

    <div>
      <div className="stat-value">
        {dashboardStats?.total_findings ?? 0}
      </div>

      <div className="stat-label">
        Findings Detected
      </div>
    </div>
  </div>


  <div className="stat-card">
    <div className="stat-icon">🛡️</div>

    <div>
      <div className="stat-value">
        {dashboardStats?.protected_files ?? 0}
      </div>

      <div className="stat-label">
        Files Protected
      </div>
    </div>
  </div>


  <div className="stat-card">
    <div className="stat-icon">✓</div>

    <div>
      <div className="stat-value">
        {dashboardStats?.verified_files ?? 0}
      </div>

      <div className="stat-label">
        Protection Verified
      </div>
    </div>
    
  </div>

</section>

        {/* ================= UPLOAD ================= */}

        <section className="upload-card">

          <div className="upload-header">

            <div>
              <h2>
                Scan a File
              </h2>

              <p>
                Check your document or image for sensitive
                information.
              </p>
            </div>

            <div className="secure-badge">
              🔒 Privacy Protected
            </div>

          </div>


          <label className="drop-zone">

            <input
              type="file"
              accept="image/*,.pdf,.txt"
              onChange={handleFileChange}
            />

            {!file ? (
              <>

                <div className="upload-icon">
                  ↑
                </div>

                <h3>
                  Drop your file here
                </h3>

                <p>
                  or click to browse
                </p>

                <div className="file-types">
                  PDF • PNG • JPG • TXT
                </div>

              </>
            ) : (
              <>

                <div className="selected-file-icon">
                  {getFileIcon()}
                </div>

                <h3>
                  {file.name}
                </h3>

                <p>
                  {(file.size / 1024).toFixed(1)} KB
                </p>

                <div className="change-file">
                  Click to change file
                </div>

              </>
            )}

          </label>

            <div className="context-section">
            <div className="context-title">
              <strong>Why are you sharing this file?</strong>
              <span>Optional</span>
            </div>

            <select
              className="context-select"
              value={sharingContext}
              onChange={(e) => setSharingContext(e.target.value)}
            >
              <option value="">Select sharing context</option>
              <option value="Job Application">Job Application</option>
              <option value="College">College</option>
              <option value="Customer Support">Customer Support</option>
              <option value="Social Media">Social Media</option>
              <option value="Work">Work</option>
              <option value="Verification">Verification</option>
              <option value="General">General</option>
            </select>
          </div>
          <button
            className="scan-button"
            onClick={scanFile}
            disabled={loading || !file}
          >
           

            {loading ? (
              <>
                <span className="spinner"></span>
                Scanning...
              </>
            ) : (
              <>
                🔍 Scan for Data Leaks
              </>
            )}

          </button>

        </section>


        {/* ================= SCAN RESULTS ================= */}

        {result && (

          <section className="results-section">

            <div className="section-title">

              <div>

                <div className="small-label">
                  SCAN RESULTS
                </div>

                <h2>
                  Security Overview
                </h2>

              </div>

              <div className={`risk-pill ${getRiskClass()}`}>
                {getRiskLevel()}
              </div>

            </div>


            {/* SUMMARY */}

            <div className="summary-grid">

              <div className="summary-card">

                <div className="summary-icon danger">
                  !
                </div>

                <div>

                  <div className="summary-value">
                    {result.total_findings}
                  </div>

                  <div className="summary-label">
                    Sensitive Findings
                  </div>

                </div>

              </div>


              <div className="summary-card">

                <div className="summary-icon shield">
                  🛡
                </div>

                <div>

                  <div className="summary-value">
                    {getRiskLevel()}
                  </div>

                  <div className="summary-label">
                    Overall Risk
                  </div>

                </div>

              </div>


              <div className="summary-card">

                <div className="summary-icon scan">
                  ✓
                </div>

                <div>

                  <div className="summary-value">
                    {result.processing_method?.includes("OCR")
                      ? "OCR"
                      : "Text"}
                  </div>

                  <div className="summary-label">
                    Detection Method
                  </div>

                </div>

              </div>

            </div>


            {/* FINDINGS */}

            <div className="findings-card">

              <div className="card-header">

                <div>

                  <h3>
                    Detected Information
                  </h3>

                  <p>
                    Sensitive elements found in your file
                  </p>

                </div>

                <span className="finding-count">
                  {result.total_findings}
                </span>

              </div>


              {result.findings.length === 0 ? (

                <div className="safe-state">

                  <div className="safe-icon">
                    ✓
                  </div>

                  <h3>
                    No sensitive information detected
                  </h3>

                  <p>
                    PDLR did not find any sensitive information
                    based on the current detection rules.
                  </p>

                </div>

              ) : (

                <div className="finding-list">

                  {result.findings.map(
                    (finding, index) => (

                      <div
                        className="finding-row"
                        key={index}
                      >

                        <div className="finding-left">

                          <div
                            className={`severity-dot ${finding.severity.toLowerCase()}`}
                          ></div>

                          <div>

                            <strong>
                              {finding.type}
                            </strong>

                            <span>
                              Sensitive information detected
                            </span>

                          </div>

                        </div>


                        <div
                          className={`severity-badge ${finding.severity.toLowerCase()}`}
                        >
                          {finding.severity}
                        </div>

                      </div>

                    )
                  )}

                </div>

              )}

            </div>


            {/* ================= PROTECT BUTTON ================= */}

            {result.total_findings > 0 &&
              (file?.type.startsWith("image/") ||
                file?.type === "application/pdf") && (

                <div className="protect-panel">
                  <button onClick={protectFile}></button>

                  <div className="protect-info">

                    <div className="protect-icon">
                      🛡️
                    </div>

                    <div>

                      <h3>
                        Protect this file
                      </h3>

                      <p>
                       PDLR will protect sensitive information,
                        create a separate safe copy, and scan it
                        again to verify the protection.
                      </p>

                    </div>

                  </div>

                <div className="protection-mode-selector">
                <label>Protection Mode</label>

                  < div className="protection-mode-options">

                  <button
                    type="button"
                    className={
                      protectionMode === "redact"
                        ? "mode-option active"
                        : "mode-option"
                    }
                    onClick={() => setProtectionMode("redact")}
                  >
                    <span className="mode-icon">🔒</span>

                    <div className="mode-content">
                      <strong>Redact</strong>
                      <small>Completely hide</small>
                    </div>

                    {protectionMode === "redact" && (
                      <span className="mode-selected">✓</span>
                    )}
                  </button>


                  <button
                    type="button"
                    className={
                      protectionMode === "mask"
                        ? "mode-option active"
                        : "mode-option"
                    }
                    onClick={() => setProtectionMode("mask")}
                  >
                    <span className="mode-icon">▰</span>

                    <div className="mode-content">
                      <strong>Mask</strong>
                      <small>Partially hide</small>
                    </div>

                    {protectionMode === "mask" && (
                      <span className="mode-selected">✓</span>
                    )}
                  </button>


                  <button
                    type="button"
                    className={
                      protectionMode === "blur"
                        ? "mode-option active"
                        : "mode-option"
                    }
                    onClick={() => setProtectionMode("blur")}
                  >
                    <span className="mode-icon">◌</span>

                    <div className="mode-content">
                      <strong>Blur</strong>
                      <small>Blur sensitive area</small>
                    </div>

                    {protectionMode === "blur" && (
                      <span className="mode-selected">✓</span>
                    )}
                  </button>

                </div>
              </div>
                  <button
                    className="protect-button"
                    onClick={protectFile}
                    disabled={protecting}
                  >

                    {protecting ? (
                      <>
                        <span className="protect-spinner"></span>
                        Protecting & Verifying...
                      </>
                    ) : (
                      <>
                        🛡️ Protect & Verify
                      </>
                    )}

                  </button>

                </div>

              )}


            {/* ================= EXTRACTED TEXT ================= */}
            {(result?.ai_analysis || protectionResult?.ai_analysis) && (() => {

                const aiAnalysis =
                  result?.ai_analysis ||
                  protectionResult?.ai_analysis;

                return (
                  <div className="ai-analysis-card">

                    <div className="ai-analysis-header">

                      <div className="ai-analysis-icon">
                        🤖
                      </div>

                      <div>
                        <div className="small-label">
                          AI PRIVACY ANALYSIS
                        </div>

                        <h3>
                          What does this mean?
                        </h3>

                        <p>
                          Amazon Bedrock analyzed the detected information
                          and generated a privacy-risk explanation.
                        </p>
                      </div>

                    </div>


                    <div className="ai-summary">

                      <div className="ai-section-title">
                        Overall Assessment
                      </div>

                      <p>
                        {aiAnalysis.summary}
                      </p>

                    </div>


                    <div className="ai-risk">

                      <div className="ai-section-title">
                        Why is this risky?
                      </div>

                      <p>
                        {aiAnalysis.risk_explanation}
                      </p>

                    </div>


                    {aiAnalysis.priority_findings?.length > 0 && (

                      <div className="ai-priority">

                        <div className="ai-section-title">
                          Priority Protection
                        </div>

                        <div className="priority-list">

                          {aiAnalysis.priority_findings.map(
                            (item, index) => (

                              <div
                                className="priority-item"
                                key={index}
                              >
                                <span>!</span>
                                {item}
                              </div>

                            )
                          )}

                        </div>

                      </div>

                    )}


                    {aiAnalysis.recommendations?.length > 0 && (

                      <div className="ai-recommendations">

                        <div className="ai-section-title">
                          Recommended Actions
                        </div>

                        <div className="recommendation-list">

                          {aiAnalysis.recommendations.map(
                            (item, index) => (

                              <div
                                className="recommendation-item"
                                key={index}
                              >
                                <span>✓</span>
                                {item}
                              </div>

                            )
                          )}

                        </div>

                      </div>

                    )}

                  </div>
                );
              })()}
            {(result?.ai_analysis || protectionResult?.ai_analysis) && (() => {

  const aiAnalysis =
    result?.ai_analysis ||
    protectionResult?.ai_analysis;

  return (
    <div className="ai-analysis-card">

      <div className="ai-analysis-header">

        <div className="ai-analysis-icon">
          🤖
        </div>

        <div>
          <div className="small-label">
            AI PRIVACY ANALYSIS
          </div>

          <h3>
            What does this mean?
          </h3>

          <p>
            Amazon Bedrock analyzed the detected information
            and generated a privacy-risk explanation.
          </p>
        </div>

      </div>


      {/* OVERALL ASSESSMENT */}
      <div className="ai-summary">

        <div className="ai-section-title">
          Overall Assessment
        </div>

        <p>
          {aiAnalysis.summary}
        </p>

      </div>


      {/* RISK EXPLANATION */}
      <div className="ai-risk">

        <div className="ai-section-title">
          Why is this risky?
        </div>

        <p>
          {aiAnalysis.risk_explanation}
        </p>

      </div>


      {/* PRIORITY FINDINGS */}
      {aiAnalysis.priority_findings?.length > 0 && (

        <div className="ai-priority">

          <div className="ai-section-title">
            Priority Protection
          </div>

          <div className="priority-list">

            {aiAnalysis.priority_findings.map(
              (item, index) => (

                <div
                  className="priority-item"
                  key={index}
                >
                  <span>!</span>
                  {item}
                </div>

              )
            )}

          </div>

        </div>

      )}


      {/* RECOMMENDATIONS */}
      {aiAnalysis.recommendations?.length > 0 && (

        <div className="ai-recommendations">

          <div className="ai-section-title">
            Recommended Actions
          </div>

          <div className="recommendation-list">

            {aiAnalysis.recommendations.map(
              (item, index) => (

                <div
                  className="recommendation-item"
                  key={index}
                >
                  <span>✓</span>
                  {item}
                </div>

              )
            )}

          </div>

        </div>

      )}

    </div>
  );

})()}
            {(result?.extracted_text || protectionResult?.extracted_text) && (

  <div className="extracted-card">

    <div className="card-header">

      <div>
        <h3>
          Extracted Content
        </h3>

        <p>
          Text identified during analysis
        </p>
      </div>

    </div>

    <pre>
      {result?.extracted_text ||
        protectionResult?.extracted_text}
    </pre>

  </div>

)}

          </section>

        )}


        {/* ================= PROTECTION RESULT ================= */}

        {protectionResult && (

          <section className="protection-card">

            <div className="small-label">
              PRIVACY SHIELD
            </div>

            {protectionResult.verification?.verified ? (

              <>

                <div className="verified-state">

                  <div className="verified-icon">
                    ✓
                  </div>

                  <div>

                    <h2>
                      Protection Verified
                    </h2>

                    <p>
                      The protected copy was scanned again
                      and no unresolved sensitive information
                      was detected.
                    </p>

                  </div>

                </div>


                <div className="verification-flow">

                  <div className="verification-step completed">
                    <span>✓</span>
                    Sensitive data detected
                  </div>

                  <div className="verification-arrow">
                    →
                  </div>

                  <div className="verification-step completed">
                    <span>✓</span>
                    Sensitive data protected
                  </div>

                  <div className="verification-arrow">
                    →
                  </div>

                  <div className="verification-step completed">
                    <span>✓</span>
                    Second scan passed
                  </div>

                </div>
                
                <div className="verification-evidence">

                  <div className="evidence-card">
                    <span className="evidence-number">
                      {protectionResult.verification_evidence?.initial_findings ??
                        protectionResult.initial_total ??
                        0}
                    </span>

                    <span className="evidence-label">
                      Findings Detected
                    </span>
                  </div>


                  <div className="evidence-card">
                    <span className="evidence-number">
                      {protectionResult.verification_evidence?.protected_regions ??
                        protectionResult.protection_summary?.regions_protected ??
                        protectionResult.redactions ??
                        0}
                    </span>

                    <span className="evidence-label">
                      Regions Protected
                    </span>
                  </div>


                  <div className="evidence-card">
                    <span className="evidence-number">
                      {protectionResult.verification_evidence?.remaining_findings ??
                        protectionResult.verification?.total_remaining ??
                        0}
                    </span>

                    <span className="evidence-label">
                      Remaining Findings
                    </span>
                  </div>

                </div>


                <div className="protection-method">

                  <span>
                    Protection Method
                  </span>

                  <strong>
                    {(
                      protectionResult.protection_summary?.method ||
                      (protectionResult.redactions
                        ? "redact"
                        : "protected")
                    ).toUpperCase()}
                  </strong>

                </div>

                <div className="protection-actions">

                  <a
                    className="safe-copy-button"
                    href={`http://127.0.0.1:8000${protectionResult.protected_url}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    👁 View Safe Copy
                  </a>

                  <a
                    className="download-button"
                    href={`http://127.0.0.1:8000${protectionResult.protected_url}`}
                    download
                  >
                    ↓ Download Safe Copy
                  </a>

                </div>


                <div className="original-note">
                  🔒 Your original file was not modified.
                  PDLR created a separate protected copy.
                </div>

              </>

              ) : (

  <div className="verification-failed">

    <div className="failed-icon">
      !
    </div>

    <div>

      <h2>
        Protection Verification Failed
      </h2>

      <p>
        Some sensitive information is still
        present in the protected copy.
      </p>

      <div className="verification-evidence">

        <div className="evidence-card">
          <span className="evidence-number">
            {protectionResult.verification_evidence?.initial_findings ??
              protectionResult.initial_total ??
              0}
          </span>

          <span className="evidence-label">
            Findings Detected
          </span>
        </div>

        <div className="evidence-card">
          <span className="evidence-number">
            {protectionResult.verification_evidence?.protected_regions ??
              protectionResult.protection_summary?.regions_protected ??
              0}
          </span>

          <span className="evidence-label">
            Regions Protected
          </span>
        </div>

        <div className="evidence-card">
          <span className="evidence-number">
            {protectionResult.verification_evidence?.remaining_findings ??
              protectionResult.verification?.total_remaining ??
              0}
          </span>

          <span className="evidence-label">
            Remaining Findings
          </span>
        </div>

      </div>

      <div className="remaining-count">
        Remaining findings:
        <strong>
          {protectionResult.verification?.total_remaining || 0}
        </strong>
      </div>

    </div>


    <div className="protection-method">

      <span>
        Protection Method
      </span>

      <strong>
        {(
          protectionResult.protection_summary?.method ||
          "redact"
        ).toUpperCase()}
      </strong>

    </div>





    {/* ================= PROTECTED COPY ================= */}

    {protectionResult.protected_url && (

      <>

        <div className="protection-actions">

          <a
            className="safe-copy-button"
            href={`http://127.0.0.1:8000${protectionResult.protected_url}`}
            target="_blank"
            rel="noreferrer"
          >
            👁 View Protected Copy
          </a>

          <a
            className="download-button"
            href={`http://127.0.0.1:8000${protectionResult.protected_url}`}
            download
          >
            ↓ Download Protected Copy
          </a>

        </div>


        <div className="original-note">
          ⚠️ This copy has <strong>not passed verification</strong>.
          Review it before sharing.
          Your original file was not modified.
        </div>

      </>

    )}

  </div>

)}

          </section>

        )}
        {!showHistory && (
  <div className="history-button-container">
    <button
      className="view-history-button"
      onClick={() => setShowHistory(true)}
    >
      📋 View Scan History
    </button>
  </div>
)}
       {showHistory && (
          <section className="history-section">
            <button
          className="back-dashboard-button"
          onClick={() => setShowHistory(false)}
        >
          ← Back to Dashboard
        </button>

        <div className="section-title">

          <div>
            <div className="small-label">
              ACTIVITY
            </div>

            <h2>
              Scan History
            </h2>
          </div>

          <span className="history-total">
            {scanHistory.length} scans
          </span>

        </div>


  <div className="history-card">

    {scanHistory.length === 0 ? (

      <div className="history-empty">

        <div className="history-empty-icon">
          ◷
        </div>

        <h3>
          No scans yet
        </h3>

        <p>
          Your recent security scans will appear here.
        </p>

      </div>

    ) : (

      <div className="history-list">

        {scanHistory.map((scan) => (

          <div
            className="history-row"
            key={scan.id}
          >

            <div className="history-file">

              <div className="history-file-icon">
                📄
              </div>

              <div>

                <strong>
                  {scan.filename}
                </strong>

                <span>
                  {new Date(
                    scan.timestamp
                  ).toLocaleString()}
                </span>

              </div>

            </div>


            <div className="history-findings">

              <strong>
                {scan.findings}
              </strong>

              <span>
                findings
              </span>

            </div>


            <div
              className={`history-risk risk-${(
                scan.risk || "low"
              ).toLowerCase()}`}
            >
              {scan.risk}
            </div>


            <div className="history-status">

              {scan.verified ? (
                <span className="verified-badge">
                  ✓ Verified
                </span>
              ) : scan.protected ? (
                <span className="protected-badge">
                  🛡 Protected
                </span>
              ) : (
                <span className="scanned-badge">
                  Scanned
                </span>
              )}

            </div>

          </div>

        ))}

      </div>

    )}

  </div>

          </section>
        )}


        {/* ================= HOW IT WORKS ================= */}

        <section className="how-section">

          <div className="small-label">
            HOW PDLR WORKS
          </div>

          <h2>
            Detect. Protect. Verify.
          </h2>

          <div className="steps">

            <div className="step">

              <div className="step-number">
                01
              </div>

              <h3>
                Detect
              </h3>

              <p>
                Find PII, secrets, QR codes and hidden metadata.
              </p>

            </div>


            <div className="step-line"></div>


            <div className="step">

              <div className="step-number">
                02
              </div>

              <h3>
                Protect
              </h3>

              <p>
                Mask or redact sensitive information before sharing.
              </p>

            </div>


            <div className="step-line"></div>


            <div className="step">

              <div className="step-number">
                03
              </div>

              <h3>
                Verify
              </h3>

              <p>
                Scan the protected copy again to prove it is safe.
              </p>

            </div>

          </div>

        </section>

      </main>


      {/* ================= FOOTER ================= */}

      <footer>

        <span>
          PDLR • Personal Data Leak Radar
        </span>

        <span>
          Privacy starts before you share.
        </span>

      </footer>

    </div>
  );
}

export default App;