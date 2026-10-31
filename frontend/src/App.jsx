import { Fragment, useCallback, useEffect, useState } from "react";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

async function api(path, opts) {
  let r;
  try {
    r = await fetch(API + path, opts);
  } catch {
    throw new Error(`The TLSentinel API is not reachable at ${API}. Ensure the backend is active on port 8000.`);
  }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.detail || `Request failed (${r.status})`);
  return j;
}

function useApi(path) {
  const [s, set] = useState({});
  const load = useCallback(() => {
    set((p) => ({ data: p.data, loading: true }));
    api(path)
      .then((data) => set({ data, loading: false }))
      .catch((e) => set({ error: e.message, loading: false }));
  }, [path]);
  useEffect(load, [load]);
  return { ...s, reload: load };
}

const when = (iso) => (iso ? new Date(iso).toLocaleString() : "-");

const KIND = { PASS: "pass", REVIEW: "review", FAIL: "fail", "NOT TESTED": "nt" };
const Badge = ({ s }) => <span className={"badge " + (KIND[s] || "nt")}>{s}</span>;

const SEV_CLASS = {
  CRITICAL: "sev-critical",
  HIGH: "sev-high",
  MEDIUM: "sev-medium",
  LOW: "sev-low",
  INFO: "sev-info"
};
const SeverityBadge = ({ s }) => <span className={"badge " + (SEV_CLASS[s] || "sev-info")}>{s}</span>;

const Head = ({ title, sub }) => (
  <>
    <h1>{title}</h1>
    {sub ? <p className="sub">{sub}</p> : null}
  </>
);

const Facts = ({ rows }) => (
  <dl className="facts">
    {rows.map(([k, v]) => (
      <Fragment key={k}>
        <dt>{k}</dt>
        <dd>{v}</dd>
      </Fragment>
    ))}
  </dl>
);

function Async({ s, children }) {
  if (s.error) return <div className="alert-box critical"><b>Error:</b> {s.error}</div>;
  if (!s.data && s.loading !== false) return <p className="muted">Loading cryptographic state...</p>;
  if (!s.data) return null;
  return children(s.data);
}

// ----------------------------------------------------
// 1. OVERVIEW VIEW
// ----------------------------------------------------
function Overview({ go }) {
  const lab = useApi("/lab/status");
  const history = useApi("/history?limit=1");
  const domains = useApi("/api/monitor/domains");
  const latest = history.data?.[0];

  return (
    <>
      <Head
        title="TLSentinel Security Overview"
        sub="Continuous TLS security assessment, automated certificate expiry tracking, and Phoenix Security-style risk quantification."
      />
      <Async s={lab}>
        {(d) => (
          <>
            <div className="stat-grid">
              <div className={`stat-card ${d.http_reachable && d.service_verified ? "pass" : "review"}`}>
                <span className="lbl">Lab HTTP Service</span>
                <span className="val" style={{ fontSize: "1.3rem", marginTop: "10px" }}>
                  {d.http_reachable ? `Port ${d.http_port} (Redirect)` : "Offline"}
                </span>
                <span className="small muted" style={{ marginTop: "4px" }}>
                  {d.service_verified ? "Verified TLSentinel Lab" : "Port verification needed"}
                </span>
              </div>
              <div className={`stat-card ${d.https_reachable ? "pass" : "fail"}`}>
                <span className="lbl">Lab HTTPS Service</span>
                <span className="val" style={{ fontSize: "1.3rem", marginTop: "10px" }}>
                  {d.https_reachable ? `Port ${d.https_port} (Active)` : "Offline"}
                </span>
                <span className="small muted" style={{ marginTop: "4px" }}>
                  {d.https_reachable ? `${d.https?.tls_version}, ${d.https?.cipher_bits}-bit` : "Not reachable"}
                </span>
              </div>
              <div className="stat-card">
                <span className="lbl">Monitored Domains</span>
                <span className="val" style={{ fontSize: "1.3rem", marginTop: "10px" }}>
                  {domains.data?.length || 0} Registered
                </span>
                <span className="small muted" style={{ marginTop: "4px" }}>
                  Auto-checking every 60s
                </span>
              </div>
              <div className="stat-card">
                <span className="lbl">Latest Assessment</span>
                <span className="val" style={{ fontSize: "1.3rem", marginTop: "10px" }}>
                  {latest ? latest.overall_status.replace(/_/g, " ") : "Not Run Yet"}
                </span>
                <span className="small muted" style={{ marginTop: "4px" }}>
                  {latest ? when(latest.created_at) : "Click below to run"}
                </span>
              </div>
            </div>

            <Facts
              rows={[
                ["HTTP Endpoint", <code>http://{d.host}:{d.http_port}</code>],
                ["HTTPS Endpoint", <code>https://{d.host}:{d.https_port}</code>],
                ["HTTP Redirect Target", d.redirect_target ? <code>{d.redirect_target}</code> : "None observed"],
                ["Service Identity", d.service_verified ? "Verified Genuine Lab Service" : "Service signature warning"],
                ["Negotiated Cipher", d.https_reachable ? `${d.https?.tls_version} (${d.https?.cipher})` : "N/A"],
                ["Checked At", when(d.checked_at)]
              ]}
            />

            <p style={{ marginTop: "24px" }}>
              <button className="btn" onClick={() => go("Assessment & Risk")}>
                🛡️ Run Risk Assessment
              </button>
              <button className="btn ghost" onClick={() => go("Cert Monitor")}>
                ⏱️ Certificate Expiry Monitor
              </button>
              <button className="btn ghost" onClick={() => go("Protocol Audit")}>
                ⚡ Protocol Matrix
              </button>
              <button className="btn ghost" onClick={lab.reload}>
                Refresh Status
              </button>
            </p>
          </>
        )}
      </Async>
    </>
  );
}

// ----------------------------------------------------
// 2. ASSESSMENT & AI RISK SCORE (Phoenix Security Style)
// ----------------------------------------------------
function AssessmentView() {
  const [data, setData] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [filter, setFilter] = useState("ALL");
  const [expanded, setExpanded] = useState({});

  const run = () => {
    setBusy(true);
    setErr(null);
    api("/analysis/local", { method: "POST" })
      .then((res) => setData(res))
      .catch((e) => setErr(e.message))
      .finally(() => setBusy(false));
  };

  useEffect(() => {
    run();
  }, []);

  const toggleExpand = (id) => {
    setExpanded((p) => ({ ...p, [id]: !p[id] }));
  };

  const filteredResults =
    data?.results?.filter((r) => {
      if (filter === "ALL") return true;
      if (filter === "FAIL_OR_REVIEW") return r.status === "FAIL" || r.status === "REVIEW";
      if (filter === "CRITICAL") return r.severity === "CRITICAL" || r.severity === "HIGH";
      return true;
    }) || [];

  const risk = data?.risk_score;

  return (
    <>
      <Head
        title="AI-Powered Security Risk Score & Assessment"
        sub="Quantified 0-100 security risk score inspired by ASPM standards. Evaluates real technical findings with calibrated point deductions and AI technical explanations."
      />

      <p>
        <button className="btn" onClick={run} disabled={busy}>
          {busy ? "Running Cryptographic Probes..." : "Run Assessment Again"}
        </button>
        {data?.id && (
          <a className="btn ghost" href={`${API}/report/${data.id}.html`} target="_blank" rel="noreferrer">
            Export PDF / HTML Report
          </a>
        )}
      </p>

      {err && <div className="alert-box critical"><b>Assessment Error:</b> {err}</div>}

      {data && risk && (
        <>
          {/* Phoenix Security ASPM Style Score Card */}
          <div className="risk-hero-card">
            <div className="risk-hero-info">
              <span className="small muted" style={{ textTransform: "uppercase", letterSpacing: "0.08em" }}>
                Target: {data.target}
              </span>
              <h2>{risk.tier} Security Posture</h2>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", marginTop: "8px" }}>
                <span className={`badge ${risk.badge_class}`} style={{ fontSize: "0.88rem", padding: "4px 12px" }}>
                  {risk.risk_level}
                </span>
                <span className="muted" style={{ fontSize: "0.9rem" }}>
                  {risk.total_deductions === 0 ? "0 risk deductions" : `${risk.total_deductions} risk points deducted`}
                </span>
              </div>
            </div>
            <div className="risk-hero-score-box">
              <span className="risk-big-number" style={{ color: risk.color }}>
                {risk.score}
              </span>
              <span className="risk-max">/ 100</span>
            </div>
          </div>

          {/* Severity Breakdown Bar */}
          <div className="severity-breakdown-bar">
            <div className="sev-col-card critical">
              <span className="small muted">Critical Severity</span>
              <div className="sev-count" style={{ color: "var(--critical)" }}>
                {risk.severity_breakdown.critical.count}
              </div>
              <span className="small muted">-{risk.severity_breakdown.critical.points} pts</span>
            </div>
            <div className="sev-col-card high">
              <span className="small muted">High Severity</span>
              <div className="sev-count" style={{ color: "var(--high)" }}>
                {risk.severity_breakdown.high.count}
              </div>
              <span className="small muted">-{risk.severity_breakdown.high.points} pts</span>
            </div>
            <div className="sev-col-card medium">
              <span className="small muted">Medium Severity</span>
              <div className="sev-count" style={{ color: "var(--medium)" }}>
                {risk.severity_breakdown.medium.count}
              </div>
              <span className="small muted">-{risk.severity_breakdown.medium.points} pts</span>
            </div>
            <div className="sev-col-card low">
              <span className="small muted">Low Severity</span>
              <div className="sev-count" style={{ color: "var(--low)" }}>
                {risk.severity_breakdown.low.count}
              </div>
              <span className="small muted">-{risk.severity_breakdown.low.points} pts</span>
            </div>
          </div>

          {/* AI Explanation & Technical Narrative Box */}
          <div className="ai-narrative-card">
            <h3>🤖 AI Security Explanation & Remediation Engine</h3>
            <p style={{ margin: "0 0 12px 0", fontSize: "0.96rem", lineHeight: "1.6" }}>
              {risk.ai_explanation.summary}
            </p>

            {risk.ai_explanation.positive_highlights?.length > 0 && (
              <div style={{ marginBottom: "14px" }}>
                <b style={{ color: "var(--pass)", fontSize: "0.9rem" }}>Positive Security Controls Verified:</b>
                <ul style={{ margin: "6px 0 0", paddingLeft: "20px", fontSize: "0.92rem", color: "#cbd5e1" }}>
                  {risk.ai_explanation.positive_highlights.map((h, i) => (
                    <li key={i}>{h}</li>
                  ))}
                </ul>
              </div>
            )}

            {risk.ai_explanation.recommended_actions?.length > 0 && (
              <div>
                <b style={{ color: "var(--accent)", fontSize: "0.9rem" }}>Prioritized Remediation Actions:</b>
                <ul className="action-checklist">
                  {risk.ai_explanation.recommended_actions.map((act, i) => (
                    <li key={i}>
                      <span style={{ color: "var(--accent)" }}>✓</span> {act}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Risk Point Deductions Waterfall */}
          {risk.deductions?.length > 0 && (
            <>
              <h3>Risk Point Deductions Breakdown</h3>
              <div className="scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Check ID</th>
                      <th>Finding</th>
                      <th>Points Deducted</th>
                      <th>Severity</th>
                      <th>Technical Justification</th>
                    </tr>
                  </thead>
                  <tbody>
                    {risk.deductions.map((d, i) => (
                      <tr key={i}>
                        <td className="mono" style={{ fontWeight: 600 }}>{d.check_id}</td>
                        <td><b>{d.name}</b></td>
                        <td style={{ color: "var(--fail)", fontWeight: 700 }}>-{d.points} pts</td>
                        <td><SeverityBadge s={d.severity} /></td>
                        <td style={{ fontSize: "0.9rem" }}>{d.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {/* Filter Bar */}
          <div style={{ display: "flex", gap: "8px", margin: "24px 0 12px" }}>
            {["ALL", "FAIL_OR_REVIEW", "CRITICAL"].map((f) => (
              <button
                key={f}
                className={`btn ghost ${filter === f ? "on" : ""}`}
                style={{ padding: "6px 14px", fontSize: "0.85rem", background: filter === f ? "var(--panel-hover)" : "none" }}
                onClick={() => setFilter(f)}
              >
                {f === "ALL" ? "All Checks" : f === "FAIL_OR_REVIEW" ? "Issues & Reviews" : "Critical & High Only"}
              </button>
            ))}
          </div>

          {/* Findings Table with Technical Details */}
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Check Name & Category</th>
                  <th>Severity</th>
                  <th>Result</th>
                  <th>Measured Value</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {filteredResults.map((r) => {
                  const isOpen = !!expanded[r.id];
                  return (
                    <Fragment key={r.id}>
                      <tr>
                        <td className="mono" style={{ fontWeight: 600 }}>{r.id}</td>
                        <td>
                          <b>{r.name}</b>
                          <div className="small muted">{r.category}</div>
                        </td>
                        <td><SeverityBadge s={r.severity} /></td>
                        <td><Badge s={r.status} /></td>
                        <td className="mono" style={{ fontSize: "0.82rem" }}>
                          {String(r.measured)}
                        </td>
                        <td>
                          <button
                            className="btn ghost"
                            style={{ padding: "4px 8px", fontSize: "0.8rem", margin: 0 }}
                            onClick={() => toggleExpand(r.id)}
                          >
                            {isOpen ? "Hide Details" : "View Evidence & Fix"}
                          </button>
                        </td>
                      </tr>
                      {isOpen && (
                        <tr>
                          <td colSpan={6} style={{ background: "rgba(0,0,0,0.25)", padding: "16px 20px" }}>
                            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px" }}>
                              <div>
                                <h4 style={{ margin: "0 0 6px 0", color: "#fff" }}>Explanation</h4>
                                <p style={{ margin: 0, fontSize: "0.92rem" }}>{r.explanation}</p>
                                {r.limitation && (
                                  <p className="small muted" style={{ marginTop: "6px" }}>
                                    <b>Limitation:</b> {r.limitation}
                                  </p>
                                )}
                                <h4 style={{ margin: "12px 0 6px 0", color: "var(--accent)" }}>Remediation Advice</h4>
                                <p style={{ margin: 0, fontSize: "0.92rem", color: "#e2e8f0" }}>{r.remediation}</p>
                              </div>
                              <div>
                                <h4 style={{ margin: "0 0 6px 0", color: "#fff" }}>Reproducible Evidence</h4>
                                <pre style={{
                                  background: "#0d1117",
                                  padding: "10px",
                                  borderRadius: "4px",
                                  fontSize: "0.8rem",
                                  overflowX: "auto",
                                  margin: 0
                                }}>
                                  {r.evidence || "No raw payload recorded"}
                                </pre>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
}

// ----------------------------------------------------
// 3. CERTIFICATE EXPIRY MONITORING (CertControl Style)
// ----------------------------------------------------
function CertMonitorView() {
  const domainsApi = useApi("/api/monitor/domains");
  const alertsApi = useApi("/api/monitor/alerts");

  const [newDomain, setNewDomain] = useState("");
  const [newPort, setNewPort] = useState(443);
  const [newEmail, setNewEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);

  const registerDomain = (e) => {
    e.preventDefault();
    if (!newDomain) return;
    setBusy(true);
    setMsg(null);
    api("/api/monitor/domains", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: newDomain, port: Number(newPort), email: newEmail || null })
    })
      .then((res) => {
        setMsg(`Registered ${res.domain.domain} for monitoring.`);
        setNewDomain("");
        setNewEmail("");
        domainsApi.reload();
        alertsApi.reload();
      })
      .catch((err) => setMsg(`Error: ${err.message}`))
      .finally(() => setBusy(false));
  };

  const recheckDomain = (id) => {
    api(`/api/monitor/domains/${id}/check`, { method: "POST" })
      .then(() => {
        domainsApi.reload();
        alertsApi.reload();
      })
      .catch((err) => alert(err.message));
  };

  const deleteDomain = (id) => {
    if (!window.confirm("Remove this domain from active certificate monitoring?")) return;
    api(`/api/monitor/domains/${id}`, { method: "DELETE" })
      .then(() => {
        domainsApi.reload();
        alertsApi.reload();
      })
      .catch((err) => alert(err.message));
  };

  const checkAllNow = () => {
    setBusy(true);
    api("/api/monitor/check-all", { method: "POST" })
      .then(() => {
        domainsApi.reload();
        alertsApi.reload();
      })
      .catch((err) => alert(err.message))
      .finally(() => setBusy(false));
  };

  const domains = domainsApi.data || [];
  const alerts = alertsApi.data || [];

  return (
    <>
      <Head
        title="Certificate Expiry Monitoring & TLS Lifecycle"
        sub="Continuous automated tracking of SSL/TLS certificate expiration dates, multi-tier threshold alerts (>30d, 30d, 15d, 7d, expired), and scheduled background monitoring."
      />

      <div style={{ display: "flex", gap: "10px", marginBottom: "20px" }}>
        <button className="btn" onClick={checkAllNow} disabled={busy}>
          {busy ? "Running Background Checks..." : "Check All Domains Now"}
        </button>
        <button className="btn ghost" onClick={() => { domainsApi.reload(); alertsApi.reload(); }}>
          Refresh
        </button>
      </div>

      {msg && <div className="alert-box info">{msg}</div>}

      {/* CertControl Style Domain Cards Grid */}
      <h2>Active Monitored Domains ({domains.length})</h2>
      <div className="monitor-grid">
        {domains.map((d) => {
          const statusLower = d.status?.toLowerCase() || "normal";
          const progressPercent = Math.max(5, Math.min(100, Math.round((d.days_left / 365) * 100)));
          const progressColor =
            d.days_left <= 0 ? "var(--fail)" : d.days_left <= 7 ? "var(--critical)" : d.days_left <= 15 ? "var(--high)" : d.days_left <= 30 ? "var(--review)" : "var(--pass)";

          return (
            <div key={d.id} className="cert-card">
              <div className="cert-card-header">
                <div>
                  <h3 className="cert-domain-title">
                    <span>🔒</span> {d.domain}
                  </h3>
                  <span className="small muted">Port {d.port} {d.email ? `• Alert: ${d.email}` : ""}</span>
                </div>
                <span className={`badge ${d.days_left <= 0 ? "fail" : d.days_left <= 15 ? "fail" : d.days_left <= 30 ? "review" : "pass"}`}>
                  {d.status}
                </span>
              </div>

              <div className={`cert-countdown-box ${statusLower}`}>
                <span className="days-num">{d.days_left >= 0 ? d.days_left : 0}</span>
                <div style={{ fontSize: "0.85rem", textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--muted)", marginTop: "4px" }}>
                  Days Remaining
                </div>
              </div>

              <div className="progress-bar-container">
                <div
                  className="progress-bar-fill"
                  style={{ width: `${progressPercent}%`, background: progressColor }}
                />
              </div>

              <div className="cert-meta-grid">
                <div>
                  <div className="item-lbl">Expires On</div>
                  <div className="item-val">{d.expiry_date ? d.expiry_date.slice(0, 10) : "Unknown"}</div>
                </div>
                <div>
                  <div className="item-lbl">Last Checked</div>
                  <div className="item-val">{when(d.last_checked)}</div>
                </div>
                <div>
                  <div className="item-lbl">Issuer</div>
                  <div className="item-val" title={d.issuer}>{d.issuer ? d.issuer.split(",")[0] : "N/A"}</div>
                </div>
                <div>
                  <div className="item-lbl">Next Auto-Check</div>
                  <div className="item-val">APScheduler (Every 60s)</div>
                </div>
              </div>

              <div style={{ display: "flex", gap: "8px", marginTop: "auto" }}>
                <button
                  className="btn ghost"
                  style={{ padding: "6px 12px", fontSize: "0.82rem", margin: 0, flex: 1 }}
                  onClick={() => recheckDomain(d.id)}
                >
                  Check Now
                </button>
                <button
                  className="btn danger"
                  style={{ padding: "6px 12px", fontSize: "0.82rem", margin: 0 }}
                  onClick={() => deleteDomain(d.id)}
                >
                  Remove
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Register New Domain Form */}
      <h2>Register Domain for Monitoring</h2>
      <form className="form-card" onSubmit={registerDomain}>
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: "16px" }}>
          <div className="form-group">
            <label>Domain or Hostname</label>
            <input
              className="form-input"
              type="text"
              placeholder="e.g. google.com or localhost"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              required
            />
          </div>
          <div className="form-group">
            <label>HTTPS Port</label>
            <input
              className="form-input"
              type="number"
              value={newPort}
              onChange={(e) => setNewPort(e.target.value)}
              required
            />
          </div>
        </div>
        <div className="form-group">
          <label>Notification Email (Optional)</label>
          <input
            className="form-input"
            type="email"
            placeholder="security-team@example.com"
            value={newEmail}
            onChange={(e) => setNewEmail(e.target.value)}
          />
          <span className="small muted">Dispatches email alerts at 30, 15, 7 days, and expiration.</span>
        </div>
        <button className="btn" type="submit" disabled={busy || !newDomain}>
          {busy ? "Registering & Testing..." : "Add Domain & Verify Certificate"}
        </button>
      </form>

      {/* Alerts Feed */}
      <h2>Monitoring Alerts & Notification History</h2>
      {alerts.length === 0 ? (
        <p className="muted">No expiry warnings or critical alerts triggered yet. All monitored domains are healthy.</p>
      ) : (
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Domain</th>
                <th>Alert Level</th>
                <th>Channel</th>
                <th>Notification Message</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((a) => (
                <tr key={a.id}>
                  <td className="small muted">{when(a.created_at)}</td>
                  <td><b>{a.domain}</b></td>
                  <td>
                    <span className={`badge ${a.alert_level === "CRITICAL" || a.alert_level === "URGENT" ? "fail" : a.alert_level === "WARNING" ? "review" : "pass"}`}>
                      {a.alert_level}
                    </span>
                  </td>
                  <td><span className="badge nt">{a.channel}</span></td>
                  <td>{a.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

// ----------------------------------------------------
// 4. PROTOCOL & CIPHER AUDIT MATRIX
// ----------------------------------------------------
function ProtocolAudit() {
  const audit = useApi("/audit/protocols");

  return (
    <>
      <Head
        title="TLS Protocol & Cipher Audit"
        sub="Multi-version protocol negotiation testing. Probes TLS 1.0 through 1.3 to verify legacy protocols are rejected and modern AEAD ciphers are enforced."
      />
      <Async s={audit}>
        {(d) => (
          <>
            <div className="matrix-grid">
              {d.matrix.map((p) => {
                const isAccepted = p.accepted;
                const isDeprecated = p.tier === "DEPRECATED";
                const cardClass = isDeprecated && isAccepted ? "deprecated" : isAccepted ? "accepted" : "rejected";

                return (
                  <div key={p.protocol} className={`matrix-card ${cardClass}`}>
                    <div className="proto-title">
                      <span>{p.protocol}</span>
                      <span className={`badge ${isAccepted && isDeprecated ? "fail" : isAccepted ? "pass" : "nt"}`}>
                        {p.status}
                      </span>
                    </div>
                    <div className="proto-details">
                      {isAccepted ? (
                        <>
                          <div><b>Cipher:</b> {p.cipher}</div>
                          <div><b>Strength:</b> {p.cipher_bits} bits ({p.aead ? "AEAD" : "Non-AEAD"})</div>
                          <div><b>Forward Secrecy:</b> {p.pfs ? "Yes (PFS)" : "No"}</div>
                        </>
                      ) : (
                        <div className="muted">{p.security_note}</div>
                      )}
                      <div style={{ marginTop: "8px", fontSize: "0.8rem" }}>
                        <b>Rating:</b> {p.tier}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            <h2>Protocol Compatibility Matrix</h2>
            <div className="scroll">
              <table>
                <thead>
                  <tr>
                    <th>Protocol</th>
                    <th>Status</th>
                    <th>Negotiated Cipher</th>
                    <th>AEAD Authenticated</th>
                    <th>Forward Secrecy</th>
                    <th>Security Assessment</th>
                  </tr>
                </thead>
                <tbody>
                  {d.matrix.map((p) => (
                    <tr key={p.protocol}>
                      <td style={{ fontWeight: 600 }}>{p.protocol}</td>
                      <td>
                        <span className={`badge ${p.accepted && p.tier === "DEPRECATED" ? "fail" : p.accepted ? "pass" : "nt"}`}>
                          {p.status}
                        </span>
                      </td>
                      <td className="mono">{p.cipher || "None"}</td>
                      <td>{p.aead ? "Yes (AEAD)" : p.accepted ? "No" : "-"}</td>
                      <td>{p.pfs ? "Yes (ECDHE/DHE)" : p.accepted ? "No" : "-"}</td>
                      <td>{p.security_note}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p>
              <button className="btn ghost" onClick={audit.reload}>
                Re-scan Protocols
              </button>
            </p>
          </>
        )}
      </Async>
    </>
  );
}

// ----------------------------------------------------
// 5. ADVANCED CERTIFICATE VALIDATION
// ----------------------------------------------------
function CertificateView() {
  const c = useApi("/certificate");
  const [copied, setCopied] = useState(false);

  return (
    <>
      <Head
        title="Advanced Certificate Validation"
        sub="Deep inspection of X.509 certificate chains, multi-tier expiry alerting, RFC 6125 SAN matching, and cryptographic key parameters."
      />
      <Async s={c}>
        {(d) => (
          <>
            {d.expiry_severity !== "LOW" && (
              <div className={`alert-box ${d.expiry_severity === "CRITICAL" ? "critical" : "high"}`}>
                <b>Expiry Alert:</b> {d.expiry_message}
              </div>
            )}

            <div className="stat-grid">
              <div className={`stat-card ${d.expiry_severity === "LOW" ? "pass" : "fail"}`}>
                <span className="lbl">Validity Status</span>
                <span className="val" style={{ fontSize: "1.4rem", marginTop: "8px" }}>
                  {d.expiry_status}
                </span>
                <span className="small muted">{d.days_left} days left</span>
              </div>
              <div className="stat-card">
                <span className="lbl">Key Strength</span>
                <span className="val" style={{ fontSize: "1.4rem", marginTop: "8px" }}>
                  {d.key_type} {d.key_size || ""}
                </span>
                <span className="small muted">SHA-256 Signature</span>
              </div>
              <div className={`stat-card ${d.hostname_matched ? "pass" : "fail"}`}>
                <span className="lbl">SAN Hostname Match</span>
                <span className="val" style={{ fontSize: "1.4rem", marginTop: "8px" }}>
                  {d.hostname_matched ? "MATCHED" : "MISMATCH"}
                </span>
                <span className="small muted">{d.san?.length || 0} SAN names</span>
              </div>
            </div>

            <Facts
              rows={[
                ["Subject", d.subject],
                ["Issuer", d.issuer],
                ["Trust Store Status", d.self_signed ? "Self-signed (Development / Lab)" : "CA-Signed"],
                ["Valid From", when(d.not_before)],
                ["Valid Until", `${when(d.not_after)} (${d.expiry_message})`],
                ["Key Type & Size", `${d.key_type} ${d.key_size || ""} bits`],
                ["Signature Hash", d.signature_hash.toUpperCase()],
                ["Subject Alternative Names", d.san.join(", ") || "None"],
                ["SAN Evaluation", d.hostname_reason],
                ["Serial Number", <span className="mono">{d.serial}</span>],
                ["SHA-256 Fingerprint", <span className="mono">{d.fingerprint_sha256}</span>]
              ]}
            />

            <p>
              <button
                className="btn ghost"
                onClick={() =>
                  navigator.clipboard.writeText(d.fingerprint_sha256).then(() => {
                    setCopied(true);
                    setTimeout(() => setCopied(false), 2000);
                  })
                }
              >
                {copied ? "Copied Fingerprint!" : "Copy SHA-256 Fingerprint"}
              </button>
              <button className="btn ghost" onClick={c.reload}>
                Refresh Certificate
              </button>
            </p>
          </>
        )}
      </Async>
    </>
  );
}

// ----------------------------------------------------
// 6. BEFORE / AFTER SECURITY COMPARISON
// ----------------------------------------------------
function ComparisonView() {
  const history = useApi("/history?limit=20");
  const [baseId, setBaseId] = useState("");
  const [targetId, setTargetId] = useState("");
  const [diff, setDiff] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  const runs = history.data || [];

  useEffect(() => {
    if (runs.length >= 2 && !baseId && !targetId) {
      setBaseId(runs[1].id);
      setTargetId(runs[0].id);
    } else if (runs.length === 1 && !baseId) {
      setBaseId(runs[0].id);
      setTargetId(runs[0].id);
    }
  }, [runs, baseId, targetId]);

  const runCompare = () => {
    if (!baseId || !targetId) return;
    setLoading(true);
    setErr(null);
    api(`/compare?base_id=${baseId}&target_id=${targetId}`)
      .then((res) => setDiff(res))
      .catch((e) => setErr(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    if (baseId && targetId) {
      runCompare();
    }
  }, [baseId, targetId]);

  return (
    <>
      <Head
        title="Before / After Security Comparison"
        sub="Compare two historical assessments to demonstrate remediation, track score improvements, or detect security regressions."
      />

      <div className="form-card" style={{ maxWidth: "800px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px" }}>
          <div className="form-group">
            <label>Baseline Assessment (Before)</label>
            <select
              className="form-input"
              value={baseId}
              onChange={(e) => setBaseId(e.target.value)}
            >
              {runs.map((r) => (
                <option key={r.id} value={r.id}>
                  #{r.id} - {r.target} ({when(r.created_at)}) [{r.overall_status}]
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label>Remediated Assessment (After)</label>
            <select
              className="form-input"
              value={targetId}
              onChange={(e) => setTargetId(e.target.value)}
            >
              {runs.map((r) => (
                <option key={r.id} value={r.id}>
                  #{r.id} - {r.target} ({when(r.created_at)}) [{r.overall_status}]
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {loading && <p className="muted">Computing security diff...</p>}
      {err && <div className="alert-box critical">{err}</div>}

      {diff && (
        <>
          <div className="diff-summary-bar">
            <div className="diff-item improved">
              <span>{diff.summary.improved} Improved</span>
            </div>
            <div className="diff-item regressed">
              <span>{diff.summary.regressed} Regressed</span>
            </div>
            <div className="diff-item unchanged">
              <span>{diff.summary.unchanged} Unchanged</span>
            </div>
            {diff.score_diff && (
              <div style={{ marginLeft: "auto", fontWeight: 700, color: diff.score_diff.delta >= 0 ? "var(--pass)" : "var(--fail)" }}>
                Score: {diff.score_diff.base_score} → {diff.score_diff.target_score} ({diff.score_diff.delta >= 0 ? `+${diff.score_diff.delta}` : diff.score_diff.delta} pts)
              </div>
            )}
          </div>

          <h2>Security Check Changes</h2>
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Check ID</th>
                  <th>Name</th>
                  <th>Change Type</th>
                  <th>Baseline Status</th>
                  <th>Remediated Status</th>
                  <th>Measured Difference</th>
                </tr>
              </thead>
              <tbody>
                {diff.checks.map((c) => {
                  const typeClass =
                    c.diff_type === "improved" ? "pass" : c.diff_type === "regressed" ? "fail" : "muted";
                  return (
                    <tr key={c.id}>
                      <td className="mono" style={{ fontWeight: 600 }}>{c.id}</td>
                      <td><b>{c.name}</b></td>
                      <td>
                        <span className={`badge ${typeClass}`}>
                          {c.diff_type.toUpperCase()}
                        </span>
                      </td>
                      <td><Badge s={c.base_status} /></td>
                      <td><Badge s={c.target_status} /></td>
                      <td className="mono" style={{ fontSize: "0.8rem" }}>
                        {c.base_measured !== c.target_measured ? (
                          <>
                            <span style={{ color: "var(--fail)" }}>- {String(c.base_measured)}</span>
                            <br />
                            <span style={{ color: "var(--pass)" }}>+ {String(c.target_measured)}</span>
                          </>
                        ) : (
                          <span className="muted">{String(c.target_measured)}</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
}

// ----------------------------------------------------
// 7. ASSESSMENT HISTORY & AUDIT TRAIL
// ----------------------------------------------------
function HistoryView({ go }) {
  const history = useApi("/history?limit=30");

  return (
    <>
      <Head
        title="Assessment History & Audit Trail"
        sub="Persistent SQLite record of all security assessments, timestamps, status ratings, and exportable reports."
      />
      <Async s={history}>
        {(rows) => (
          <>
            <div className="scroll">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Target</th>
                    <th>Assessment Time</th>
                    <th>Overall Status</th>
                    <th>Results Summary</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.id}>
                      <td className="mono" style={{ fontWeight: 600 }}>#{r.id}</td>
                      <td><b>{r.target}</b></td>
                      <td>{when(r.created_at)}</td>
                      <td>
                        <span className={`badge ${r.overall_status === "HEALTHY" ? "pass" : r.overall_status === "CRITICAL_RISK" ? "fail" : "review"}`}>
                          {r.overall_status.replace(/_/g, " ")}
                        </span>
                      </td>
                      <td style={{ fontSize: "0.85rem" }}>
                        <span style={{ color: "var(--pass)" }}>{r.summary.pass} Pass</span>,{" "}
                        <span style={{ color: "var(--review)" }}>{r.summary.review} Review</span>,{" "}
                        <span style={{ color: "var(--fail)" }}>{r.summary.critical + r.summary.high} Risk</span>
                      </td>
                      <td>
                        <a
                          className="btn ghost"
                          style={{ padding: "4px 10px", fontSize: "0.82rem", margin: "0 4px 0 0" }}
                          href={`${API}/report/${r.id}.html`}
                          target="_blank"
                          rel="noreferrer"
                        >
                          View HTML / PDF
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p>
              <button className="btn" onClick={() => go("Assessment & Risk")}>
                Run New Assessment
              </button>
              <button className="btn ghost" onClick={history.reload}>
                Refresh History
              </button>
            </p>
          </>
        )}
      </Async>
    </>
  );
}

// ----------------------------------------------------
// 8. AUTHORIZED REMOTE ASSESSMENT
// ----------------------------------------------------
function RemoteAssessment() {
  const [domain, setDomain] = useState("");
  const [port, setPort] = useState(443);
  const [auth, setAuth] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [err, setErr] = useState(null);

  const submit = (e) => {
    e.preventDefault();
    if (!auth) {
      setErr("You must confirm you are authorized to test this target domain.");
      return;
    }
    setBusy(true);
    setErr(null);
    api("/analysis/remote", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, port: Number(port), authorized: auth })
    })
      .then((res) => setResult(res))
      .catch((e) => setErr(e.message))
      .finally(() => setBusy(false));
  };

  return (
    <>
      <Head
        title="Authorized Remote-Domain Assessment"
        sub="Assess an external production domain that you own or have permission to evaluate. Includes strict rate limiting, domain validation, and SSRF loopback protections."
      />

      <div className="alert-box info">
        <b>Safeguards Enforced:</b> This tool will not probe private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
        loopback addresses, or cloud metadata endpoints. Only publicly resolvable FQDNs can be assessed.
      </div>

      <form className="form-card" onSubmit={submit}>
        <div className="form-group">
          <label>Target Domain (FQDN)</label>
          <input
            className="form-input"
            type="text"
            placeholder="example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            required
          />
        </div>
        <div className="form-group">
          <label>HTTPS Port</label>
          <input
            className="form-input"
            type="number"
            value={port}
            onChange={(e) => setPort(e.target.value)}
            required
          />
        </div>
        <div className="form-group">
          <label className="form-check">
            <input
              type="checkbox"
              checked={auth}
              onChange={(e) => setAuth(e.target.checked)}
            />
            <span>I confirm that I own or have explicit authorization to assess this target.</span>
          </label>
        </div>
        <button className="btn" type="submit" disabled={busy || !domain || !auth}>
          {busy ? "Assessing Target Domain..." : "Start Remote Assessment"}
        </button>
      </form>

      {err && <div className="alert-box critical">{err}</div>}

      {result && (
        <div style={{ marginTop: "24px" }}>
          <h2>Assessment Result for {result.target}</h2>
          <div className="stat-grid">
            <div className="stat-card pass">
              <span className="lbl">Security Score</span>
              <span className="val" style={{ color: result.risk_score?.color }}>{result.risk_score?.score} / 100</span>
            </div>
            <div className="stat-card pass">
              <span className="lbl">Passed Checks</span>
              <span className="val">{result.summary.pass}</span>
            </div>
            <div className="stat-card fail">
              <span className="lbl">Failed Checks</span>
              <span className="val">{result.summary.fail}</span>
            </div>
          </div>
          <p>
            <a className="btn" href={`${API}/report/${result.id}.html`} target="_blank" rel="noreferrer">
              View & Print Full Report
            </a>
          </p>
        </div>
      )}
    </>
  );
}

// ----------------------------------------------------
// 9. HANDSHAKE SIMULATOR
// ----------------------------------------------------
const STEPS = [
  ["client", "ClientHello", "The browser lists supported TLS versions and cipher suites, sends a random nonce and key share."],
  ["server", "ServerHello", "The server picks the TLS version and cipher suite, then sends its matching key share."],
  ["server", "EncryptedExtensions & Cert", "The server delivers its certificate and proves possession of the matching private key (encrypted in TLS 1.3)."],
  ["client", "Certificate Validation", "The browser checks validity dates, SAN matching, and validates the issuer against the root trust store."],
  ["client", "Finished", "Both sides verify handshake transcript integrity with HMAC. Session keys are activated."],
  ["server", "Application Data", "HTTP traffic travels fully encrypted inside TLS records with AEAD authentication."]
];

function Handshake() {
  const lab = useApi("/lab/status");
  const [i, setI] = useState(0);
  const [, title, text] = STEPS[i];
  const m = lab.data?.https;

  return (
    <>
      <Head
        title="TLS Handshake Interactive Walkthrough"
        sub="A visual step-by-step trace of the TLS 1.3 handshake exchange that occurs between your browser and the server."
      />
      <div className="lane">
        <span>Client (Browser)</span>
        <span>Server (localhost:{lab.data?.https_port || 8443})</span>
      </div>
      <div className="wire">
        {STEPS.map(([from, t], n) => (
          <button
            key={t}
            className={`msg ${from} ${n === i ? "on" : n < i ? "done" : ""}`}
            onClick={() => setI(n)}
          >
            <span className="lbl">{t}</span>
            <span className="line" />
          </button>
        ))}
      </div>
      <h2>{title}</h2>
      <p className="sub">{text}</p>
      {i === 1 && m?.reachable && (
        <p>
          <b>Live Measurement from your Lab:</b> <span className="mono">{m.tls_version}, {m.cipher}</span>
        </p>
      )}
      <button className="btn ghost" onClick={() => setI(i - 1)} disabled={i === 0}>
        Previous Step
      </button>
      <button className="btn" onClick={() => setI(i + 1)} disabled={i === STEPS.length - 1}>
        Next Step
      </button>
    </>
  );
}

// ----------------------------------------------------
// MAIN APP COMPONENT
// ----------------------------------------------------
const PAGES = {
  Overview,
  "Assessment & Risk": AssessmentView,
  "Cert Monitor": CertMonitorView,
  "Protocol Audit": ProtocolAudit,
  Certificate: CertificateView,
  Comparison: ComparisonView,
  History: HistoryView,
  "Remote Target": RemoteAssessment,
  Handshake
};

export default function App() {
  const [page, setPage] = useState("Overview");
  const Page = PAGES[page];

  return (
    <div className="app">
      <nav aria-label="Sections">
        <div className="brand">
          <span style={{ color: "var(--accent)" }}>🛡️</span> TLSentinel
        </div>
        <div className="brand-sub">Security Platform</div>
        <div className="nav-list">
          {Object.keys(PAGES).map((p) => (
            <button key={p} className={p === page ? "on" : ""} onClick={() => setPage(p)}>
              {p}
            </button>
          ))}
        </div>
        <div className="nav-footer">
          <div>TLSentinel v2.1</div>
          <div style={{ color: "var(--pass)", marginTop: "4px" }}>● Local Lab & APScheduler Active</div>
        </div>
      </nav>
      <main>
        <Page go={(p) => setPage(p)} />
      </main>
    </div>
  );
}
