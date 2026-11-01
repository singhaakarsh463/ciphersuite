"""TLSentinel - TLS Security Assessment Platform Backend API."""
import html
import ipaddress
import logging
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

import database
import scanner

logger = logging.getLogger("tlsentinel")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="TLSentinel API",
    description="Advanced TLS Security Assessment, Risk Scoring & Certificate Monitoring Platform",
    version="2.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://ciphersuite-blush.vercel.app"
    ],
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

HOST, HTTP_PORT, HTTPS_PORT = "localhost", 8080, 8443
scheduler: Optional[BackgroundScheduler] = None


def run_domain_monitoring_check():
    """Periodic job executed by APScheduler to monitor all registered domains."""
    try:
        domains = database.get_monitored_domains()
        for d in domains:
            if not d.get("enabled", 1):
                continue
            perform_domain_check(d["id"], d["domain"], d["port"], d.get("email"))
    except Exception as e:
        logger.error(f"Error during domain monitoring check: {e}")


def perform_domain_check(domain_id: int, domain: str, port: int = 443, email: Optional[str] = None) -> Dict[str, Any]:
    """Execute live TLS certificate check, update DB, and fire alerts/notifications if needed."""
    res = scanner.fetch_target_certificate(domain, port)
    now_iso = scanner.now_iso()

    days_left = res.get("days_left", -1)
    hours_left = res.get("hours_left", -1)
    status = res.get("status", "ERROR")
    alert_level = res.get("alert_level", "NORMAL")
    expiry_date = res.get("expiry_date") or ""
    issuer = res.get("issuer") or ""
    subject = res.get("subject") or ""

    database.update_monitored_domain(
        domain_id=domain_id,
        last_checked=now_iso,
        status=status,
        days_left=days_left,
        hours_left=hours_left,
        expiry_date=expiry_date,
        issuer=issuer,
        subject=subject,
        alert_level=alert_level
    )

    # Record notification if alert condition triggered
    if alert_level in ("NOTICE", "WARNING", "URGENT", "CRITICAL"):
        database.add_notification(
            domain_id=domain_id,
            domain=domain,
            alert_level=alert_level,
            message=res.get("alert_message", f"Certificate alert for {domain}: {days_left} days left"),
            channel="DASHBOARD"
        )
        if email:
            database.add_notification(
                domain_id=domain_id,
                domain=domain,
                alert_level=alert_level,
                message=f"[EMAIL DISPATCHED to {email}]: {res.get('alert_message')}",
                channel="EMAIL"
            )

    return res


@app.on_event("startup")
def on_startup():
    global scheduler
    database.init_db()

    # Seed localhost domain for monitoring if empty
    domains = database.get_monitored_domains()
    if not domains:
        did = database.add_monitored_domain("localhost", port=HTTPS_PORT)
        perform_domain_check(did, "localhost", port=HTTPS_PORT)

    # Start APScheduler for automated periodic certificate monitoring (every 60 seconds)
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(run_domain_monitoring_check, "interval", seconds=60, id="cert_monitor_job", replace_existing=True)
    scheduler.start()
    logger.info("APScheduler initialized for TLSentinel Certificate Monitoring.")


@app.on_event("shutdown")
def on_shutdown():
    global scheduler
    if scheduler and scheduler.running:
        scheduler.shutdown(wait=False)


@app.get("/health")
def health():
    return {"status": "ok", "platform": "TLSentinel", "version": app.version}


@app.get("/lab/status")
def lab_status():
    h = scanner.probe_http(HOST, HTTP_PORT)
    s = scanner.probe_https(HOST, HTTPS_PORT, target_hostname=HOST)
    s.pop("headers", None)
    s.pop("peer_cert_bytes", None)
    return {
        "platform": "TLSentinel",
        "host": HOST,
        "http_port": HTTP_PORT,
        "https_port": HTTPS_PORT,
        "http": h,
        "https": s,
        "http_reachable": h["reachable"],
        "https_reachable": s["reachable"],
        "redirect_target": h.get("redirect_target"),
        "service_verified": h.get("service_verified", False) and s.get("service_verified", False),
        "checked_at": scanner.now_iso()
    }


@app.get("/certificate")
def certificate():
    if not scanner.CERT_PATH.exists():
        raise HTTPException(404, "server.crt not found. Run lab-server/generate_certificate.py first.")
    c = scanner.read_certificate_data(scanner.CERT_PATH.read_bytes(), cert_source="server.crt", target_host=HOST)
    return {**c, "checked_at": scanner.now_iso()}


@app.get("/audit/protocols")
def audit_protocols(host: str = HOST, port: int = HTTPS_PORT):
    return scanner.audit_tls_protocols(host, port)


@app.post("/analysis/local")
def analysis_local():
    report = scanner.run_full_assessment(target=HOST, http_port=HTTP_PORT, https_port=HTTPS_PORT, is_remote=False)
    aid = database.save_assessment(target=HOST, overall_status=report["overall_status"], summary=report["summary"], details=report)
    report["id"] = aid
    return report


class RemoteScanRequest(BaseModel):
    domain: str
    port: int = 443
    authorized: bool


@app.post("/analysis/remote")
def analysis_remote(req: RemoteScanRequest):
    if not req.authorized:
        raise HTTPException(400, "You must explicitly confirm you are authorized to assess this target.")

    domain = req.domain.strip().lower()
    if not domain or len(domain) > 253:
        raise HTTPException(400, "Invalid domain name.")

    # Resolve IP and enforce anti-SSRF protections against private, loopback, link-local, multicast addresses
    try:
        resolved = socket.getaddrinfo(domain, req.port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        if not resolved:
            raise HTTPException(400, f"Could not resolve domain {domain}.")
        target_ip_str = resolved[0][4][0]
        ip_obj = ipaddress.ip_address(target_ip_str)

        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
            raise HTTPException(400, f"Scanning internal or private address ({target_ip_str}) is prohibited.")
    except socket.gaierror as e:
        raise HTTPException(400, f"DNS resolution failed for {domain}: {e}")
    except ValueError as e:
        raise HTTPException(400, f"Invalid IP/host: {e}")

    # Run assessment
    report = scanner.run_full_assessment(target=domain, http_port=80, https_port=req.port, is_remote=True)
    aid = database.save_assessment(target=domain, overall_status=report["overall_status"], summary=report["summary"], details=report)
    report["id"] = aid
    return report


# ===================================================================
# Certificate Expiry Monitoring Endpoints
# ===================================================================

class RegisterDomainRequest(BaseModel):
    domain: str
    port: int = 443
    email: Optional[str] = None


@app.get("/api/monitor/domains")
def list_monitored_domains():
    return database.get_monitored_domains()


@app.post("/api/monitor/domains")
def register_domain(req: RegisterDomainRequest):
    domain_clean = req.domain.strip().lower()
    if not domain_clean:
        raise HTTPException(400, "Domain name is required.")
    
    # Save/register domain
    did = database.add_monitored_domain(domain_clean, port=req.port, email=req.email)
    
    # Immediately check certificate
    check_res = perform_domain_check(did, domain_clean, port=req.port, email=req.email)
    record = database.get_monitored_domain(did)
    return {"message": f"Domain {domain_clean} registered for monitoring.", "domain": record, "check_result": check_res}


@app.delete("/api/monitor/domains/{domain_id}")
def delete_domain(domain_id: int):
    database.delete_monitored_domain(domain_id)
    return {"message": f"Domain #{domain_id} deleted from monitoring."}


@app.post("/api/monitor/domains/{domain_id}/check")
def trigger_domain_check(domain_id: int):
    d = database.get_monitored_domain(domain_id)
    if not d:
        raise HTTPException(404, "Monitored domain not found.")
    res = perform_domain_check(d["id"], d["domain"], d["port"], d.get("email"))
    record = database.get_monitored_domain(domain_id)
    return {"domain": record, "check_result": res}


@app.post("/api/monitor/check-all")
def check_all_domains():
    domains = database.get_monitored_domains()
    results = []
    for d in domains:
        if d.get("enabled", 1):
            r = perform_domain_check(d["id"], d["domain"], d["port"], d.get("email"))
            results.append({"domain": d["domain"], "status": r.get("status"), "days_left": r.get("days_left")})
    return {"checked": len(results), "results": results}


@app.get("/api/monitor/alerts")
def list_monitoring_alerts(limit: int = Query(50, ge=1, le=100)):
    return database.get_notifications(limit=limit)


# ===================================================================
# History, Diff & Reports
# ===================================================================

@app.get("/history")
def history(limit: int = Query(30, ge=1, le=100)):
    return database.get_history(limit=limit)


@app.get("/history/{assessment_id}")
def get_assessment(assessment_id: int):
    record = database.get_assessment(assessment_id)
    if not record:
        raise HTTPException(404, f"Assessment #{assessment_id} not found.")
    return record


@app.get("/compare")
def compare_assessments(base_id: int = Query(..., description="Original/baseline assessment ID"),
                        target_id: int = Query(..., description="Target/remediated assessment ID")):
    try:
        return database.compare_assessments(base_id, target_id)
    except ValueError as e:
        raise HTTPException(404, str(e))


@app.get("/report/latest")
def report_latest():
    history_items = database.get_history(limit=1)
    if history_items:
        return database.get_assessment(history_items[0]["id"])
    return analysis_local()


@app.get("/report/{assessment_id}.html", response_class=HTMLResponse)
def report_html_by_id(assessment_id: int):
    record = database.get_assessment(assessment_id)
    if not record:
        raise HTTPException(404, f"Assessment #{assessment_id} not found.")
    return render_report_html(record)


@app.get("/report/latest.html", response_class=HTMLResponse)
def report_html_latest():
    history_items = database.get_history(limit=1)
    if history_items:
        record = database.get_assessment(history_items[0]["id"])
    else:
        record = analysis_local()
    return render_report_html(record)


def render_report_html(r: Dict[str, Any]) -> HTMLResponse:
    e = html.escape
    target = e(r.get("target", "localhost"))
    gen_time = e(r.get("generated_at", ""))
    status = e(r.get("overall_status", "UNKNOWN"))

    # Risk Score Data (Phoenix Security ASPM Style)
    risk = r.get("risk_score") or {}
    score = risk.get("score", 100)
    tier = e(risk.get("tier", "Good"))
    risk_color = risk.get("color", "#10b981")
    ai_narrative = risk.get("ai_explanation") or {}

    # Status badge color
    status_color = "#10b981" if status == "HEALTHY" else "#f59e0b" if "REVIEW" in status or "ACCEPTABLE" in status else "#ef4444"

    # Deduction rows
    deductions_html = ""
    for d in risk.get("deductions", []):
        sev_color = "#ef4444" if d["severity"] == "CRITICAL" else "#f97316" if d["severity"] == "HIGH" else "#f59e0b" if d["severity"] == "MEDIUM" else "#10b981"
        deductions_html += f"""<tr>
            <td style="font-family:monospace;font-weight:bold">{e(d['check_id'])}</td>
            <td><b>{e(d['name'])}</b></td>
            <td><span style="color:{sev_color};font-weight:bold">-{d['points']} pts</span></td>
            <td><span style="background:{sev_color}22;color:{sev_color};padding:2px 6px;border-radius:4px;font-size:11px;">{e(d['severity'])}</span></td>
            <td>{e(d['reason'])}</td>
        </tr>"""

    # Findings rows
    findings_rows = ""
    for c in r.get("results", []):
        sev = c.get("severity", "INFO")
        sev_color = "#ef4444" if sev == "CRITICAL" else "#f97316" if sev == "HIGH" else "#f59e0b" if sev == "MEDIUM" else "#10b981"
        st = c.get("status", "")
        st_color = "#10b981" if st == "PASS" else "#f59e0b" if st == "REVIEW" else "#ef4444"

        findings_rows += f"""<tr>
            <td style="font-family:monospace;font-weight:bold">{e(c['id'])}</td>
            <td><b>{e(c['name'])}</b><br><small style="color:#64748b">{e(c.get('category',''))}</small></td>
            <td><span style="background:{sev_color}22;color:{sev_color};padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold">{e(sev)}</span></td>
            <td><span style="color:{st_color};font-weight:bold">{e(st)}</span></td>
            <td><code>{e(str(c['measured']))}</code></td>
            <td>{e(c['explanation'])}</td>
            <td style="font-size:13px;color:#334155">{e(c.get('remediation',''))}</td>
        </tr>"""

    cert = r.get("certificate") or {}
    cert_html = ""
    if cert:
        cert_html = f"""
        <h2>Certificate Inspection</h2>
        <table class="grid">
            <tr><th>Subject</th><td>{e(cert.get('subject',''))}</td><th>Key</th><td>{e(str(cert.get('key_type')))} {e(str(cert.get('key_size')))} bits</td></tr>
            <tr><th>Issuer</th><td>{e(cert.get('issuer',''))}</td><th>Signature Hash</th><td>{e(str(cert.get('signature_hash')).upper())}</td></tr>
            <tr><th>Valid From</th><td>{e(cert.get('not_before',''))}</td><th>Valid Until</th><td>{e(cert.get('not_after',''))} ({cert.get('days_left')} days)</td></tr>
            <tr><th>SANs</th><td>{e(', '.join(cert.get('san', [])))}</td><th>SHA-256 Fingerprint</th><td style="font-family:monospace;word-break:break-all">{e(cert.get('fingerprint_sha256',''))}</td></tr>
        </table>
        """

    summ = r.get("summary", {})
    body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>TLSentinel Security Assessment Report - {target}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 1040px; margin: 30px auto; padding: 0 20px; color: #0f172a; line-height: 1.5; }}
  h1, h2, h3 {{ color: #0f172a; }}
  .header {{ border-bottom: 2px solid #e2e8f0; padding-bottom: 16px; margin-bottom: 24px; }}
  .score-card {{ display: flex; align-items: center; justify-content: space-between; background: #0f172a; color: #fff; padding: 24px; border-radius: 10px; margin: 20px 0; }}
  .score-circle {{ font-size: 48px; font-weight: 800; color: {risk_color}; }}
  .badge {{ display: inline-block; padding: 4px 12px; border-radius: 9999px; font-weight: bold; font-size: 14px; text-transform: uppercase; }}
  .summary-cards {{ display: flex; gap: 16px; margin: 20px 0; }}
  .card {{ flex: 1; padding: 14px; border: 1px solid #e2e8f0; border-radius: 8px; background: #f8fafc; text-align: center; }}
  .card .num {{ font-size: 26px; font-weight: bold; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0 32px 0; font-size: 14px; }}
  th, td {{ border: 1px solid #cbd5e1; padding: 8px 12px; text-align: left; vertical-align: top; }}
  th {{ background: #f1f5f9; font-weight: 600; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; background: #f1f5f9; padding: 2px 4px; border-radius: 3px; }}
  .actions {{ margin-bottom: 24px; }}
  .btn-print {{ background: #2563eb; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-weight: 600; cursor: pointer; }}
  .ai-box {{ background: #eff6ff; border-left: 4px solid #3b82f6; padding: 16px; border-radius: 6px; margin: 18px 0; }}
  @media print {{
    .actions {{ display: none; }}
    body {{ max-width: 100%; margin: 0; padding: 0; }}
    table {{ page-break-inside: auto; }}
    tr {{ page-break-inside: avoid; page-break-after: auto; }}
  }}
</style>
</head>
<body>
<div class="actions">
  <button class="btn-print" onclick="window.print()">Print / Save as PDF</button>
</div>
<div class="header">
  <div style="display:flex; justify-content:space-between; align-items:center;">
    <div>
      <h1 style="margin:0 0 6px 0;">TLSentinel Security Assessment</h1>
      <p style="margin:0; color:#64748b;">Target: <b>{target}</b> | Generated: {gen_time}</p>
    </div>
    <div>
      <span class="badge" style="background:{status_color}22; color:{status_color}; border:1px solid {status_color}">{status}</span>
    </div>
  </div>
</div>

<!-- Phoenix Security ASPM Style Score Card -->
<div class="score-card">
  <div>
    <div style="font-size:14px; text-transform:uppercase; letter-spacing:0.06em; color:#94a3b8;">Quantified Security Score</div>
    <div style="font-size:28px; font-weight:700; margin:4px 0 8px 0;">{tier} Security Posture</div>
    <div style="font-size:14px; color:#cbd5e1;">Evaluated against industry cryptographic and transport standards.</div>
  </div>
  <div style="text-align:right;">
    <div class="score-circle">{score} <span style="font-size:22px; color:#94a3b8;">/ 100</span></div>
  </div>
</div>

<div class="ai-box">
  <h3 style="margin:0 0 8px 0; color:#1e40af;">AI Technical Narrative & Remediation Summary</h3>
  <p style="margin:0 0 10px 0;">{e(ai_narrative.get('summary', ''))}</p>
  <b>Recommended Action Plan:</b>
  <ul style="margin:6px 0 0 0; padding-left:20px;">
    {''.join(f'<li>{e(act)}</li>' for act in ai_narrative.get('recommended_actions', []))}
  </ul>
</div>

<div class="summary-cards">
  <div class="card"><div style="color:#10b981">Passed Checks</div><div class="num" style="color:#10b981">{summ.get('pass', 0)}</div></div>
  <div class="card"><div style="color:#f59e0b">Review Needed</div><div class="num" style="color:#f59e0b">{summ.get('review', 0)}</div></div>
  <div class="card"><div style="color:#ef4444">Failed / Critical</div><div class="num" style="color:#ef4444">{summ.get('fail', 0) + summ.get('critical', 0)}</div></div>
  <div class="card"><div style="color:#3b82f6">Total Checks</div><div class="num">{len(r.get('results', []))}</div></div>
</div>

{f"<h3>Risk Point Deductions</h3><table><tr><th>Check ID</th><th>Finding</th><th>Points Deducted</th><th>Severity</th><th>Impact Reason</th></tr>{deductions_html}</table>" if deductions_html else ""}

{cert_html}

<h2>Security Findings & Technical Evidence</h2>
<table>
  <tr><th>ID</th><th>Check & Category</th><th>Severity</th><th>Result</th><th>Measured</th><th>Explanation</th><th>Remediation</th></tr>
  {findings_rows}
</table>

<h2>Limitations & Scope</h2>
<ul>{''.join(f'<li>{e(lim)}</li>' for lim in r.get('limitations', []))}</ul>

<footer style="margin-top:40px; border-top:1px solid #e2e8f0; padding-top:16px; color:#94a3b8; font-size:12px; text-align:center;">
  Generated by TLSentinel Security Assessment Platform
</footer>
</body>
</html>"""
    return HTMLResponse(body, headers={"Content-Disposition": f"inline; filename=tlsentinel-report-{target}.html"})
