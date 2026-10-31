"""TLSentinel Security Scanner, Assessment & Risk Scoring Engine.
Performs real reproducible measurements against TLS endpoints and certificates.
"""
import html
import http.client
import ipaddress
import platform
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes

LAB_ROOT = Path(__file__).resolve().parent.parent / "lab-server"
CERT_PATH = LAB_ROOT / "server.crt"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def verify_service_identity(headers: Dict[str, str], body_text: str = "", is_https: bool = False) -> Tuple[bool, str]:
    """Verify if the responding endpoint is genuinely the expected TLSentinel lab service,

    mitigating port conflict risks where an unrelated service occupies 8080/8443.
    """
    has_lab_header = headers.get("x-tlsentinel-lab") == "v1" or headers.get("server") == "TLSentinel-Lab"
    has_lab_body = "HTTPS Lab" in body_text or "HTTPS lab server" in body_text

    if has_lab_header or has_lab_body:
        return True, "Verified TLSentinel Lab service identity via server signatures."

    # In case user or standard script is running without custom header but standard redirect
    if not is_https and headers.get("location", "").startswith("https://localhost:8443"):
        return True, "Redirect target matches expected lab HTTPS endpoint (:8443)."

    return False, "Unknown or unexpected service responding on this port. Expected TLSentinel lab service."


def check_hostname_match(cert_sans: List[str], target_host: str) -> Tuple[bool, str]:
    """RFC 6125 compliant hostname and SAN evaluation including IP and wildcard matching."""
    if not cert_sans:
        return False, "Certificate has no Subject Alternative Names (SANs)."

    target_clean = target_host.strip().lower()
    is_ip = False
    try:
        ipaddress.ip_address(target_clean)
        is_ip = True
    except ValueError:
        is_ip = False

    for san in cert_sans:
        san_clean = san.strip().lower()
        if is_ip:
            if san_clean == target_clean or san_clean == f"ip:{target_clean}":
                return True, f"Target IP {target_host} matches SAN {san}"
        else:
            if san_clean == target_clean or san_clean == f"dns:{target_clean}":
                return True, f"Target hostname {target_host} matches SAN {san}"
            # Wildcard matching *.domain.com
            if san_clean.startswith("*."):
                domain_suffix = san_clean[2:]
                parts = target_clean.split(".")
                if len(parts) > 1 and ".".join(parts[1:]) == domain_suffix:
                    return True, f"Target {target_host} matches wildcard SAN {san}"

    return False, f"Target '{target_host}' was not found in certificate SAN list ({', '.join(cert_sans)})."


def verify_trust_store(host: str, port: int) -> Dict[str, Any]:
    """Actively test certificate validation against the system root trust store."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                return {
                    "trusted": True,
                    "reason": "Validated against system CA trust store.",
                    "error_code": None,
                    "raw_error": None
                }
    except ssl.SSLCertVerificationError as e:
        msg = str(e)
        code = getattr(e, "verify_code", None)
        message = getattr(e, "verify_message", str(e))
        return {
            "trusted": False,
            "reason": f"Trust validation failed: {message}",
            "error_code": code,
            "raw_error": msg
        }
    except Exception as e:
        return {
            "trusted": False,
            "reason": f"Connection/handshake error during trust check: {e}",
            "error_code": None,
            "raw_error": str(e)
        }


def read_certificate_data(cert_bytes: bytes, cert_source: str = "server.crt", target_host: str = "localhost") -> Dict[str, Any]:
    """Parse X.509 certificate and evaluate dates, key strength, SANs, and trust."""
    try:
        c = x509.load_pem_x509_certificate(cert_bytes)
    except Exception:
        c = x509.load_der_x509_certificate(cert_bytes)
    pub = c.public_key()
    fp = c.fingerprint(hashes.SHA256()).hex().upper()

    try:
        san_ext = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(n.value) for n in san_ext]
    except x509.ExtensionNotFound:
        names = []

    now = datetime.now(timezone.utc)
    not_before = c.not_valid_before_utc
    not_after = c.not_valid_after_utc

    not_yet_valid = now < not_before
    expired = now > not_after
    days_left = (not_after - now).days
    hours_left = int((not_after - now).total_seconds() / 3600)

    # Multi-tier expiry assessment
    if expired:
        expiry_status = "EXPIRED"
        expiry_severity = "CRITICAL"
        expiry_msg = f"Certificate expired {abs(days_left)} days ago ({not_after.strftime('%Y-%m-%d %H:%M UTC')})."
    elif not_yet_valid:
        expiry_status = "NOT_YET_VALID"
        expiry_severity = "CRITICAL"
        expiry_msg = f"Certificate is not valid until {not_before.strftime('%Y-%m-%d %H:%M UTC')}."
    elif hours_left <= 24:
        expiry_status = "CRITICAL_EXPIRY"
        expiry_severity = "CRITICAL"
        expiry_msg = f"Certificate expires within 24 hours ({hours_left} hours left)!"
    elif days_left <= 7:
        expiry_status = "URGENT_EXPIRY"
        expiry_severity = "HIGH"
        expiry_msg = f"Certificate expires within 7 days ({days_left} days left)."
    elif days_left <= 15:
        expiry_status = "WARNING_EXPIRY"
        expiry_severity = "HIGH"
        expiry_msg = f"Certificate expires within 15 days ({days_left} days left)."
    elif days_left <= 30:
        expiry_status = "NOTICE_EXPIRY"
        expiry_severity = "MEDIUM"
        expiry_msg = f"Certificate expires in {days_left} days (less than 30 days)."
    else:
        expiry_status = "HEALTHY"
        expiry_severity = "LOW"
        expiry_msg = f"Valid until {not_after.strftime('%Y-%m-%d')} ({days_left} days remaining)."

    is_self_signed = (c.subject == c.issuer)

    key_type = type(pub).__name__.strip("_").replace("PublicKey", "")
    key_size = getattr(pub, "key_size", None)

    # Hostname matching evaluation
    san_matched, san_match_reason = check_hostname_match(names, target_host)

    return {
        "subject": c.subject.rfc4514_string(),
        "issuer": c.issuer.rfc4514_string(),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": days_left,
        "hours_left": hours_left,
        "expiry_status": expiry_status,
        "expiry_severity": expiry_severity,
        "expiry_message": expiry_msg,
        "fingerprint_sha256": ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)),
        "serial": format(c.serial_number, "X"),
        "key_type": key_type,
        "key_size": key_size,
        "signature_hash": c.signature_hash_algorithm.name,
        "san": names,
        "self_signed": is_self_signed,
        "hostname_matched": san_matched,
        "hostname_reason": san_match_reason,
        "source": cert_source
    }


def audit_tls_protocols(host: str, port: int) -> Dict[str, Any]:
    """Perform multi-version protocol handshake testing to produce a compatibility matrix."""
    protocols_to_test = [
        ("TLSv1.0", ssl.TLSVersion.TLSv1, "DEPRECATED", "CRITICAL"),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1, "DEPRECATED", "HIGH"),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2, "SECURE", "LOW"),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3, "MODERN", "LOW"),
    ]

    results = []
    accepted_count = 0
    deprecated_accepted = False

    for name, proto_ver, expected_tier, risk in protocols_to_test:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = proto_ver
            ctx.maximum_version = proto_ver
            with socket.create_connection((host, port), timeout=2) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    cipher_info = ss.cipher()
                    cipher_name = cipher_info[0] if cipher_info else "Unknown"
                    cipher_bits = cipher_info[2] if cipher_info else 0
                    is_aead = any(x in cipher_name for x in ("GCM", "CHACHA20", "POLY1305"))
                    is_pfs = "ECDHE" in cipher_name or "DHE" in cipher_name or proto_ver == ssl.TLSVersion.TLSv1_3

                    accepted_count += 1
                    if expected_tier == "DEPRECATED":
                        deprecated_accepted = True

                    results.append({
                        "protocol": name,
                        "accepted": True,
                        "status": "ACCEPTED",
                        "tier": expected_tier,
                        "cipher": cipher_name,
                        "cipher_bits": cipher_bits,
                        "aead": is_aead,
                        "pfs": is_pfs,
                        "security_note": "Legacy protocol accepted - vulnerable!" if expected_tier == "DEPRECATED" else "Standard protocol active."
                    })
        except Exception as e:
            err_str = str(e)
            results.append({
                "protocol": name,
                "accepted": False,
                "status": "REJECTED",
                "tier": expected_tier,
                "cipher": None,
                "cipher_bits": None,
                "aead": False,
                "pfs": False,
                "security_note": f"Rejected by server ({type(e).__name__})" if "HANDSHAKE" in err_str.upper() or "WRONG_VERSION" in err_str.upper() or "NO_CIPHERS" in err_str.upper() or "RESET" in err_str.upper() else f"Not negotiated ({err_str[:40]})"
            })

    return {
        "matrix": results,
        "deprecated_accepted": deprecated_accepted,
        "accepted_count": accepted_count,
        "supports_tls13": any(r["protocol"] == "TLSv1.3" and r["accepted"] for r in results),
        "supports_tls12": any(r["protocol"] == "TLSv1.2" and r["accepted"] for r in results)
    }


def probe_http(host: str, port: int, timeout: int = 3) -> Dict[str, Any]:
    """Probe plain HTTP port, inspect redirect, and check service identity."""
    try:
        c = http.client.HTTPConnection(host, port, timeout=timeout)
        c.request("GET", "/")
        r = c.getresponse()
        loc = r.getheader("Location")
        raw_headers = {k.lower(): v for k, v in r.getheaders()}
        body = r.read(1024).decode("utf-8", errors="ignore")
        c.close()

        is_lab_service, service_note = verify_service_identity(raw_headers, body, is_https=False)

        return {
            "reachable": True,
            "status": r.status,
            "redirect_target": loc,
            "headers": raw_headers,
            "service_verified": is_lab_service,
            "service_note": service_note
        }
    except Exception as e:
        return {"reachable": False, "error": str(e), "service_verified": False, "service_note": "Service unreachable"}


def probe_https(host: str, port: int, target_hostname: str = "localhost", timeout: int = 3) -> Dict[str, Any]:
    """Probe HTTPS port without trust store abort to measure protocol & headers."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=target_hostname) as t:
                cipher, _, bits = t.cipher()
                version = t.version()
                peer_cert = t.getpeercert(binary_form=True)

                t.sendall(f"GET / HTTP/1.1\r\nHost: {target_hostname}\r\nConnection: close\r\n\r\n".encode("utf-8"))
                data = b""
                while len(data) < 65536 and (ch := t.recv(4096)):
                    data += ch

        parts = data.split(b"\r\n\r\n", 1)
        header_text = parts[0].decode("latin-1")
        body_text = parts[1].decode("utf-8", errors="ignore") if len(parts) > 1 else ""

        lines = header_text.split("\r\n")[1:]
        headers = {k.strip().lower(): v.strip() for k, _, v in (l.partition(":") for l in lines)}

        is_lab_service, service_note = verify_service_identity(headers, body_text, is_https=True)

        return {
            "reachable": True,
            "tls_version": version,
            "cipher": cipher,
            "cipher_bits": bits,
            "headers": headers,
            "peer_cert_bytes": peer_cert,
            "service_verified": is_lab_service,
            "service_note": service_note
        }
    except Exception as e:
        return {"reachable": False, "error": str(e), "service_verified": False, "service_note": "Service unreachable"}


# ===================================================================
# AI-Powered Security Risk Scoring Engine (Phoenix Security / ASPM style)
# ===================================================================

def calculate_risk_score(checks: List[Dict[str, Any]], target: str, is_remote: bool = False) -> Dict[str, Any]:
    """Calculate quantified 0-100 Security Risk Score based on real scan findings

    Formula: Score = max(0, 100 - Total Risk Points)
    Assigns calibrated penalty points and generates an AI technical explanation narrative.
    """
    total_deductions = 0
    deductions_list = []
    
    # Map checks by ID
    c_map = {c["id"]: c for c in checks}

    # Weight definitions based on industry risk standards
    # 1. Certificate Expiry / Date Validity
    c07 = c_map.get("C07")
    if c07:
        if c07["status"] == "FAIL" or "expired" in str(c07["measured"]).lower():
            pts = 30
            total_deductions += pts
            deductions_list.append({"check_id": "C07", "name": "Expired Certificate", "points": pts, "severity": "CRITICAL", "reason": "Certificate is expired or not yet valid, breaking browser trust entirely."})
        elif c07["severity"] == "HIGH" or "urgent" in str(c07["measured"]).lower() or "warning" in str(c07["measured"]).lower():
            pts = 15
            total_deductions += pts
            deductions_list.append({"check_id": "C07", "name": "Imminent Certificate Expiry", "points": pts, "severity": "HIGH", "reason": "Certificate expires in less than 15 days."})
        elif c07["severity"] == "MEDIUM" or "notice" in str(c07["measured"]).lower():
            pts = 5
            total_deductions += pts
            deductions_list.append({"check_id": "C07", "name": "Certificate Expiry Notice", "points": pts, "severity": "MEDIUM", "reason": "Certificate expires within 30 days."})

    # 2. Deprecated TLS Protocols
    c_proto = c_map.get("C05_PROTO")
    if c_proto and c_proto["status"] == "FAIL":
        pts = 25
        total_deductions += pts
        deductions_list.append({"check_id": "C05_PROTO", "name": "Deprecated TLS Protocols Accepted", "points": pts, "severity": "CRITICAL", "reason": "Server accepts legacy TLS 1.0 or 1.1 vulnerable to POODLE/BEAST attacks."})

    # 3. Hostname / SAN Mismatch
    c10 = c_map.get("C10")
    if c10 and c10["status"] == "FAIL":
        pts = 25
        total_deductions += pts
        deductions_list.append({"check_id": "C10", "name": "Hostname / SAN Mismatch", "points": pts, "severity": "HIGH", "reason": "Certificate SAN list does not match target hostname, triggering browser security warnings."})

    # 4. Weak Key Strength
    c08 = c_map.get("C08")
    if c08 and c08["status"] == "FAIL":
        pts = 15
        total_deductions += pts
        deductions_list.append({"check_id": "C08", "name": "Weak Cryptographic Key", "points": pts, "severity": "HIGH", "reason": "RSA key size is under 2048 bits or uses weak curves."})

    # 5. Broken Signature Algorithm
    c09 = c_map.get("C09")
    if c09 and c09["status"] == "FAIL":
        pts = 15
        total_deductions += pts
        deductions_list.append({"check_id": "C09", "name": "Broken Signature Hash", "points": pts, "severity": "CRITICAL", "reason": "Certificate signed with broken hash (MD5 or SHA-1), vulnerable to collision attacks."})

    # 6. HTTP Redirect to HTTPS
    c01 = c_map.get("C01")
    if c01 and c01["status"] in ("FAIL", "REVIEW"):
        pts = 15
        total_deductions += pts
        deductions_list.append({"check_id": "C01", "name": "Plain HTTP Not Redirected", "points": pts, "severity": "HIGH", "reason": "Port 80/8080 does not enforce a 301/302 HTTPS upgrade, leaving traffic exposed to sniffing."})

    # 7. Non-AEAD Cipher Suite
    c04 = c_map.get("C04")
    if c04 and c04["status"] == "REVIEW":
        pts = 10
        total_deductions += pts
        deductions_list.append({"check_id": "C04", "name": "Non-AEAD Cipher Suite", "points": pts, "severity": "HIGH", "reason": "Negotiated cipher does not provide authenticated encryption (AEAD), risking packet tampering."})

    # 8. Certificate Trust-Store Chain
    c06 = c_map.get("C06")
    if c06 and c06["status"] == "REVIEW":
        pts = 20 if is_remote else 5
        total_deductions += pts
        deductions_list.append({"check_id": "C06", "name": "Untrusted Certificate / Chain Error", "points": pts, "severity": "HIGH" if is_remote else "LOW", "reason": "Certificate untrusted by system trust store (Normal for local lab; High risk for production)." if not is_remote else "Certificate chain validation failed against public trust store."})

    # 9. Strict-Transport-Security (HSTS)
    c11 = c_map.get("C11")
    if c11 and c11["status"] == "REVIEW":
        pts = 10
        total_deductions += pts
        deductions_list.append({"check_id": "C11", "name": "Missing HSTS Header", "points": pts, "severity": "MEDIUM", "reason": "Missing Strict-Transport-Security header leaves users vulnerable to SSL-stripping downgrades."})

    # 10. Content-Security-Policy (CSP)
    c13 = c_map.get("C13")
    if c13 and c13["status"] == "REVIEW":
        pts = 5
        total_deductions += pts
        deductions_list.append({"check_id": "C13", "name": "Missing Content-Security-Policy", "points": pts, "severity": "LOW", "reason": "No Content-Security-Policy header defined to restrict malicious inline scripts."})

    # 11. X-Content-Type-Options
    c12 = c_map.get("C12")
    if c12 and c12["status"] == "REVIEW":
        pts = 5
        total_deductions += pts
        deductions_list.append({"check_id": "C12", "name": "Missing nosniff Header", "points": pts, "severity": "LOW", "reason": "X-Content-Type-Options: nosniff header missing, allowing MIME-sniffing."})

    score = max(0, min(100, 100 - total_deductions))

    # Risk Tier Classification
    if score >= 90:
        tier = "Excellent"
        risk_level = "Low Risk"
        color = "#10b981"
        badge_class = "pass"
    elif score >= 75:
        tier = "Good"
        risk_level = "Moderate Risk"
        color = "#3b82f6"
        badge_class = "pass"
    elif score >= 50:
        tier = "Moderate"
        risk_level = "Medium Risk"
        color = "#f59e0b"
        badge_class = "review"
    elif score >= 25:
        tier = "High Risk"
        risk_level = "High Risk"
        color = "#f97316"
        badge_class = "fail"
    else:
        tier = "Critical Risk"
        risk_level = "Critical Risk"
        color = "#ef4444"
        badge_class = "fail"

    # AI Explanation Synthesis grounded in measurements
    ai_narrative = generate_ai_explanation(score, tier, deductions_list, checks, target, is_remote)

    # Findings counts by severity
    critical_count = sum(1 for d in deductions_list if d["severity"] == "CRITICAL")
    high_count = sum(1 for d in deductions_list if d["severity"] == "HIGH")
    medium_count = sum(1 for d in deductions_list if d["severity"] == "MEDIUM")
    low_count = sum(1 for d in deductions_list if d["severity"] == "LOW")

    return {
        "score": score,
        "max_score": 100,
        "tier": tier,
        "risk_level": risk_level,
        "color": color,
        "badge_class": badge_class,
        "total_deductions": total_deductions,
        "deductions": deductions_list,
        "severity_breakdown": {
            "critical": {"count": critical_count, "points": sum(d["points"] for d in deductions_list if d["severity"] == "CRITICAL")},
            "high": {"count": high_count, "points": sum(d["points"] for d in deductions_list if d["severity"] == "HIGH")},
            "medium": {"count": medium_count, "points": sum(d["points"] for d in deductions_list if d["severity"] == "MEDIUM")},
            "low": {"count": low_count, "points": sum(d["points"] for d in deductions_list if d["severity"] == "LOW")},
        },
        "ai_explanation": ai_narrative
    }


def generate_ai_explanation(score: int, tier: str, deductions: List[Dict[str, Any]], checks: List[Dict[str, Any]], target: str, is_remote: bool) -> Dict[str, Any]:
    """Generates an automated, factual technical narrative synthesizing security posture."""
    highlights = []
    top_risks = []
    action_items = []

    # Positive attributes
    tls13 = any(c["id"] == "C03" and "TLSv1.3" in str(c["measured"]) for c in checks)
    aead = any(c["id"] == "C04" and c["status"] == "PASS" for c in checks)
    redirect = any(c["id"] == "C01" and c["status"] == "PASS" for c in checks)
    rsa_strong = any(c["id"] == "C08" and c["status"] == "PASS" for c in checks)

    if tls13:
        highlights.append("Modern TLS 1.3 negotiated with zero round-trip overhead and strong encryption.")
    if aead:
        highlights.append("Authenticated Encryption (AEAD) ciphers active, preventing ciphertext tampering.")
    if redirect:
        highlights.append("HTTP requests automatically upgraded to HTTPS via 301 Moved Permanently.")
    if rsa_strong:
        highlights.append("Cryptographic keys meet or exceed industry strength standards (≥2048-bit RSA / ECDSA).")

    # Risk drivers
    for d in deductions:
        top_risks.append(f"{d['name']} (-{d['points']} pts): {d['reason']}")
        if d["check_id"] == "C07":
            action_items.append("Renew the expiring SSL/TLS certificate to prevent browser connection outages.")
        elif d["check_id"] == "C05_PROTO":
            action_items.append("Disable TLS 1.0 and 1.1 in web server configuration to satisfy RFC 8996 compliance.")
        elif d["check_id"] == "C11":
            action_items.append("Configure the HTTP Strict-Transport-Security (HSTS) response header.")
        elif d["check_id"] == "C13":
            action_items.append("Deploy a Content-Security-Policy (CSP) header to restrict external resource execution.")
        elif d["check_id"] == "C10":
            action_items.append("Re-issue the certificate with proper Subject Alternative Names (SANs) for this target.")

    if not top_risks:
        top_risks.append("No critical or high-severity vulnerabilities identified during scan.")
        action_items.append("Continue periodic certificate expiry monitoring and posture audits.")

    summary = (
        f"Target '{target}' received a Security Score of {score}/100, classified as {tier} ({score >= 75 and 'Satisfactory' or 'Remediation Required'}). "
        f"{len(highlights)} positive security controls verified. {len(deductions)} risk deductions recorded based on measured technical findings."
    )

    return {
        "summary": summary,
        "positive_highlights": highlights,
        "top_risk_drivers": top_risks,
        "recommended_actions": action_items[:4]
    }


# ===================================================================
# Standalone Certificate Fetcher for Domain Expiry Monitoring
# ===================================================================

def fetch_target_certificate(domain: str, port: int = 443, timeout: int = 4) -> Dict[str, Any]:
    """Connects to any remote or local domain on specified port, extracts X.509 cert,

    and evaluates expiration countdown for monitoring alerts.
    """
    clean_domain = domain.strip().lower()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((clean_domain, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=clean_domain) as ss:
                peer_der = ss.getpeercert(binary_form=True)
                cipher = ss.cipher()
                tls_ver = ss.version()
                
        c_data = read_certificate_data(peer_der, cert_source="Live TLS Handshake", target_host=clean_domain)
        
        # Categorize alert level according to monitoring schedule rules:
        # More than 30 days: Normal
        # 30 days: First alert (Notice)
        # 15 days: Warning
        # 7 days: Urgent warning
        # Expired (<=0): Critical alert
        days = c_data["days_left"]
        if days <= 0:
            status = "EXPIRED"
            alert_level = "CRITICAL"
            alert_msg = f"CRITICAL: Certificate for {clean_domain} expired {abs(days)} days ago!"
        elif days <= 7:
            status = "URGENT"
            alert_level = "URGENT"
            alert_msg = f"URGENT WARNING: Certificate for {clean_domain} expires in {days} days ({c_data['hours_left']} hours)!"
        elif days <= 15:
            status = "WARNING"
            alert_level = "WARNING"
            alert_msg = f"WARNING: Certificate for {clean_domain} expires in {days} days."
        elif days <= 30:
            status = "NOTICE"
            alert_level = "NOTICE"
            alert_msg = f"NOTICE: Certificate for {clean_domain} expires in {days} days (first alert threshold)."
        else:
            status = "NORMAL"
            alert_level = "NORMAL"
            alert_msg = f"Certificate for {clean_domain} is healthy ({days} days remaining)."

        return {
            "success": True,
            "domain": clean_domain,
            "port": port,
            "status": status,
            "alert_level": alert_level,
            "alert_message": alert_msg,
            "days_left": days,
            "hours_left": c_data["hours_left"],
            "expiry_date": c_data["not_after"],
            "issuer": c_data["issuer"],
            "subject": c_data["subject"],
            "tls_version": tls_ver,
            "cipher": cipher[0] if cipher else "Unknown",
            "cert_data": c_data
        }
    except Exception as e:
        # If localhost and server is offline, fallback to server.crt if available
        if clean_domain in ("localhost", "127.0.0.1") and CERT_PATH.exists():
            try:
                c_data = read_certificate_data(CERT_PATH.read_bytes(), cert_source="Local Lab File (server.crt)", target_host=clean_domain)
                days = c_data["days_left"]
                if days <= 0:
                    status = "EXPIRED"
                    alert_level = "CRITICAL"
                    alert_msg = f"CRITICAL: Certificate for {clean_domain} expired {abs(days)} days ago!"
                elif days <= 7:
                    status = "URGENT"
                    alert_level = "URGENT"
                    alert_msg = f"URGENT WARNING: Certificate for {clean_domain} expires in {days} days ({c_data['hours_left']} hours)!"
                elif days <= 15:
                    status = "WARNING"
                    alert_level = "WARNING"
                    alert_msg = f"WARNING: Certificate for {clean_domain} expires in {days} days."
                elif days <= 30:
                    status = "NOTICE"
                    alert_level = "NOTICE"
                    alert_msg = f"NOTICE: Certificate for {clean_domain} expires in {days} days (first alert threshold)."
                else:
                    status = "NORMAL"
                    alert_level = "NORMAL"
                    alert_msg = f"Certificate for {clean_domain} is healthy ({days} days remaining)."

                return {
                    "success": True,
                    "domain": clean_domain,
                    "port": port,
                    "status": status,
                    "alert_level": alert_level,
                    "alert_message": alert_msg,
                    "days_left": days,
                    "hours_left": c_data["hours_left"],
                    "expiry_date": c_data["not_after"],
                    "issuer": c_data["issuer"],
                    "subject": c_data["subject"],
                    "tls_version": "N/A (Read from file)",
                    "cipher": "N/A",
                    "cert_data": c_data
                }
            except Exception:
                pass

        return {
            "success": False,
            "domain": clean_domain,
            "port": port,
            "status": "ERROR",
            "alert_level": "ERROR",
            "alert_message": f"Connection/TLS error for {clean_domain}:{port} - {str(e)}",
            "days_left": -1,
            "hours_left": -1,
            "expiry_date": None,
            "issuer": None,
            "subject": None,
            "error": str(e)
        }


# ===================================================================
# Full End-to-End Security Assessment
# ===================================================================

def run_full_assessment(target: str = "localhost", http_port: int = 8080, https_port: int = 8443, is_remote: bool = False) -> Dict[str, Any]:
    """Executes full reproducible security assessment and maps checks to severity, evidence & remediation."""
    h = probe_http(target, http_port)
    s = probe_https(target, https_port, target_hostname=target)

    # Read certificate
    cert_data = None
    if s.get("peer_cert_bytes"):
        cert_data = read_certificate_data(s["peer_cert_bytes"], cert_source="TLS Handshake Peer Cert", target_host=target)
    elif not is_remote and CERT_PATH.exists():
        cert_data = read_certificate_data(CERT_PATH.read_bytes(), cert_source=CERT_PATH.name, target_host=target)

    # Multi-protocol audit
    proto_audit = audit_tls_protocols(target, https_port) if s["reachable"] else {"matrix": [], "deprecated_accepted": False, "accepted_count": 0}

    # Trust store validation
    trust_result = verify_trust_store(target, https_port) if s["reachable"] else {"trusted": False, "reason": "Endpoint unreachable"}

    checks = []
    alerts = []

    def add(cid: str, name: str, category: str, status: str, severity: str, measured: Any, explanation: str, remediation: str, evidence: str, limitation: str = ""):
        checks.append({
            "id": cid,
            "name": name,
            "category": category,
            "status": status,
            "severity": severity,
            "measured": measured,
            "explanation": explanation,
            "remediation": remediation,
            "evidence": evidence,
            "limitation": limitation
        })
        if severity in ("CRITICAL", "HIGH"):
            alerts.append({
                "id": cid,
                "title": f"[{severity}] {name}",
                "severity": severity,
                "message": explanation
            })

    # C00: Service Identity & Port Conflict Check
    if not h["reachable"]:
        add("C00", "Service Identity Verification", "Transport", "NOT TESTED", "HIGH",
            "HTTP service offline", "Cannot verify if the expected lab service is running on port 8080.",
            "Start the lab service using python app.py.", "Connection failed")
    elif not h.get("service_verified"):
        add("C00", "Service Identity Verification", "Transport", "REVIEW", "HIGH",
            "Signature mismatch", "Port conflict suspected: An unrecognized service is answering on port 8080.",
            "Verify with netstat -ano | findstr :8080 and ensure the correct lab process is bound.",
            f"Headers: {h.get('headers')}")
    else:
        add("C00", "Service Identity Verification", "Transport", "PASS", "LOW",
            "Verified TLSentinel Lab", "Confirmed genuine lab server process running on the expected port.",
            "No action needed.", h.get("service_note", "Verified"))

    # C01: HTTP Redirect to HTTPS
    if not h["reachable"]:
        add("C01", "HTTP Redirect to HTTPS", "Transport", "NOT TESTED", "HIGH",
            h.get("error", "Offline"), "The HTTP service did not respond.", "Start lab-server/app.py.", "No HTTP response")
    else:
        loc = h.get("redirect_target") or ""
        ok = h["status"] in (301, 302, 307, 308) and loc.startswith("https://")
        add("C01", "HTTP Redirect to HTTPS", "Transport",
            "PASS" if ok else "REVIEW",
            "LOW" if ok else "MEDIUM",
            f"Status {h['status']}, Location: {loc or 'none'}",
            "HTTP traffic is automatically upgraded to HTTPS to prevent unencrypted plaintext transmission.",
            "Configure a 301 Moved Permanently redirect from HTTP to HTTPS in server configuration.",
            f"HTTP status code: {h['status']}, Location header: {loc}",
            "Only root path '/' tested.")

    # C02: HTTPS Reachability
    if not s["reachable"]:
        add("C02", "HTTPS Endpoint Reachable", "Transport", "NOT TESTED", "CRITICAL",
            s.get("error", "Offline"), "Could not establish TLS connection to the HTTPS port.",
            "Ensure the HTTPS server is running on the designated port and certificate files exist.",
            str(s.get("error")), "")
    else:
        add("C02", "HTTPS Endpoint Reachable", "Transport", "PASS", "LOW",
            f"{target}:{https_port} completed TLS handshake",
            "The HTTPS endpoint is active and listening for TLS connections.",
            "No action needed.",
            f"Connected to {target}:{https_port}")

    # C03: Negotiated TLS Version
    if s["reachable"]:
        ver = s["tls_version"]
        is_modern = ver in ("TLSv1.2", "TLSv1.3")
        add("C03", "Negotiated TLS Version", "Protocol",
            "PASS" if is_modern else "FAIL",
            "LOW" if is_modern else "CRITICAL",
            ver,
            f"Negotiated {ver}. TLS 1.2 and TLS 1.3 provide state-of-the-art cryptographic security.",
            "Upgrade your web server configuration to only support TLSv1.2 and TLSv1.3.",
            f"Client-server handshake negotiated: {ver}")

    # C04: Negotiated Cipher Suite & AEAD
    if s["reachable"]:
        cipher = s["cipher"]
        bits = s["cipher_bits"]
        is_aead = any(x in cipher for x in ("GCM", "CHACHA20", "POLY1305"))
        is_pfs = "ECDHE" in cipher or "DHE" in cipher or s["tls_version"] == "TLSv1.3"
        add("C04", "Cipher Suite & AEAD", "Cipher",
            "PASS" if is_aead else "REVIEW",
            "LOW" if is_aead else "HIGH",
            f"{cipher} ({bits}-bit)",
            f"Cipher provides authenticated encryption (AEAD: {is_aead}) and perfect forward secrecy (PFS: {is_pfs}).",
            "Prefer AEAD cipher suites like AES-GCM or ChaCha20-Poly1305 with ECDHE key exchange.",
            f"Cipher: {cipher}, Key bits: {bits}, AEAD: {is_aead}, PFS: {is_pfs}")

    # C05: Multi-Protocol Compatibility (Audit)
    if proto_audit.get("matrix"):
        dep = proto_audit["deprecated_accepted"]
        proto_summary = ", ".join(f"{p['protocol']} ({p['status']})" for p in proto_audit["matrix"])
        add("C05_PROTO", "Protocol Audit (TLS 1.0 - 1.3)", "Protocol",
            "FAIL" if dep else "PASS",
            "CRITICAL" if dep else "LOW",
            "Deprecated protocols active!" if dep else "Legacy protocols rejected; TLS 1.2+ accepted",
            "Legacy protocols (TLS 1.0, 1.1) are deprecated by RFC 8996 due to known vulnerabilities (BEAST, POODLE).",
            "Disable TLSv1.0 and TLSv1.1 in SSL context (ctx.minimum_version = ssl.TLSVersion.TLSv1_2).",
            proto_summary)

    # C06: Certificate Trust Chain Validation
    if cert_data:
        if trust_result["trusted"]:
            add("C06", "Certificate Trust-Store Validation", "Certificate", "PASS", "LOW",
                "Trusted by system CA store",
                "Certificate successfully validated against recognized root Certificate Authorities.",
                "No action needed.",
                trust_result.get("reason", "Verified"))
        elif cert_data["self_signed"]:
            add("C06", "Certificate Trust-Store Validation", "Certificate", "REVIEW", "MEDIUM" if not is_remote else "HIGH",
                "Self-signed (untrusted CA root)",
                "Certificate is self-signed (issuer matches subject). Browsers will display untrusted certificate warnings, although traffic remains encrypted.",
                "For public production websites, obtain a certificate signed by a publicly trusted CA (e.g. Let's Encrypt). For development/lab, self-signed is acceptable.",
                f"Subject: {cert_data['subject']} == Issuer: {cert_data['issuer']}; Error: {trust_result.get('reason')}")
        else:
            add("C06", "Certificate Trust-Store Validation", "Certificate", "REVIEW", "HIGH",
                "Untrusted intermediate/issuer",
                f"Certificate trust chain could not be validated: {trust_result.get('reason')}",
                "Ensure intermediate certificates are bundled properly in fullchain.pem.",
                trust_result.get("reason", "Validation error"))

    # C07: Certificate Date Validity & Multi-Tier Expiry
    if cert_data:
        add("C07", "Certificate Validity & Expiry", "Certificate",
            "PASS" if cert_data["expiry_severity"] == "LOW" else "REVIEW" if cert_data["expiry_severity"] in ("MEDIUM", "HIGH") else "FAIL",
            cert_data["expiry_severity"],
            cert_data["expiry_message"],
            f"Certificate valid from {cert_data['not_before'][:10]} to {cert_data['not_after'][:10]}. Current status: {cert_data['expiry_status']}.",
            "Renew the certificate before expiry to prevent service disruption and browser security blocks.",
            f"Valid NotBefore: {cert_data['not_before']}, NotAfter: {cert_data['not_after']}, Days Remaining: {cert_data['days_left']}")

    # C08: Key Strength
    if cert_data:
        k_sz = cert_data["key_size"] or 0
        k_tp = cert_data["key_type"]
        is_strong = (k_tp == "RSA" and k_sz >= 2048) or ("EC" in k_tp or "Ed25519" in k_tp)
        add("C08", "Cryptographic Key Strength", "Certificate",
            "PASS" if is_strong else "FAIL",
            "LOW" if is_strong else "HIGH",
            f"{k_tp} {k_sz}-bit" if k_sz else k_tp,
            "RSA keys must be at least 2048 bits (3072+ recommended) or use elliptic curves (ECDSA P-256/P-384).",
            "Generate an RSA key with at least 2048 bits or an ECDSA key with prime256v1.",
            f"Algorithm: {k_tp}, Key Size: {k_sz} bits")

    # C09: Signature Hash Algorithm
    if cert_data:
        sig = cert_data["signature_hash"].lower()
        is_secure_hash = sig in ("sha256", "sha384", "sha512")
        add("C09", "Signature Algorithm Security", "Certificate",
            "PASS" if is_secure_hash else "FAIL",
            "LOW" if is_secure_hash else "CRITICAL",
            sig.upper(),
            "Collision-resistant hash algorithms (SHA-256 or higher) prevent certificate forgery. MD5 and SHA-1 are cryptographically broken.",
            "Re-issue certificate signed using SHA-256 (e.g. openssl req -sha256).",
            f"Signature hash: {sig}")

    # C10: RFC 6125 Hostname & SAN Matching
    if cert_data:
        matched = cert_data["hostname_matched"]
        add("C10", "Hostname & SAN Matching", "Certificate",
            "PASS" if matched else "FAIL",
            "LOW" if matched else "HIGH",
            f"{target} matched: {matched}",
            f"RFC 6125 evaluation: {cert_data['hostname_reason']}",
            f"Ensure the certificate Subject Alternative Name (SAN) extension includes DNS:{target} or IP:{target}.",
            f"Target: {target}, SANs: {', '.join(cert_data['san'])}")

    # C11: HSTS (Strict-Transport-Security)
    if s["reachable"]:
        hd = s["headers"]
        has_hsts = "strict-transport-security" in hd
        add("C11", "Strict-Transport-Security (HSTS)", "Headers",
            "PASS" if has_hsts else "REVIEW",
            "LOW" if has_hsts else "MEDIUM",
            hd.get("strict-transport-security", "Header not sent"),
            "HSTS instructs browsers to strictly communicate over HTTPS, mitigating SSL-stripping MITM attacks. (Note: Lab intentionally omits HSTS to prevent locking the browser's localhost cache).",
            "In production, add header: Strict-Transport-Security: max-age=31536000; includeSubDomains.",
            f"Response headers checked: {list(hd.keys())}")

    # C12: X-Content-Type-Options
    if s["reachable"]:
        hd = s["headers"]
        cto = hd.get("x-content-type-options")
        ok_cto = cto == "nosniff"
        add("C12", "X-Content-Type-Options Header", "Headers",
            "PASS" if ok_cto else "REVIEW",
            "LOW" if ok_cto else "LOW",
            cto or "Header not sent",
            "Prevents MIME-confusion attacks and prevents browsers from MIME-sniffing away from declared Content-Type.",
            "Add header: X-Content-Type-Options: nosniff",
            f"Value received: {cto}")

    # C13: Content-Security-Policy (CSP)
    if s["reachable"]:
        hd = s["headers"]
        has_csp = "content-security-policy" in hd
        add("C13", "Content-Security-Policy (CSP)", "Headers",
            "PASS" if has_csp else "REVIEW",
            "LOW" if has_csp else "LOW",
            hd.get("content-security-policy", "Header not sent"),
            "CSP restricts resource and script execution origins, mitigating Cross-Site Scripting (XSS) and injection attacks.",
            "Configure a restrictive Content-Security-Policy header (e.g. default-src 'self').",
            f"Response headers checked: {list(hd.keys())}")

    # Compute statistics & overall status
    counts = {
        "pass": sum(1 for c in checks if c["status"] == "PASS"),
        "review": sum(1 for c in checks if c["status"] == "REVIEW"),
        "fail": sum(1 for c in checks if c["status"] == "FAIL"),
        "not_tested": sum(1 for c in checks if c["status"] == "NOT TESTED"),
        "critical": sum(1 for c in checks if c["severity"] == "CRITICAL"),
        "high": sum(1 for c in checks if c["severity"] == "HIGH"),
        "medium": sum(1 for c in checks if c["severity"] == "MEDIUM"),
        "low": sum(1 for c in checks if c["severity"] == "LOW"),
    }

    if counts["critical"] > 0:
        overall_status = "CRITICAL_RISK"
    elif counts["high"] > 0 or counts["fail"] > 0:
        overall_status = "ACTION_REQUIRED"
    elif counts["review"] > 0:
        overall_status = "ACCEPTABLE_WITH_REVIEW"
    else:
        overall_status = "HEALTHY"

    # Compute quantified AI-powered Security Risk Score
    risk_score_data = calculate_risk_score(checks, target=target, is_remote=is_remote)

    return {
        "platform": "TLSentinel",
        "generated_at": now_iso(),
        "target": target,
        "environment": {
            "host": target,
            "http_port": http_port,
            "https_port": https_port,
            "python": platform.python_version(),
            "os": platform.platform(),
            "is_remote": is_remote
        },
        "overall_status": overall_status,
        "risk_score": risk_score_data,
        "summary": {
            **counts,
            "alerts": alerts
        },
        "results": checks,
        "protocol_matrix": proto_audit.get("matrix", []),
        "certificate": cert_data,
        "trust_verification": trust_result,
        "limitations": [
            "Assessments are point-in-time cryptographic measurements against target configuration.",
            "Local lab uses a self-signed certificate by design; trust store warnings are expected.",
            "Probing reflects client-supported capabilities negotiated with target service."
        ],
        "recommendations": [
            "Use certificates issued by recognized CAs for public production domains.",
            "Ensure only TLS 1.2 and TLS 1.3 are enabled across all endpoints.",
            "Deploy HSTS and Content-Security-Policy headers on production domains."
        ]
    }
