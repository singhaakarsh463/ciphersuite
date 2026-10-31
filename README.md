# 🛡️ TLSentinel — Advanced TLS Security Assessment Platform

**TLSentinel** is an advanced cryptographic inspection and TLS configuration auditing platform featuring an automated multi-protocol test engine, deep X.509 certificate validation, persistent SQLite history, before/after remediation diffs, and professional PDF/HTML report exports.

## Core Capabilities

1. **Protocol & Cipher Compatibility Audit**:
   - Actively probes TLS 1.0, 1.1, 1.2, and 1.3 protocol handshakes against the target.
   - Generates a real-time **Protocol Compatibility Matrix** confirming legacy protocol rejection and modern AEAD / Perfect Forward Secrecy (PFS) enforcement.
2. **Advanced Certificate Validation**:
   - Multi-tier expiration tracking (Critical <24h, Warning <7d, Notice <30d, Healthy).
   - Real system CA trust-chain validation with detailed error analysis.
   - RFC 6125 SAN and hostname matching (DNS, IP SAN, and wildcard support).
   - Key size (RSA/ECDSA) and signature hash verification.
3. **Before / After Security Comparison**:
   - Compares any two historical assessment runs side-by-side.
   - Highlights improvements (remediations), regressions, and certificate changes.
4. **Persistent Assessment History & Alerts**:
   - SQLite-backed audit trail (`backend/data/tlsentinel.db`).
   - Active security alert banners for immediate risks.
5. **Professional Security Reports**:
   - Findings mapped to explicit severity ratings (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
   - Detailed explanations, technical reproducible evidence, and remediation advice.
   - Standalone printable HTML report with `@media print` PDF support.
6. **Authorized Remote Domain Assessment**:
   - Strictly validates FQDNs with anti-SSRF protections against private, loopback, and cloud metadata IPs.
7. **AI-Powered Security Risk Score (Phoenix Security / ASPM style)**:
   - Quantified 0–100 security risk score with calibrated technical point deductions.
   - Severity breakdown and automated AI narrative explaining positive controls, risk drivers, and prioritized remediation actions.
8. **Automated Certificate Expiry Monitoring (CertControl style)**:
   - Continuous background monitoring via APScheduler every 60 seconds.
   - Real-time countdown meters, expiration progress bars, multi-tier threshold alerts (>30d, 30d, 15d, 7d, expired), and simulated email notifications.

---

## Architecture & Endpoints

| Service | Address | Description |
|---|---|---|
| **Dashboard UI** | [http://localhost:5173](http://localhost:5173) | Modern React + Vite assessment dashboard |
| **Lab HTTP** | [http://localhost:8080](http://localhost:8080) | Plain HTTP with 301 redirect and service identity signature |
| **Lab HTTPS** | [https://localhost:8443](https://localhost:8443) | TLS 1.3 / 1.2 test server |
| **API & Docs** | [http://localhost:8000/docs](http://localhost:8000/docs) | FastAPI interactive Swagger documentation |

---

## Safety & Security Guardrails
- **Service Verification**: The scanner verifies expected service identity headers (`X-TLSentinel-Lab`) to prevent measuring the wrong service in case of a local port conflict.
- **Private Key Isolation**: `server.key` is never read or exposed by the API and is excluded by `.gitignore`.
- **SSRF Safeguards**: Remote domain scans strictly reject private network addresses (RFC 1918), loopback, link-local, and multicast addresses.
