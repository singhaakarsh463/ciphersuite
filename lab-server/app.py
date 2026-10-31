"""Local HTTPS lab: HTTP :8080 redirects to HTTPS :8443. Binds to 127.0.0.1 only."""
import html, ssl, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BIND, HOST, HTTP_PORT, HTTPS_PORT = "127.0.0.1", "localhost", 8080, 8443
BASE = Path(__file__).parent

PAGE = """<!doctype html><meta charset=utf-8><title>HTTPS Lab</title>
<body style="font-family:system-ui;max-width:640px;margin:48px auto;line-height:1.6">
<h1>HTTPS lab server</h1>
<p>This page was delivered over TLS on port {port}.</p>
<p>Capture test: open <code>http://localhost:8080/?note=visible_in_http</code> and compare
the HTTP request in Wireshark with the TLS records of this page.</p>
<p>Note received: <b>{note}</b></p></body>"""


class Redirect(BaseHTTPRequestHandler):
    def _go(self):
        self.send_response(301)
        self.send_header("Location", f"https://{HOST}:{HTTPS_PORT}{self.path}")
        self.send_header("Server", "TLSentinel-Lab")
        self.send_header("X-TLSentinel-Lab", "v1")
        self.send_header("Content-Length", "0")
        self.end_headers()
    do_GET = do_HEAD = _go


class Secure(BaseHTTPRequestHandler):
    def _page(self, body=True):
        note = parse_qs(urlparse(self.path).query).get("note", ["none"])[0]
        data = PAGE.format(port=HTTPS_PORT, note=html.escape(note)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Server", "TLSentinel-Lab")
        self.send_header("X-TLSentinel-Lab", "v1")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if body:
            self.wfile.write(data)
    def do_GET(self): self._page()
    def do_HEAD(self): self._page(False)


def main():
    crt, key = BASE / "server.crt", BASE / "server.key"
    if not (crt.exists() and key.exists()):
        sys.exit("server.crt / server.key missing. Run generate_certificate.bat first.")
    try:
        http = ThreadingHTTPServer((BIND, HTTP_PORT), Redirect)
        https = ThreadingHTTPServer((BIND, HTTPS_PORT), Secure)
    except OSError as e:
        sys.exit(f"Could not bind a port ({e}). Another program may be using 8080 or 8443.")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(crt, key)
    https.socket = ctx.wrap_socket(https.socket, server_side=True)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    print(f"HTTP  redirect: http://{HOST}:{HTTP_PORT}\nHTTPS server:   https://{HOST}:{HTTPS_PORT}\nCtrl+C to stop.")
    try:
        https.serve_forever()
    except KeyboardInterrupt:
        print("Stopped.")

if __name__ == "__main__":
    main()
