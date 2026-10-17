#!/usr/bin/env python3
"""
auth_logger.py - small proxy in front of the Juice Shop login endpoint.

Nginx sends only POST /rest/user/login here. The request is forwarded to
Juice Shop unchanged, and ONE structured JSON event is written per login
attempt for Wazuh to read.

Logged:  decision, HTTP status, account (the e-mail field), source IP,
         correlation ID (Nginx $request_id), user agent, timestamp.
NEVER logged: the password, tokens or the rest of the request/response body.
"""
import datetime
import json
import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = os.environ.get("UPSTREAM", "http://offer-juice-shop:3000")
LOG_FILE = os.environ.get("AUTH_LOG", "/var/log/authlog/auth-events.json")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8081"))

# Headers that must not be copied between the two connections
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}


def write_event(event: dict) -> None:
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


class LoginProxy(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""

        # Read ONLY the e-mail field. The password is never stored or logged.
        try:
            account = json.loads(body or b"{}").get("email")
        except (ValueError, AttributeError):
            account = None

        # Forward the request unchanged to Juice Shop
        upstream_req = urllib.request.Request(UPSTREAM + self.path, data=body, method="POST")
        for name, value in self.headers.items():
            if name.lower() not in HOP_BY_HOP:
                upstream_req.add_header(name, value)

        try:
            with urllib.request.urlopen(upstream_req, timeout=30) as resp:
                status, resp_body, resp_headers = resp.status, resp.read(), resp.getheaders()
        except urllib.error.HTTPError as err:
            status, resp_body, resp_headers = err.code, err.read(), list(err.headers.items())
        except Exception:
            status, resp_body, resp_headers = 502, b"Bad gateway", []

        # Return Juice Shop's answer to the client
        self.send_response(status)
        for name, value in resp_headers:
            if name.lower() not in HOP_BY_HOP:
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

        # One event per attempt - Juice Shop answers 200 only on a successful login
        write_event({
            "auth_event": "login",
            "decision": "success" if status == 200 else "failure",
            "http_status": status,
            "account": str(account)[:200] if account is not None else None,
            "src_ip": self.headers.get("X-Real-IP", self.client_address[0]),
            "correlation_id": self.headers.get("X-Request-ID"),
            "user_agent": (self.headers.get("User-Agent") or "")[:200],
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        })

    def log_message(self, *args):  # keep stdout quiet
        pass


if __name__ == "__main__":
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    ThreadingHTTPServer(("127.0.0.1", LISTEN_PORT), LoginProxy).serve_forever()
