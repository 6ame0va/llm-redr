#!/usr/bin/env python3
"""
Minimal static file server that logs the FULL HTTP request and response for
every GET to hits.log, so you can see exactly which page(s) an LLM/agent
actually hit — and exactly what was sent both ways — when testing
redirect-following behavior.

Also serves a real 1x1 transparent GIF at /pixel.gif (logged like any other
request) — this is the capture endpoint for the Streamlit app's "digest"
(markdown/image exfiltration) page. Streamlit itself can't capture a plain,
non-browser-JS HTTP GET (the kind a real `<img src="...">` markdown tag
triggers): that request never runs Streamlit's Python script, so nothing
gets logged there. This plain http.server-based server has no such
limitation — it logs any raw GET, request and response both.

Usage:
    python3 server.py [port]

Then point your LLM/agent test at, e.g.:
    http://localhost:8000/index.html

Or, for the exfiltration capture endpoint:
    http://localhost:8000/pixel.gif?exfil=<whatever-the-agent-put-there>
"""
import base64
import http.server
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
PUBLIC_DIR = Path(__file__).parent / "public"
LOG_FILE = Path(__file__).parent / "hits.log"

# Minimal valid 1x1 transparent GIF, so an <img> tag pointed at /pixel.gif
# renders as an invisible pixel instead of a broken image.
TRANSPARENT_GIF = bytes([
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
])

# Response bodies under this size are logged as text/base64 in full; larger
# ones are truncated so one big file can't blow up hits.log.
MAX_LOGGED_BODY_BYTES = 65536


class _TeeWriter:
    """Wraps wfile, capturing every byte written to it while still passing
    the write through untouched. This is what lets us log the *exact* bytes
    sent on the wire (status line, headers, and body) regardless of whether
    they came from our own code or the inherited SimpleHTTPRequestHandler
    file-serving/404 logic."""

    def __init__(self, real):
        self._real = real
        self.captured = bytearray()

    def write(self, data):
        self.captured.extend(data)
        return self._real.write(data)

    def flush(self):
        return self._real.flush()

    def __getattr__(self, name):
        return getattr(self._real, name)


class LoggingHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(PUBLIC_DIR), **kwargs)

    def do_GET(self):
        request_entry = {
            "method": self.command,
            "path": self.path,
            "http_version": self.request_version,
            "client": self.client_address[0],
            "headers": dict(self.headers.items()),
        }

        # Swap in a tee so we capture the raw bytes written to the socket,
        # and wrap send_response/send_header so we capture status + headers
        # even though http.server never hands them back to us directly.
        real_wfile = self.wfile
        tee = _TeeWriter(real_wfile)
        self.wfile = tee

        response_status = {}
        response_headers = []
        orig_send_response = self.send_response
        orig_send_header = self.send_header

        def send_response(code, message=None):
            response_status["code"] = code
            response_status["message"] = message
            return orig_send_response(code, message)

        def send_header(keyword, value):
            response_headers.append([keyword, value])
            return orig_send_header(keyword, value)

        self.send_response = send_response
        self.send_header = send_header

        try:
            path_only = self.path.split("?", 1)[0]
            if path_only == "/pixel.gif":
                self.send_response(200)
                self.send_header("Content-Type", "image/gif")
                self.send_header("Content-Length", str(len(TRANSPARENT_GIF)))
                self.end_headers()
                self.wfile.write(TRANSPARENT_GIF)
            else:
                super().do_GET()
        finally:
            self.wfile = real_wfile
            self.send_response = orig_send_response
            self.send_header = orig_send_header

        # `tee.captured` is the exact wire bytes: status line + headers +
        # blank line + body. Split off the body for readable logging.
        raw = bytes(tee.captured)
        _, _, body = raw.partition(b"\r\n\r\n")
        truncated = len(body) > MAX_LOGGED_BODY_BYTES
        if truncated:
            body = body[:MAX_LOGGED_BODY_BYTES]

        content_type = next(
            (v for k, v in response_headers if k.lower() == "content-type"), ""
        )
        is_text = content_type.startswith("text/") or content_type in (
            "application/json", "application/javascript",
        )
        if is_text:
            try:
                body_repr, body_encoding = body.decode("utf-8"), "utf-8"
            except UnicodeDecodeError:
                body_repr, body_encoding = base64.b64encode(body).decode("ascii"), "base64"
        else:
            body_repr, body_encoding = base64.b64encode(body).decode("ascii"), "base64"

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request": request_entry,
            "response": {
                "status": response_status.get("code"),
                "reason": response_status.get("message"),
                "headers": response_headers,
                "body": body_repr,
                "body_encoding": body_encoding,
                "body_truncated": truncated,
            },
        }
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
        print(
            f"HIT  {entry['timestamp']}  {request_entry['method']} {request_entry['path']} "
            f"-> {response_status.get('code')}"
        )

    def log_message(self, format, *args):
        pass  # suppress default stderr logging; we log to hits.log instead


if __name__ == "__main__":
    LOG_FILE.touch(exist_ok=True)
    print(f"Serving {PUBLIC_DIR} on http://localhost:{PORT}")
    print(f"Logging full request+response to {LOG_FILE}")
    http.server.HTTPServer(("0.0.0.0", PORT), LoggingHandler).serve_forever()
