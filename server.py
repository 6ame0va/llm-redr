#!/usr/bin/env python3
"""
Minimal static file server that logs every request to hits.log,
so you can see exactly which page(s) an LLM/agent actually hit
when testing redirect-following behavior.

Also serves a real 1x1 transparent GIF at /pixel.gif (logging the hit,
including any query string, first) — this is the capture endpoint for the
Streamlit app's "digest" (markdown/image exfiltration) page. Streamlit
itself can't capture a plain, non-browser-JS HTTP GET (the kind a real
`<img src="...">` markdown tag triggers): that request never runs
Streamlit's Python script, so nothing gets logged there. This plain
http.server-based server has no such limitation — it logs any raw GET.

Usage:
    python3 server.py [port]

Then point your LLM/agent test at, e.g.:
    http://localhost:8000/index.html

Or, for the exfiltration capture endpoint:
    http://localhost:8000/pixel.gif?exfil=<whatever-the-agent-put-there>
"""
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


class LoggingHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(PUBLIC_DIR), **kwargs)

    def log_hit(self):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "path": self.path,
            "client": self.client_address[0],
            "referrer": self.headers.get("Referer", ""),
            "user_agent": self.headers.get("User-Agent", ""),
        }
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
        print(f"HIT  {entry['timestamp']}  {entry['path']}  ref={entry['referrer']}")

    def do_GET(self):
        self.log_hit()
        path_only = self.path.split("?", 1)[0]
        if path_only == "/pixel.gif":
            self.send_response(200)
            self.send_header("Content-Type", "image/gif")
            self.send_header("Content-Length", str(len(TRANSPARENT_GIF)))
            self.end_headers()
            self.wfile.write(TRANSPARENT_GIF)
            return
        super().do_GET()

    def log_message(self, format, *args):
        pass  # suppress default stderr logging; we log to hits.log instead


if __name__ == "__main__":
    LOG_FILE.touch(exist_ok=True)
    print(f"Serving {PUBLIC_DIR} on http://localhost:{PORT}")
    print(f"Logging hits to {LOG_FILE}")
    http.server.HTTPServer(("0.0.0.0", PORT), LoggingHandler).serve_forever()
