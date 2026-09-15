#!/usr/bin/env python3
"""
Minimal static file server that logs every request to hits.log,
so you can see exactly which page(s) an LLM/agent actually hit
when testing redirect-following behavior.

Usage:
    python3 server.py [port]

Then point your LLM/agent test at, e.g.:
    http://localhost:8000/index.html
"""
import http.server
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
PUBLIC_DIR = Path(__file__).parent / "public"
LOG_FILE = Path(__file__).parent / "hits.log"


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
        super().do_GET()

    def log_message(self, format, *args):
        pass  # suppress default stderr logging; we log to hits.log instead


if __name__ == "__main__":
    LOG_FILE.touch(exist_ok=True)
    print(f"Serving {PUBLIC_DIR} on http://localhost:{PORT}")
    print(f"Logging hits to {LOG_FILE}")
    http.server.HTTPServer(("0.0.0.0", PORT), LoggingHandler).serve_forever()
