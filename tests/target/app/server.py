#!/usr/bin/env python3
"""Small intentionally vulnerable target for GeistScope integration tests."""

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import json


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self.send_text("ok")
        elif parsed.path == "/":
            self.send_text(INDEX_HTML, content_type="text/html")
        elif parsed.path == "/static/app.js":
            self.send_text(APP_JS, content_type="application/javascript")
        elif parsed.path == "/search":
            query = parse_qs(parsed.query).get("q", [""])[0]
            self.send_text(f"<html><body>Search: {query}</body></html>", content_type="text/html")
        elif parsed.path == "/api/users":
            user_id = parse_qs(parsed.query).get("id", [""])[0]
            if "'" in user_id:
                self.send_text("sqlite3.OperationalError: near \"'\": syntax error", status=HTTPStatus.OK)
            else:
                self.send_json({"id": user_id, "name": "Ada"})
        elif parsed.path == "/redirect":
            target = parse_qs(parsed.query).get("next", ["/"])[0]
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", target)
            self.end_headers()
        elif parsed.path == "/debug":
            self.send_text("Debug interface: stack trace enabled", content_type="text/plain")
        else:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/graphql":
            _ = self.rfile.read(int(self.headers.get("content-length", "0") or "0"))
            self.send_json({"data": {"__schema": {"queryType": {"name": "Query"}, "types": [{"name": "Query", "kind": "OBJECT"}]}}})
        else:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.end_headers()

    def send_text(self, body, status=HTTPStatus.OK, content_type="text/plain"):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def send_json(self, value, status=HTTPStatus.OK):
        self.send_text(json.dumps(value), status=status, content_type="application/json")


INDEX_HTML = """<!doctype html>
<html>
  <head><script src="/static/app.js"></script></head>
  <body>
    <a href="/search?q=hello">Search</a>
    <a href="/redirect?next=/home">Redirect</a>
    <form action="/api/users?id=1"><input name="id" value="1"></form>
  </body>
</html>
"""

APP_JS = r"""
/*! jQuery JavaScript Library v3.4.1 */
const internalApi = "http://api.internal/admin";
const metadataIp = "http://10.1.2.3/latest/meta-data/";
fetch("/api/users?id=1", { method: "GET" });
fetch("/search?q=test");
fetch("/redirect?next=/home");
fetch("/graphql", {
  method: "POST",
  headers: {"content-type": "application/json"},
  body: JSON.stringify({ query: "{ __schema { types { name } } }" })
});
"""


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
