#!/usr/bin/env python3
"""Toy forward_auth service for the Tardigrade forward-auth example.

Allows requests that carry `Authorization: Bearer letmein` and names the user
in `X-Auth-Request-User`. Browsers (Accept: text/html) without a token are
redirected to a login page; every other caller gets a 401 challenge.

Not for production: use oauth2-proxy, Authelia, or your identity provider.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "Bearer letmein"


class AuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        original = self.headers.get("X-Forwarded-Uri", "/")
        if self.headers.get("Authorization") == TOKEN:
            self.send_response(200)
            self.send_header("X-Auth-Request-User", "alice")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if "text/html" in self.headers.get("Accept", ""):
            self.send_response(302)
            self.send_header("Location", f"https://login.example.test/?rd={original}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"authentication required\n"
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Bearer realm="example"')
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 4180), AuthHandler).serve_forever()
