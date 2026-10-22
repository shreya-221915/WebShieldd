from http.server import BaseHTTPRequestHandler, HTTPServer
from http.cookies import SimpleCookie

HOST = "127.0.0.1"
PORT = 8000

class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>WebShield Local Demo</title></head>
<body style="font-family:Arial;max-width:760px;margin:40px auto;line-height:1.6">
<h1>WebShield Local Demo Site</h1>
<p>This local-only site is intentionally configured with a few missing security headers
so WebShield can demonstrate its checks.</p>
<p>No external website is contacted by this demo server.</p>
</body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # Deliberately omit common security headers for educational testing.
        self.send_header("Set-Cookie", "webshield_demo=student; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        print("[local demo] " + (format % args))

if __name__ == "__main__":
    print(f"WebShield demo site running at http://{HOST}:{PORT}")
    print("Keep this terminal open. Press Ctrl+C to stop.")
    HTTPServer((HOST, PORT), DemoHandler).serve_forever()
