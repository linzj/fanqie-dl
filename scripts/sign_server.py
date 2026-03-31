#!/usr/bin/env python3
"""
Frida-based signing HTTP proxy server.

Attaches to the running 番茄小说 app, hooks r4.onCallToAddSecurityFactor(),
and exposes it as an HTTP endpoint for the Rust client.

Usage:
    python3 sign_server.py [--port 8899] [--pid PID]

API:
    POST /sign
    Body: {"url": "https://...", "headers": {"key": "value"}}
    Response: {"X-Gorgon": "...", "X-Argus": "...", ...}
"""
import frida
import sys
import json
import argparse
import signal
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

SCRIPT_PATH = Path(__file__).parent / "investigate.js"

session = None
script = None


def on_message(message, data):
    if message['type'] == 'send':
        print(f"[frida] {message['payload']}", flush=True)
    elif message['type'] == 'error':
        print(f"[frida:err] {message.get('description', '')}", flush=True)
    else:
        print(f"[frida] {message}", flush=True)


def setup_frida(pid=None):
    global session, script

    device = frida.get_usb_device()

    if pid is None:
        for proc in device.enumerate_processes():
            if proc.name == "com.dragon.read":
                pid = proc.pid
                break
        if pid is None:
            print("[!] com.dragon.read not running")
            sys.exit(1)

    print(f"[*] Attaching to PID {pid}...")
    session = device.attach(pid)
    js_code = SCRIPT_PATH.read_text()
    script = session.create_script(js_code)
    script.on('message', on_message)
    script.load()

    # Wait for r4 instance to be captured
    import time
    for i in range(10):
        status = script.exports_sync.ping()
        if status == "ready":
            print("[+] Frida signer ready!")
            return
        time.sleep(1)

    print("[!] Warning: r4 instance not captured yet, signing may fail")


class SignHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/sign":
            self.send_error(404)
            return

        content_len = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_len).decode()

        try:
            req = json.loads(body)
            url = req["url"]
            headers = req.get("headers", {})

            result = script.exports_sync.sign(url, json.dumps(headers))
            signatures = json.loads(result)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(signatures).encode())
            print(f"[sign] {url[:80]}... -> {len(signatures)} headers")

        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())
            print(f"[err] {e}")

    def do_GET(self):
        if self.path == "/health":
            status = script.exports_sync.ping() if script else "not_connected"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": status}).encode())
        else:
            self.send_error(404)

    def log_message(self, fmt, *args):
        pass  # Suppress default access logs


def main():
    parser = argparse.ArgumentParser(description="Frida signing proxy server")
    parser.add_argument("--port", type=int, default=8899)
    parser.add_argument("--pid", type=int, default=None)
    args = parser.parse_args()

    setup_frida(args.pid)

    server = HTTPServer(("127.0.0.1", args.port), SignHandler)
    print(f"[*] Signing proxy listening on http://127.0.0.1:{args.port}")
    print(f"[*] POST /sign  {{\"url\": \"...\"}}")
    print(f"[*] GET  /health")

    def shutdown(sig, frame):
        print("\n[*] Shutting down...")
        server.shutdown()
        if session:
            session.detach()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    server.serve_forever()


if __name__ == "__main__":
    main()
