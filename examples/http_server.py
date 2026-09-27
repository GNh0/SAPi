"""Loopback HTTP/HTTPS demonstration adapter. Not a production web server."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import ssl

from sapi import Codec, KeyRecord, SecureServer
from sapi.constants import MAX_WIRE
from sapi.serialization import unb64


def make_server(handle, *, host="127.0.0.1", port=0, certificate=None, private_key=None):
    class Handler(BaseHTTPRequestHandler):
        def handle(self):
            try:
                super().handle()
            except (ConnectionError, TimeoutError, ssl.SSLError):
                pass  # Includes peers correctly rejecting an invalid TLS certificate.

        def log_message(self, *args):
            pass  # Never log ciphertext, credentials or decrypted data in this demo.

        def empty(self, status):
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def do_GET(self):
            self.empty(405)

        def do_POST(self):
            self.connection.settimeout(5)
            lengths = self.headers.get_all("Content-Length", [])
            if (self.path != "/sapi" or self.headers.get("Content-Type") != "application/sapi+jwe"
                    or "Authorization" in self.headers or "Transfer-Encoding" in self.headers
                    or len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,8}", lengths[0])):
                self.empty(400)
                return
            size = int(lengths[0])
            if size > MAX_WIRE:
                self.empty(400)
                return
            try:
                body = self.rfile.read(size)
                if len(body) != size:
                    raise ValueError("incomplete body")
                response = handle(body.decode("ascii", errors="strict")).encode("ascii")
                if len(response) > MAX_WIRE:
                    raise ValueError("oversized result")
            except Exception:
                self.empty(400)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/sapi+jwe")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    if certificate or private_key:
        if not certificate or not private_key:
            raise ValueError("certificate and private key both required")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate, private_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--keys", type=Path, required=True, help="securely provisioned key registry; never commit real keys")
    parser.add_argument("--service", default="demo")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--certificate")
    parser.add_argument("--private-key")
    args = parser.parse_args()
    raw = json.loads(args.keys.read_text("utf-8"))
    keys = {kid: KeyRecord(unb64(v["key"]), v["subject"], frozenset(v["scopes"])) for kid, v in raw.items()}
    api = SecureServer(Codec(args.service, keys))
    api.register("echo", "echo", lambda d: set(d) == {"message"} and isinstance(d["message"], str),
                 lambda principal, data: True, lambda principal, data: data)
    transport = make_server(api.handle, port=args.port, certificate=args.certificate, private_key=args.private_key)
    scheme = "https" if args.certificate else "http"
    print(f"Experimental SAPI endpoint: {scheme}://127.0.0.1:{transport.server_port}/sapi", flush=True)
    try:
        transport.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        transport.server_close()


if __name__ == "__main__":
    main()
