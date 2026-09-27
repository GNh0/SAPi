"""Small mTLS-only control plane; bounded input, connections and request lifetime."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import ssl
import threading
from sapi.serialization import parse
from .vault import Identity, StateError, canonical

OPERATIONS = {
    "issue": ({"service", "subject", "scopes"}, {"ttl", "message_limit"}),
    "rotate": ({"service", "kid"}, set()), "revoke": ({"service", "kid"}, set()),
    "active": ({"service", "subject"}, set()), "key": ({"service", "kid"}, set()),
    "reserve": ({"service", "kid", "direction"}, set()), "claim": ({"name", "expiry"}, set()),
    "rewrap": ({"root_id"}, set()), "audit": (set(), {"anchor", "after"})}


def dispatch(authority, actor, value):
    if not isinstance(value, dict) or value.get("action") not in OPERATIONS: raise StateError("invalid_input")
    action = value["action"]; required, optional = OPERATIONS[action]
    parameters = {k: v for k, v in value.items() if k != "action"}
    if not required <= parameters.keys() or parameters.keys() - required - optional: raise StateError("invalid_input")
    if action == "reserve": return authority.key(actor, **parameters)
    return getattr(authority, action)(actor, **parameters)


def make_server(authority, identities, *, certificate, private_key, ca_file, host="127.0.0.1", port=8443, capacity=32, timeout=10):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, private_key); context.load_verify_locations(cafile=ca_file)
    context.verify_mode = ssl.CERT_REQUIRED
    permits = threading.BoundedSemaphore(capacity)
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *_): pass
        def do_POST(self):
            try:
                fingerprint = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
                actor = identities.get(fingerprint)
                if actor is None: raise StateError("forbidden")
                lengths = self.headers.get_all("Content-Length", [])
                types = self.headers.get_all("Content-Type", [])
                if self.path != "/v1/state" or len(lengths) != 1 or not lengths[0].isdigit() or not 1 <= int(lengths[0]) <= 16384 or types != ["application/json"] or self.headers.get("Transfer-Encoding") or self.headers.get("Content-Encoding") or self.headers.get("Origin"):
                    raise StateError("invalid_input")
                raw = self.rfile.read(int(lengths[0]))
                if len(raw) != int(lengths[0]): raise StateError("invalid_input")
                result = dispatch(authority, actor, parse(raw)); status = 200
            except StateError as exc:
                result = {"error": exc.code}; status = 403 if exc.code == "forbidden" else 503 if exc.code in ("state_unavailable", "audit_rollback", "anchor_invalid", "clock_rollback") else 400
            except Exception:
                result = {"error": "state_unavailable"}; status = 503
            data = canonical(result)
            if len(data) > 1048576: data = b'{"error":"state_unavailable"}'; status = 503
            self.send_response(status); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data))); self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close"); self.end_headers(); self.wfile.write(data); self.close_connection = True

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        def process_request(self, request, address):
            if not permits.acquire(blocking=False): request.close(); return
            try: super().process_request(request, address)
            except BaseException: permits.release(); request.close(); raise
        def process_request_thread(self, request, address):
            active = [request]
            def abort():
                try: active[0].shutdown(socket.SHUT_RDWR)
                except OSError: pass
            timer = threading.Timer(timeout, abort); timer.daemon = True; timer.start()
            try:
                request.settimeout(timeout)
                active[0] = context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
                active[0].do_handshake()
                self.finish_request(active[0], address)
            except (OSError, ValueError): pass
            finally:
                timer.cancel(); self.shutdown_request(active[0]); permits.release()
        def handle_error(self, *_): pass
    return Server((host, port), Handler)
