"""Fixed endpoint, strict framing, peer limits and bounded connection lifetime."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import socket
import ssl
import threading
import time
import urllib.parse
from sapi.constants import MAX_WIRE
from sapi.http_limits import LimitedMetadataReader


def make_server(application,*,host="127.0.0.1",port=8444,certificate=None,private_key=None,capacity=32,timeout=10,peer_requests=120,allowed_origins=()):
    if (certificate is None)!=(private_key is None) or not 1<=capacity<=256 or not 0<timeout<=30 or not 1<=peer_requests<=10000:raise ValueError("bounded listener configuration required")
    context=None
    if certificate:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate,private_key)
    permits=threading.BoundedSemaphore(capacity)
    peers={};peer_lock=threading.Lock()
    for value in allowed_origins:
        parsed=urllib.parse.urlsplit(value)
        if parsed.scheme!="https" or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password or any(ord(c)<33 or ord(c)>126 for c in value):raise ValueError("fixed HTTPS browser origins required")
    allowed_origins=frozenset(allowed_origins)

    class Handler(BaseHTTPRequestHandler):
        protocol_version="HTTP/1.1"
        def version_string(self):return "SAPi"
        def send_error(self,code,message=None,explain=None):
            self.send_response(code);self.send_header("Content-Length","0");self.send_header("Connection","close");self.end_headers();self.close_connection=True
        def setup(self):
            super().setup();self.rfile=LimitedMetadataReader(self.rfile)
        def handle(self):
            try:super().handle()
            except Exception:self.close_connection=True
        def log_message(self,*_):pass
        def origin(self):
            values=self.headers.get_all("Origin",[])
            if len(values)>1 or (values and values[0] not in allowed_origins):raise ValueError("unlisted origin")
            return values[0] if values else None
        def do_POST(self):
            result=b"";status=400
            try:
                origin=self.origin()
                sizes=self.headers.get_all("Content-Length",[])
                media=self.headers.get_all("Content-Type",[])
                if self.path!="/sapi" or len(sizes)!=1 or not sizes[0].isdigit() or not 1<=int(sizes[0])<=MAX_WIRE or media!=["application/sapi+jwe"] or self.headers.get("Transfer-Encoding") is not None or self.headers.get("Content-Encoding") is not None:
                    raise ValueError("invalid transport")
                data=self.rfile.read(int(sizes[0]))
                if len(data)!=int(sizes[0]):raise ValueError("incomplete request")
                result=application.handle(data.decode("ascii",errors="strict")).encode("ascii")
                if len(result)>MAX_WIRE:raise ValueError("oversized response")
                status=200
            except Exception:result=b""
            self.send_response(status)
            self.send_header("Content-Type","application/sapi+jwe")
            self.send_header("Content-Length",str(len(result)))
            self.send_header("Cache-Control","no-store")
            self.send_header("X-Content-Type-Options","nosniff")
            self.send_header("Connection","close")
            if status==200 and origin:self.send_header("Access-Control-Allow-Origin",origin);self.send_header("Vary","Origin")
            if context:self.send_header("Strict-Transport-Security","max-age=31536000")
            self.end_headers();self.wfile.write(result);self.close_connection=True
        def do_OPTIONS(self):
            try:
                origin=self.origin()
                if self.path!="/sapi" or origin is None or self.headers.get_all("Access-Control-Request-Method",[])!=["POST"] or self.headers.get("Access-Control-Request-Headers","").lower()!="content-type":raise ValueError()
                self.send_response(204);self.send_header("Access-Control-Allow-Origin",origin);self.send_header("Vary","Origin");self.send_header("Access-Control-Allow-Methods","POST");self.send_header("Access-Control-Allow-Headers","Content-Type")
            except ValueError:self.send_response(400)
            self.send_header("Content-Length","0");self.send_header("Connection","close");self.end_headers();self.close_connection=True

    class Server(ThreadingHTTPServer):
        daemon_threads=True
        def process_request(self,request,address):
            # X-Forwarded-For is not an identity source. Use the actual socket peer.
            now=time.monotonic()
            with peer_lock:
                for peer,value in list(peers.items()):
                    if value[0]+60<=now:del peers[peer]
                value=peers.get(address[0],(now,0))
                if value[1]>=peer_requests or (address[0] not in peers and len(peers)>=4096):request.close();return
                peers[address[0]]=(value[0],value[1]+1)
            if not permits.acquire(blocking=False):request.close();return
            try:super().process_request(request,address)
            except BaseException:permits.release();request.close();raise
        def process_request_thread(self,request,address):
            transport=[request]
            def abort():
                try:transport[0].shutdown(socket.SHUT_RDWR)
                except OSError:pass
            timer=threading.Timer(timeout,abort);timer.daemon=True;timer.start()
            try:
                request.settimeout(timeout)
                if context:
                    transport[0]=context.wrap_socket(request,server_side=True,do_handshake_on_connect=False)
                    transport[0].do_handshake()
                self.finish_request(transport[0],address)
            except (OSError,ValueError):pass
            finally:
                timer.cancel();self.shutdown_request(transport[0]);permits.release()
        def handle_error(self,*_):pass
    return Server((host,port),Handler)
