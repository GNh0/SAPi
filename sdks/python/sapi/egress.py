"""Declared HTTPS destinations with DNS pinning, bounded IO and closed JSON output."""
import http.client
import ipaddress
import queue
import socket
import ssl
import threading
import time
import urllib.parse
from .constants import NAME
from .errors import SapiError
from .schema import Schema
from .serialization import parse
from .http_limits import LimitedMetadataReader

_dns_slots = threading.BoundedSemaphore(4)
_lookup = socket.getaddrinfo
_connect = socket.create_connection
_translated = (ipaddress.ip_network("64:ff9b::/96"),ipaddress.ip_network("64:ff9b:1::/48"))


def _resolve(host, port, timeout):
    if not _dns_slots.acquire(blocking=False): raise SapiError("outbound_unavailable")
    result = queue.Queue(maxsize=1)
    def lookup():
        try: result.put((True, _lookup(host, port, type=socket.SOCK_STREAM)))
        except Exception: result.put((False, None))
        finally: _dns_slots.release()
    threading.Thread(target=lookup, daemon=True).start()
    try: success, addresses = result.get(timeout=timeout)
    except queue.Empty: raise SapiError("outbound_unavailable")
    if not success or not 1 <= len(addresses) <= 32: raise SapiError("outbound_unavailable")
    ips = []
    for address in addresses:
        try: value = ipaddress.ip_address(address[4][0])
        except ValueError: raise SapiError("outbound_forbidden")
        if not value.is_global or value.is_multicast or value.is_unspecified or (getattr(value,"ipv4_mapped",None) and not value.ipv4_mapped.is_global): raise SapiError("outbound_forbidden")
        if isinstance(value,ipaddress.IPv6Address) and (value.scope_id or value.sixtofour or value.teredo or any(value in network for network in _translated)):
            raise SapiError("outbound_forbidden")
        ips.append(str(value))
    return ips[0]


class _ResponseSocket:
    def __init__(self, connection): self.connection = connection
    def makefile(self, mode): return LimitedMetadataReader(self.connection.makefile(mode))


class Egress:
    """Targets are deployment configuration; callers select a name and query values."""
    def __init__(self, targets, *, ca_file=None, timeout=3, limit=65000):
        if type(targets) is not dict or len(targets) > 64 or not 0 < timeout <= 10 or not 1 <= limit <= 65000: raise ValueError("bounded target configuration required")
        self._targets = {}
        self._timeout, self._limit = timeout, limit
        self._context = ssl.create_default_context(cafile=ca_file)
        self._context.minimum_version = ssl.TLSVersion.TLSv1_2
        for name, value in targets.items():
            if not isinstance(name,str) or not NAME.fullmatch(name) or type(value) is not dict or set(value) != {"origin","path","input","output"}: raise ValueError("declared target required")
            origin = urllib.parse.urlsplit(value["origin"])
            if origin.scheme != "https" or not origin.hostname or not origin.hostname.isascii() or origin.path not in ("","/") or origin.query or origin.fragment or origin.username or origin.password or (origin.port is not None and not 1<=origin.port<=65535) or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:" for c in origin.hostname): raise ValueError("fixed HTTPS origin required")
            path = value["path"]
            if not isinstance(path,str) or not path.startswith("/") or path.startswith("//") or not path.isascii() or any(c not in "/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-~" for c in path) or ".." in path.split("/"): raise ValueError("fixed URL path required")
            input_schema = Schema(value["input"], root_object=True)
            if any(s["type"] not in ("string","integer","number","boolean") for s in value["input"]["properties"].values()): raise ValueError("scalar query parameters required")
            self._targets[name] = (origin.hostname, origin.port or 443, path, input_schema, Schema(value["output"],root_object=True))

    def fetch(self, name, values):
        target = self._targets.get(name)
        if target is None: raise SapiError("outbound_forbidden")
        host, port, path, input_schema, output_schema = target
        if not input_schema.validate(values): raise SapiError("invalid_input")
        deadline = time.monotonic() + self._timeout
        def remaining():
            value = deadline - time.monotonic()
            if value <= 0: raise SapiError("outbound_unavailable")
            return value
        transport, timer, response = [None], None, None
        try:
            # Resolve once and connect to the verified numeric address, retaining SNI
            # and certificate verification against the configured hostname.
            ip = _resolve(host, port, remaining())
            transport[0] = _connect((ip,port), timeout=remaining())
            def abort():
                try: transport[0].shutdown(socket.SHUT_RDWR)
                except (OSError,AttributeError): pass
            timer = threading.Timer(remaining(),abort);timer.daemon=True;timer.start()
            transport[0] = self._context.wrap_socket(transport[0],server_hostname=host,do_handshake_on_connect=False)
            transport[0].settimeout(remaining());transport[0].do_handshake()
            query = urllib.parse.urlencode({k:("true" if v else "false") if type(v) is bool else str(v) for k,v in values.items()})
            authority = ("["+host+"]") if ":" in host else host
            if port != 443: authority += ":" + str(port)
            request = "GET " + path + (("?"+query) if query else "") + " HTTP/1.1\r\nHost: " + authority + "\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
            if len(request) > 16384: raise SapiError("invalid_input")
            transport[0].settimeout(remaining());transport[0].sendall(request.encode("ascii"))
            response = http.client.HTTPResponse(_ResponseSocket(transport[0]));response.begin()
            if 300 <= response.status < 400: raise SapiError("outbound_forbidden")
            if response.status != 200 or response.getheader("Content-Type","").split(";")[0].strip().lower() != "application/json": raise SapiError("outbound_unavailable")
            length = response.getheader("Content-Length")
            transfer=response.getheader("Transfer-Encoding")
            if transfer not in (None,"chunked") or (transfer is not None and length is not None):raise SapiError("outbound_unavailable")
            if length is not None and (not length.isdigit() or int(length)>self._limit): raise SapiError("outbound_unavailable")
            if response.getheader("Content-Encoding") not in (None,"identity"): raise SapiError("outbound_unavailable")
            body = response.read(self._limit+1)
            if len(body)>self._limit or (length is not None and len(body)!=int(length)): raise SapiError("outbound_unavailable")
            remaining();value=parse(body)
            if not output_schema.validate(value): raise SapiError("outbound_unavailable")
            return value
        except SapiError: raise
        except Exception: raise SapiError("outbound_unavailable")
        finally:
            if timer:timer.cancel()
            if response:response.close()
            if transport[0]:transport[0].close()
