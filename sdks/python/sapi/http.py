from __future__ import annotations
"""Bounded standard-library HTTP transport with an absolute response deadline."""
import http.client
import socket
import ssl
import threading
import time
import urllib.parse
from .constants import MAX_WIRE
from .errors import SapiError


def post(url, body, media_type, *, ca_file=None, certificate=None, private_key=None, timeout=30, limit=MAX_WIRE):
    address = urllib.parse.urlsplit(url)
    if address.scheme not in ("http", "https") or address.query or address.fragment or address.username or address.password or not address.hostname or timeout <= 0:
        raise ValueError("bounded HTTP(S) URL required")
    start = time.monotonic()
    if address.scheme == "https":
        context = ssl.create_default_context(cafile=ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if certificate: context.load_cert_chain(certificate, private_key)
        connection = http.client.HTTPSConnection(address.hostname, address.port, context=context, timeout=timeout)
    else:
        connection = http.client.HTTPConnection(address.hostname, address.port, timeout=timeout)
    timer = None
    expired = threading.Event()
    try:
        connection.connect()
        remaining = timeout - (time.monotonic() - start)
        if remaining <= 0: raise TimeoutError()
        active_socket = connection.sock
        def abort():
            expired.set()
            try: active_socket.shutdown(socket.SHUT_RDWR)
            except OSError: pass
        timer = threading.Timer(remaining, abort); timer.daemon = True; timer.start()
        connection.request("POST", address.path or "/", body, {"Content-Type": media_type, "Accept": media_type, "Connection": "close"})
        response = connection.getresponse()
        content_type = response.getheader("Content-Type", "").split(";")[0]
        data = response.read(limit + 1)
        if expired.is_set() or time.monotonic() - start >= timeout or len(data) > limit: raise SapiError("transport_error")
        return response.status, content_type, data
    finally:
        if timer: timer.cancel()
        connection.close()


def exchange(url: str, wire: str, *, ca_file=None, timeout=30) -> str:
    if urllib.parse.urlsplit(url).path != "/sapi": raise ValueError("/sapi URL required")
    if not isinstance(wire, str) or len(wire) > MAX_WIRE or not wire.isascii(): raise SapiError()
    status, media, data = post(url, wire.encode("ascii"), "application/sapi+jwe", ca_file=ca_file, timeout=timeout)
    if status != 200 or media != "application/sapi+jwe": raise SapiError("transport_error")
    return data.decode("ascii", errors="strict")
