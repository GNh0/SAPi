"""Optional standard-library HTTP binding, with certificate checks and no redirects."""
import ssl
import urllib.parse
import urllib.request
from .constants import MAX_WIRE
from .errors import SapiError


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def exchange(url: str, wire: str, *, ca_file: str | None = None, timeout=30) -> str:
    address = urllib.parse.urlsplit(url)
    if address.scheme not in ("http", "https") or address.path != "/sapi" or address.query or address.fragment or address.username:
        raise ValueError("HTTP(S) /sapi URL required")
    if len(wire) > MAX_WIRE or not wire.isascii():
        raise SapiError()
    context = ssl.create_default_context(cafile=ca_file)
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(url, wire.encode("ascii"), {"Content-Type": "application/sapi+jwe", "Accept": "application/sapi+jwe"}, method="POST")
    with opener.open(request, timeout=timeout) as response:
        if response.status != 200 or response.headers.get_content_type() != "application/sapi+jwe":
            raise SapiError("transport_error")
        data = response.read(MAX_WIRE + 1)
    if len(data) > MAX_WIRE:
        raise SapiError("transport_error")
    return data.decode("ascii", errors="strict")
