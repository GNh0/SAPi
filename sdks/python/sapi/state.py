"""Optional mTLS state authority adapter. No key cache or plaintext control channel."""
import urllib.parse
from .http import post
from .models import KeyRecord
from .errors import SapiError
from .serialization import encode, parse, unb64


class StateClient:
    def __init__(self, url, *, ca_file, certificate, private_key, timeout=10):
        address = urllib.parse.urlsplit(url)
        if address.scheme != "https" or address.path not in ("", "/") or address.query or address.fragment or address.username or address.password:
            raise ValueError("HTTPS authority origin required")
        self.url = url.rstrip("/") + "/v1/state"
        self.options = dict(ca_file=ca_file, certificate=certificate, private_key=private_key, timeout=timeout, limit=1048576)

    def call(self, action, **parameters):
        try:
            status, media, data = post(self.url, encode(dict(action=action, **parameters)), "application/json", **self.options)
            if media != "application/json": raise SapiError("state_unavailable")
            result = parse(data)
            if status != 200 or "error" in result: raise SapiError(result.get("error", "state_unavailable"))
            return result
        except SapiError: raise
        except Exception: raise SapiError("state_unavailable")

    def get(self, service, kid):
        return self._record(self.call("key", service=service, kid=kid))

    def reserve(self, service, kid, direction):
        return self._record(self.call("reserve", service=service, kid=kid, direction=direction))

    @staticmethod
    def _record(value):
        return KeyRecord(unb64(value["master"]), value["subject"], frozenset(value["scopes"]))

    def claim(self, name, expiry, now):
        return self.call("claim", name=name, expiry=int(expiry))["claimed"] is True

    def request(self, codec, subject, operation, data):
        for attempt in range(3):
            kid = self.call("active", service=codec.service, subject=subject)["kid"]
            try: return codec.request(kid, operation, data)
            except SapiError as exc:
                if exc.code not in ("key_retired", "key_rotation_required") or attempt == 2: raise

