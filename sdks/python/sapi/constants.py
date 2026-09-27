import re

MAX_WIRE = 131072
MAX_BODY = 65536
NAME = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")
HEADER_KEYS = {"alg", "enc", "typ", "kid", "sapi", "dir", "svc", "crit"}
