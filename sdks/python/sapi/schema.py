"""Closed, bounded application schemas shared by every SAPi implementation."""
import copy
import math
import re

FIELD = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]*\Z")
UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
SAFE = 9007199254740991
FORBIDDEN = {"__proto__", "constructor", "prototype"}


class Schema:
    def __init__(self, definition, *, root_object=False):
        self._definition = copy.deepcopy(definition)
        self._nodes = 0
        self._compile(self._definition, 0)
        if root_object and self._definition["type"] != "object":
            raise ValueError("object schema required")

    @staticmethod
    def _integer(value):
        return type(value) in (int, float) and math.isfinite(value) and -SAFE <= value <= SAFE and value == math.floor(value)

    def _compile(self, node, depth):
        self._nodes += 1
        if depth > 16 or self._nodes > 256 or type(node) is not dict:
            raise ValueError("bounded schema required")
        kind = node.get("type")
        allowed = {"object": {"properties", "optional"}, "array": {"items", "minItems", "maxItems"},
                   "string": {"minBytes", "maxBytes", "format", "enum"}, "integer": {"min", "max"},
                   "number": {"min", "max"}, "boolean": set(), "null": set()}
        if kind not in allowed or node.keys() - {"type"} - allowed[kind]: raise ValueError("unsupported schema")
        if kind == "object":
            props = node.get("properties")
            if type(props) is not dict or len(props) > 64 or any(not FIELD.fullmatch(k) or k in FORBIDDEN for k in props): raise ValueError("safe properties required")
            optional = node.get("optional", [])
            if type(optional) is not list or any(type(k) is not str for k in optional) or len(set(optional)) != len(optional) or not set(optional) <= props.keys(): raise ValueError("optional properties invalid")
            for child in props.values(): self._compile(child, depth + 1)
        elif kind == "array":
            self._bounds(node, "minItems", "maxItems", 0, 16, 64)
            self._compile(node.get("items"), depth + 1)
        elif kind == "string":
            self._bounds(node, "minBytes", "maxBytes", 0, 4096, 65536)
            if node.get("format", "text") not in ("text", "identifier", "uuid"): raise ValueError("unsupported format")
            if "enum" in node:
                values = node["enum"]
                if type(values) is not list or not 1 <= len(values) <= 64 or any(type(v) is not str for v in values) or len(set(values)) != len(values) or any(not self._validate({k:v for k,v in node.items() if k != "enum"}, s) for s in values): raise ValueError("invalid enum")
        elif kind in ("integer", "number"):
            low, high = node.get("min", -SAFE), node.get("max", SAFE)
            if any(type(v) not in (int, float) or not math.isfinite(v) or not -SAFE <= v <= SAFE for v in (low, high)) or low > high or (kind == "integer" and not all(self._integer(v) for v in (low, high))): raise ValueError("invalid numeric bounds")

    @classmethod
    def _bounds(cls, node, lower, upper, default_low, default_high, cap):
        low, high = node.get(lower, default_low), node.get(upper, default_high)
        if not cls._integer(low) or not cls._integer(high) or not 0 <= low <= high <= cap: raise ValueError("invalid bounds")

    def validate(self, value):
        return self._validate(self._definition, value)

    def _validate(self, node, value):
        kind = node["type"]
        if kind == "object":
            props, optional = node["properties"], node.get("optional", [])
            return type(value) is dict and not value.keys() - props.keys() and props.keys() - set(optional) <= value.keys() and all(self._validate(props[k], v) for k,v in value.items())
        if kind == "array":
            return type(value) is list and node.get("minItems", 0) <= len(value) <= node.get("maxItems", 16) and all(self._validate(node["items"], v) for v in value)
        if kind == "string":
            if type(value) is not str: return False
            try: length = len(value.encode("utf-8", errors="strict"))
            except UnicodeError: return False
            if not node.get("minBytes", 0) <= length <= node.get("maxBytes", 4096) or any((ord(c) < 32 and c not in "\t\n\r") or ord(c) == 127 for c in value): return False
            form = node.get("format", "text")
            if form == "identifier" and not IDENTIFIER.fullmatch(value): return False
            if form == "uuid" and not UUID.fullmatch(value): return False
            return "enum" not in node or value in node["enum"]
        if kind == "integer": return self._integer(value) and node.get("min", -SAFE) <= value <= node.get("max", SAFE)
        if kind == "number": return type(value) in (int, float) and math.isfinite(value) and node.get("min", -SAFE) <= value <= node.get("max", SAFE)
        if kind == "boolean": return type(value) is bool
        return value is None
