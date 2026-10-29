"""Canonical bytes shared with the Go sidecar; no policy evaluation belongs here."""

from __future__ import annotations

import json
import math
from decimal import Decimal
from typing import cast

from .types import AuthRailError, JSONObject, JSONValue, Phase

MAX_CONTEXT = 128 * 1024
MAX_VALUE = 64 * 1024


def _string(value: str) -> str:
    # Go encoding/json escapes HTML and JavaScript line separators in signed bytes.
    encoded = json.dumps(value, ensure_ascii=False)
    for char in "<>&\u2028\u2029":
        encoded = encoded.replace(char, f"\\u{ord(char):04x}")
    try:
        encoded.encode("utf-8")
    except UnicodeError:
        raise AuthRailError("Context contains invalid Unicode") from None
    return encoded


def canonical(value: object, *, ordered: bool = False, _depth: int = 0) -> str:
    """Encode strict JSON with Go-compatible ordering, escaping and number notation."""
    if _depth > 64:
        raise AuthRailError("Context nesting is too deep")
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is str:
        return _string(value)
    if type(value) is int:
        # The sidecar evaluates JSON numbers as float64; do not silently round Python integers.
        if abs(value) > 2**53 - 1:
            raise AuthRailError("Use a string for integers outside the safe JSON range")
        return str(value)
    if type(value) is float:
        if not math.isfinite(value):
            raise AuthRailError("Context must contain finite JSON numbers")
        if value == 0:
            return "0"
        text = repr(value).lower()
        if 1e-6 <= abs(value) < 1e21:
            decimal = format(Decimal(text), "f")
            return decimal.rstrip("0").rstrip(".") if "." in decimal else decimal
        mantissa, exponent = text.split("e")
        mantissa = mantissa.removesuffix(".0")
        number = int(exponent)
        return f"{mantissa}e{'+' if number >= 0 else '-'}{abs(number)}"
    if type(value) is list:
        return "[" + ",".join(canonical(v, _depth=_depth + 1) for v in value) + "]"
    if type(value) is dict and all(type(k) is str for k in value):
        try:
            keys = list(value) if ordered else sorted(value, key=lambda key: key.encode("utf-8"))
        except UnicodeError:
            raise AuthRailError("Context contains invalid Unicode") from None
        return (
            "{"
            + ",".join(_string(k) + ":" + canonical(value[k], _depth=_depth + 1) for k in keys)
            + "}"
        )
    raise AuthRailError("Context must contain only JSON values")


def parse_object(data: bytes) -> JSONObject:
    """Reject duplicate keys and non-JSON constants before accepting local responses."""

    def pairs(items: list[tuple[str, JSONValue]]) -> JSONObject:
        result: JSONObject = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def invalid_constant(_: str) -> None:
        raise ValueError("invalid constant")

    def integer(text: str) -> int | float:
        number = int(text)
        # Canonical float64 values such as 1e20 use decimal notation on the wire.
        # Restore them as floats rather than mistaking them for unsafe Python ints.
        return number if abs(number) <= 2**53 - 1 else float(text)

    try:
        value = json.loads(
            data, object_pairs_hook=pairs, parse_constant=invalid_constant, parse_int=integer
        )
        if type(value) is not dict:
            raise ValueError("object required")
        canonical(value)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise AuthRailError("Invalid JSON object") from None
    return cast(JSONObject, value)


def snapshot(value: object, limit: int = MAX_CONTEXT) -> bytes:
    encoded = canonical(value).encode("utf-8")
    if len(encoded) > limit:
        raise AuthRailError("Context exceeds its size limit")
    return encoded


def _fields(value: JSONValue, names: tuple[str, ...], required: tuple[str, ...]) -> str:
    if type(value) is not dict or set(value) - set(names) or not set(required) <= set(value):
        raise AuthRailError("Invalid contextual input fields")
    return (
        "{"
        + ",".join(
            _string(k) + ":" + canonical(value[k])
            for k in names
            if k in value and (k in required or value[k] not in (None, "", [], {}))
        )
        + "}"
    )


def encode_input(call: JSONObject, phase: Phase, result: object = None) -> str:
    """Bind arguments and phase-specific result plus facts/history to the executor proof."""
    entries = ['"arguments":' + canonical(call["arguments"])]
    if phase == "tool_result":
        if type(result) is not dict:
            raise AuthRailError("Tool result must be a JSON object")
        snapshot(result, MAX_VALUE)
        entries.append('"result":' + canonical(result))
    facts = call.get("factResolutions")
    if facts:
        if type(facts) is not list:
            raise AuthRailError("Invalid fact resolutions")
        encoded = []
        names = (
            "sourceVersionId",
            "providerAccountId",
            "sourceIdentity",
            "accountBoundary",
            "lookup",
            "lookupKey",
            "authenticatedExecutor",
            "status",
            "observedAt",
            "value",
            "extraction",
        )
        for fact in facts:
            # These struct fields have an explicit order in the sidecar's digest.
            text = _fields(
                fact,
                names,
                ("sourceVersionId", "lookup", "lookupKey", "authenticatedExecutor", "status"),
            )
            if type(fact) is dict and fact.get("extraction"):
                extraction = _fields(
                    fact["extraction"],
                    (
                        "sourceSha256",
                        "sourceBytes",
                        "sourceLocation",
                        "modelId",
                        "modelConfigSha256",
                        "promptVersion",
                        "extractedAt",
                    ),
                    (
                        "sourceSha256",
                        "sourceBytes",
                        "sourceLocation",
                        "modelId",
                        "modelConfigSha256",
                        "promptVersion",
                        "extractedAt",
                    ),
                )
                text = text[: text.rfind('"extraction":')] + '"extraction":' + extraction + "}"
            encoded.append(text)
        entries.append('"factResolutions":[' + ",".join(encoded) + "]")
    trajectory = call.get("trajectory")
    if trajectory:
        if type(trajectory) is dict and trajectory.get("start") is False:
            trajectory = {key: value for key, value in trajectory.items() if key != "start"}
        entries.append(
            '"trajectory":'
            + _fields(
                trajectory,
                ("sessionId", "start", "complete", "priorReadOperationVersionIds", "values"),
                ("sessionId", "complete", "priorReadOperationVersionIds"),
            )
        )
    if call.get("guardEvidence"):
        entries.append('"guardEvidence":' + canonical(call["guardEvidence"]))
    return "{" + ",".join(entries) + "}"
