"""Exact, version-pinned string processing requested by the local sidecar."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import re
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Literal, cast

from ._async import with_deadline
from ._protocol import MAX_VALUE, canonical, parse_object, snapshot
from .observe import _UUID, _matches
from .types import AuthRailError, JSONObject, JSONValue, Phase

_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,79}\Z")
_SEGMENT = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,79}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN = {"__proto__", "prototype", "constructor"}


@dataclass(frozen=True, kw_only=True)
class GuardHandler:
    """Pure processing for one reviewed handler version; it never performs a business effect."""

    id: str
    version: str
    kind: Literal["sanitize", "transform"]
    process: Callable[[str], str | Awaitable[str]] = field(repr=False)


def registered_handlers(
    handlers: Sequence[GuardHandler] | None,
) -> dict[tuple[str, str, str], GuardHandler]:
    registered: dict[tuple[str, str, str], GuardHandler] = {}
    if handlers is None:
        return registered
    if len(handlers) > 64:
        raise AuthRailError("Too many Guard handlers")
    for handler in handlers:
        if (
            not isinstance(handler, GuardHandler)
            or not _matches(_IDENTIFIER, handler.id)
            or not _matches(_DIGEST, handler.version)
            or handler.kind not in ("sanitize", "transform")
            or not callable(handler.process)
        ):
            raise AuthRailError("Invalid Guard handler")
        key = (handler.id, handler.version, handler.kind)
        if key in registered:
            raise AuthRailError("Duplicate Guard handler")
        registered[key] = handler
    return registered


@dataclass(frozen=True)
class GuardProcessing:
    output: JSONObject = field(repr=False)
    evidence: list[JSONValue] = field(repr=False)
    bundle_id: str
    sequence: int


async def process_guard(
    plan: JSONObject,
    operation_version_id: str,
    phase: Phase,
    value: JSONObject,
    handlers: dict[tuple[str, str, str], GuardHandler],
) -> GuardProcessing:
    """Process a copy; malformed, overlapping or unsupported obligations stop the boundary."""
    required = {
        "formatVersion",
        "operationVersionId",
        "phase",
        "bundleId",
        "sequence",
        "coverage",
        "requirements",
    }
    requirements = plan.get("requirements")
    if (
        set(plan) != required
        or type(plan.get("formatVersion")) is not int
        or plan["formatVersion"] != 1
        or plan["operationVersionId"] != operation_version_id
        or plan["phase"] != phase
        or not _matches(_UUID, plan.get("bundleId"))
        or type(plan["sequence"]) is not int
        or plan["sequence"] < 1
        or plan["coverage"] != "evaluated"
        or type(requirements) is not list
        or len(requirements) > 64
    ):
        raise AuthRailError("Invalid Guard processing plan")
    reviewed: list[JSONObject] = []
    seen: set[str] = set()
    paths: list[list[str]] = []
    for requirement in requirements:
        if type(requirement) is not dict or set(requirement) != {
            "railVersionId",
            "ruleId",
            "kind",
            "handlerId",
            "handlerVersion",
            "target",
        }:
            raise AuthRailError("Invalid Guard requirement")
        target = requirement["target"]
        if (
            not _matches(_UUID, requirement["railVersionId"])
            or not _matches(_IDENTIFIER, requirement["ruleId"])
            or requirement["kind"] not in ("sanitize", "transform", "isolate")
            or not _matches(_IDENTIFIER, requirement["handlerId"])
            or not _matches(_DIGEST, requirement["handlerVersion"])
            or type(target) is not dict
            or set(target) != {"root", "path"}
            or target["root"] != ("arguments" if phase == "tool_call" else "result")
            or type(target["path"]) is not list
            or not 1 <= len(target["path"]) <= 8
            or any(not _matches(_SEGMENT, part) or part in _FORBIDDEN for part in target["path"])
        ):
            raise AuthRailError("Invalid Guard target or handler identity")
        key = canonical(
            {k: requirement[k] for k in ("kind", "handlerId", "handlerVersion", "target")}
        )
        if key in seen:
            continue
        path = cast(list[str], target["path"])
        if any(
            path[: min(len(path), len(old))] == old[: min(len(path), len(old))] for old in paths
        ):
            raise AuthRailError("Overlapping Guard targets")
        seen.add(key)
        paths.append(path)
        reviewed.append(requirement)
    output = parse_object(snapshot(value, MAX_VALUE))
    evidence: list[JSONValue] = []
    for requirement in reviewed:
        if requirement["kind"] == "isolate":
            raise AuthRailError("This adapter cannot fulfil an isolation obligation")
        handler_key = tuple(
            cast(str, requirement[k]) for k in ("handlerId", "handlerVersion", "kind")
        )
        handler = handlers.get(cast(tuple[str, str, str], handler_key))
        if handler is None:
            raise AuthRailError("Exact reviewed Guard handler is not registered")
        target = cast(JSONObject, requirement["target"])
        path = cast(list[str], target["path"])
        parent = output
        for part in path[:-1]:
            child = parent.get(part)
            if type(child) is not dict:
                raise AuthRailError("Guard target does not exist")
            parent = child
        before = parent.get(path[-1])
        if type(before) is not str:
            raise AuthRailError("Guard target must be a string")

        after = await with_deadline(_invoke_handler(handler, before), 4.0)
        if type(after) is not str:
            raise AuthRailError("Guard handler did not return a string")
        parent[path[-1]] = after
        snapshot(output, MAX_VALUE)
        evidence.append(
            {
                "phase": phase,
                "bundleId": plan["bundleId"],
                "kind": requirement["kind"],
                "handlerId": handler.id,
                "handlerVersion": handler.version,
                "target": target,
                "inputSha256": hashlib.sha256(canonical(before).encode()).hexdigest(),
                "outputSha256": hashlib.sha256(canonical(after).encode()).hexdigest(),
            }
        )
    return GuardProcessing(output, evidence, cast(str, plan["bundleId"]), plan["sequence"])


async def _invoke_handler(processor: GuardHandler, text: str) -> str:
    # Pure synchronous processing must not stall the decision event loop.
    if inspect.iscoroutinefunction(processor.process):
        return await cast(Awaitable[str], processor.process(text))
    result = await asyncio.to_thread(processor.process, text)
    return await result if inspect.isawaitable(result) else result
