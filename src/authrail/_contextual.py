"""Select reviewed material and request AuthRail findings through the local sidecar."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
import time
from typing import cast
from urllib.parse import urlencode

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._http import response_object
from ._protocol import canonical, encode_input, snapshot
from .types import AuthRailError, JSONObject, JSONValue, Phase, PreparedCall

_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,79}\Z")
_HANDLER = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,79}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN = {"__proto__", "prototype", "constructor"}


def _identifier(value: object, pattern: re.Pattern[str]) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _selected(fields: list[JSONValue], body: JSONObject, phase: Phase, result: object) -> list[str]:
    values: list[str] = []
    for field in fields:
        if type(field) is not dict:
            raise AuthRailError("Invalid contextual material selection")
        root, path = field.get("root"), field.get("path")
        if (
            root not in ("arguments", "result")
            or (phase == "tool_call" and root == "result")
            or type(path) is not list
            or not 1 <= len(path) <= 8
            or any(not _identifier(part, _NAME) or part in _FORBIDDEN for part in path)
        ):
            raise AuthRailError("Invalid contextual material selection")
        value: object = body["arguments"] if root == "arguments" else result
        for part in path:
            value = value.get(cast(str, part)) if type(value) is dict else None
        if type(value) is not str or not value.strip():
            return []
        values.append(value)
    return values


def _disclosure_processed(plan: JSONObject, body: JSONObject, phase: Phase, result: object) -> bool:
    requirements = plan.get("disclosureRequirements")
    evidence = body.get("guardEvidence")
    if (
        type(requirements) is not list
        or not 1 <= len(requirements) <= 128
        or type(evidence) is not list
        or len(evidence) > 128
    ):
        return False
    for requirement in requirements:
        if type(requirement) is not dict:
            return False
        target = requirement.get("target")
        handler = requirement.get("handlerId")
        version = requirement.get("handlerVersion")
        if (
            not _identifier(handler, _HANDLER)
            or not _identifier(version, _DIGEST)
            or requirement.get("kind") not in ("sanitize", "transform", "isolate")
            or type(target) is not dict
            or target.get("root") not in ("arguments", "result")
            or (phase == "tool_call" and target.get("root") == "result")
            or type(target.get("path")) is not list
        ):
            return False
        path = cast(list[JSONValue], target["path"])
        if not 1 <= len(path) <= 8 or any(
            not _identifier(part, _NAME) or part in _FORBIDDEN for part in path
        ):
            return False
        processing_phase = "tool_call" if target.get("root") == "arguments" else "tool_result"
        value: object = body["arguments"] if processing_phase == "tool_call" else result
        for part in path:
            value = value.get(cast(str, part)) if type(value) is dict else None
        if type(value) is not str:
            return False
        matches = [
            item
            for item in evidence
            if type(item) is dict
            and item.get("phase") == processing_phase
            and item.get("bundleId") == plan["bundleId"]
            and all(
                item.get(key) == requirement.get(key)
                for key in ("handlerId", "handlerVersion", "kind", "target")
            )
        ]
        if (
            len(matches) != 1
            or matches[0].get("outputSha256")
            != hashlib.sha256(canonical(value).encode()).hexdigest()
        ):
            return False
    return True


async def read_contextual(
    http: httpx.AsyncClient,
    *,
    endpoint: str,
    token: str,
    organisation_id: str,
    deployment_id: str,
    private_key: Ed25519PrivateKey,
    call: PreparedCall,
    phase: Phase,
    result: object,
) -> list[JSONValue]:
    """A missing finding stays missing; this integration never fabricates a rule answer."""
    body = call.as_dict()
    query = urlencode({"operationVersionId": body["operationVersionId"], "phase": phase})
    headers = {"Authorization": "Bearer " + token}
    if call.traceparent:
        headers["traceparent"] = call.traceparent
    try:
        async with (
            asyncio.timeout(4),
            http.stream(
                "GET", endpoint + "/contextual-requirements?" + query, headers=headers, timeout=4
            ) as response,
        ):
            # Older runtimes cannot satisfy contextual rules, but still evaluate ordinary Rails.
            if response.status_code == 404:
                return []
            if response.status_code != 200:
                raise AuthRailError("Contextual requirements are unavailable")
            plan = await response_object(response, 128 * 1024)
    except (httpx.HTTPError, TimeoutError):
        raise AuthRailError("Contextual requirements are unavailable") from None
    requirements = plan.get("requirements")
    if (
        plan.get("formatVersion") != 1
        or plan.get("operationVersionId") != body["operationVersionId"]
        or plan.get("phase") != phase
        or type(requirements) is not list
        or len(requirements) > 8
    ):
        raise AuthRailError("Invalid contextual requirements")
    if plan.get("coverage") in ("uncovered", "unavailable") and not requirements:
        return []
    if plan.get("coverage") != "evaluated" or not _identifier(plan.get("bundleId"), _UUID):
        raise AuthRailError("Invalid contextual requirements")
    if plan.get("disclosureProcessing") is True and not _disclosure_processed(
        plan, body, phase, result
    ):
        return []
    input_digest = hashlib.sha256(encode_input(body, phase, result).encode()).hexdigest()
    attribution = cast(JSONObject, body["attribution"])
    ordered_attribution = {
        key: attribution[key]
        for key in ("principalId", "sessionId", "resourceId", "principalSource", "resourceSource")
    }
    attribution_digest = hashlib.sha256(
        canonical(ordered_attribution, ordered=True).encode()
    ).hexdigest()
    public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    key_digest = hashlib.sha256(public).hexdigest()
    findings: list[JSONValue] = []
    seen: set[str] = set()
    for requirement in requirements:
        if type(requirement) is not dict or not _identifier(
            requirement.get("railVersionId"), _UUID
        ):
            raise AuthRailError("Invalid contextual requirement")
        assessment = requirement.get("assessment")
        if type(assessment) is not dict:
            raise AuthRailError("Invalid contextual assessment")
        fields = assessment.get("fields")
        if (
            not _identifier(assessment.get("id"), _NAME)
            or assessment.get("phase") not in ("tool_call", "tool_result")
            or type(fields) is not list
            or not 1 <= len(fields) <= 4
        ):
            raise AuthRailError("Invalid contextual assessment")
        identity = str(requirement["railVersionId"]) + ":" + str(assessment["id"])
        if identity in seen:
            raise AuthRailError("Duplicated contextual assessment")
        seen.add(identity)
        selected = _selected(fields, body, phase, result)
        if len(selected) != len(fields):
            continue
        material = canonical(selected).encode()
        if len(material) > 16_384:
            continue
        now = int(time.time())
        statement: JSONObject = {
            "type": "authrail.contextual.request.v1",
            "organisationId": organisation_id,
            "deploymentId": deployment_id,
            "bundleId": plan["bundleId"],
            "railVersionId": requirement["railVersionId"],
            "assessmentId": assessment["id"],
            "operationVersionId": body["operationVersionId"],
            "requestId": call.request_id,
            "phase": phase,
            "inputSha256": input_digest,
            "attributionSha256": attribution_digest,
            "materialSha256": hashlib.sha256(material).hexdigest(),
            "keySha256": key_digest,
            "issuedAt": now,
            "expiresAt": now + 30,
        }
        request: JSONObject = {
            "formatVersion": 1,
            **{
                key: statement[key]
                for key in (
                    "bundleId",
                    "railVersionId",
                    "assessmentId",
                    "operationVersionId",
                    "requestId",
                    "phase",
                    "inputSha256",
                    "attributionSha256",
                )
            },
            "material": base64.urlsafe_b64encode(material).rstrip(b"=").decode(),
            "keySha256": key_digest,
            "proof": {
                "issuedAt": now,
                "expiresAt": now + 30,
                "signature": base64.urlsafe_b64encode(
                    private_key.sign(canonical(statement, ordered=True).encode())
                )
                .rstrip(b"=")
                .decode(),
            },
        }
        try:
            async with (
                asyncio.timeout(12),
                http.stream(
                    "POST",
                    endpoint + "/contextual-readings",
                    headers={**headers, "Content-Type": "application/json"},
                    content=snapshot(request),
                    timeout=12,
                ) as response,
            ):
                if response.status_code != 200:
                    continue
                finding = await response_object(response, 8192)
            if (
                set(finding) == {"payload", "keyId", "algorithm", "signature"}
                and type(finding["payload"]) is str
                and len(finding["payload"]) <= 4096
                and type(finding["keyId"]) is str
                and finding["algorithm"] == "ECDSA_SHA_256"
                and type(finding["signature"]) is str
            ):
                findings.append(finding)
        except (httpx.HTTPError, TimeoutError, AuthRailError):
            # The deterministic evaluator handles unavailable context under the published rule.
            continue
    return findings
