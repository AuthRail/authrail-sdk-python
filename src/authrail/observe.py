"""Async advisory checks at the application's real tool boundary."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
import time
import uuid
from collections.abc import Awaitable, Callable
from types import TracebackType
from typing import TypeVar, cast
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._protocol import MAX_CONTEXT, MAX_VALUE, canonical, encode_input, parse_object, snapshot
from .types import (
    AuthRailError,
    Decision,
    JSONObject,
    JSONValue,
    Observation,
    ObserveRun,
    Operation,
    Phase,
    PreparedCall,
)

T = TypeVar("T")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
_REF = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
_TRACE = re.compile(r"00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}\Z")


def _matches(pattern: re.Pattern[str], value: object) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


class AsyncObserveClient:
    """Observe one local deployment. This client never blocks a business action on a rule."""

    def __init__(
        self,
        *,
        sidecar_url: str,
        adapter_token: str,
        organisation_id: str,
        deployment_id: str,
        executor_private_key: bytes | Ed25519PrivateKey,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        try:
            url = urlsplit(sidecar_url)
            port = url.port
            valid = (
                url.scheme == "http"
                and url.hostname in ("127.0.0.1", "::1")
                and url.username is None
                and url.password is None
                and url.path in ("", "/")
                and not url.query
                and not url.fragment
                and (port is None or 0 < port <= 65535)
                and "?" not in sidecar_url
                and "#" not in sidecar_url
                and not any(c.isspace() or ord(c) < 32 for c in sidecar_url)
                and _matches(_REF, adapter_token)
                and len(adapter_token) >= 32
                and _matches(_UUID, organisation_id)
                and _matches(_UUID, deployment_id)
            )
            if not valid:
                raise ValueError("configuration")
            private: object = executor_private_key
            if isinstance(executor_private_key, bytes):
                private = serialization.load_pem_private_key(executor_private_key, password=None)
            if not isinstance(private, Ed25519PrivateKey):
                raise ValueError("key")
        except (ValueError, TypeError, AttributeError):
            raise AuthRailError("Invalid local sidecar configuration or Ed25519 key") from None
        self._endpoint = sidecar_url.rstrip("/")
        self._token = adapter_token
        self._organisation_id = organisation_id
        self._deployment_id = deployment_id
        self._private = private
        # Never send a local adapter credential through an environment proxy or a redirect.
        self._http = httpx.AsyncClient(
            transport=transport, trust_env=False, follow_redirects=False, timeout=2.0
        )
        self._pending: set[asyncio.Task[Observation]] = set()

    async def __aenter__(self) -> AsyncObserveClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close connections after the application has awaited its Observe runs."""
        await self._http.aclose()

    def prepare(self, operation: Operation, arguments: JSONObject) -> PreparedCall:
        """Snapshot trusted caller context once and reuse its identity for both phases."""
        if not isinstance(operation, Operation):
            raise AuthRailError("Operation is required")
        if (
            not _matches(_UUID, operation.version_id)
            or not all(
                _matches(_REF, v)
                for v in (operation.action_key, operation.principal_id, operation.session_id)
            )
            or (operation.resource_id is not None and not _matches(_REF, operation.resource_id))
            or operation.principal_source not in ("application_session", "service_identity")
            or operation.resource_source not in ("application_lookup", "not_applicable")
            or type(arguments) is not dict
            or type(operation.fact_resolutions) is not list
        ):
            raise AuthRailError("Invalid action identity or arguments")
        if operation.traceparent is not None:
            match = _TRACE.fullmatch(operation.traceparent)
            if not match or match[1] == "0" * 32 or match[2] == "0" * 16:
                raise AuthRailError("Invalid trace context")
        snapshot(arguments, MAX_VALUE)
        body: JSONObject = {
            "requestId": str(uuid.uuid4()),
            "operationVersionId": operation.version_id,
            "arguments": arguments,
            "attribution": {
                "principalId": operation.principal_id,
                "sessionId": operation.session_id,
                "resourceId": operation.resource_id,
                "principalSource": operation.principal_source,
                "resourceSource": operation.resource_source,
            },
        }
        if operation.fact_resolutions:
            body["factResolutions"] = cast(list[JSONValue], operation.fact_resolutions)
        if operation.trajectory is not None:
            body["trajectory"] = operation.trajectory
        encoded = snapshot(body)
        # Validate contextual field names before any asynchronous work or signature.
        encode_input(parse_object(encoded), "tool_call")
        return PreparedCall(
            cast(str, body["requestId"]), operation.action_key, operation.traceparent, encoded
        )

    def _proof(
        self,
        call: PreparedCall,
        phase: Phase,
        result: object,
        issued_at: int,
    ) -> JSONObject:
        body = call.as_dict()
        attribution = cast(JSONObject, body["attribution"])
        ordered_attribution = {
            k: attribution[k]
            for k in ("principalId", "sessionId", "resourceId", "principalSource", "resourceSource")
        }
        statement: JSONObject = {
            "type": "authrail.observe.executor.v1",
            "organisationId": self._organisation_id,
            "deploymentId": self._deployment_id,
            "requestId": call.request_id,
            "actionKey": call.action_key,
            "operationVersionId": body["operationVersionId"],
            "phase": phase,
            "inputSha256": hashlib.sha256(encode_input(body, phase, result).encode()).hexdigest(),
        }
        # Statement and attribution are Go structs, whose field order differs from JSON maps.
        message = canonical(statement, ordered=True)[:-1]
        message += ',"attribution":' + canonical(ordered_attribution, ordered=True)
        message += f',"issuedAt":{issued_at},"expiresAt":{issued_at + 30}' + "}"
        signature = self._private.sign(message.encode("utf-8"))
        return {
            "issuedAt": issued_at,
            "expiresAt": issued_at + 30,
            "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
        }

    async def evaluate(
        self,
        call: PreparedCall,
        phase: Phase,
        result: object = None,
    ) -> Decision:
        """Check an Observe phase; callers must never use this as Enforce permission."""
        if phase not in ("tool_call", "tool_result"):
            raise AuthRailError("Invalid evaluation phase")
        body = call.as_dict()
        body["formatVersion"] = 1
        body["phase"] = phase
        body["identityProof"] = self._proof(call, phase, result, int(time.time()))
        if phase == "tool_result":
            body["result"] = cast(JSONObject, result)
        headers = {
            "Authorization": "Bearer " + self._token,
            "Idempotency-Key": call.action_key,
            "Content-Type": "application/json",
        }
        if call.traceparent:
            headers["traceparent"] = call.traceparent
        try:
            async with (
                asyncio.timeout(2.0),
                self._http.stream(
                    "POST",
                    self._endpoint + "/evaluate",
                    headers=headers,
                    content=snapshot(body),
                ) as response,
            ):
                if response.status_code != 200:
                    raise AuthRailError(f"Sidecar returned HTTP {response.status_code}")
                data = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(data) + len(chunk) > MAX_CONTEXT:
                        raise AuthRailError("Sidecar response exceeds its size limit")
                    data.extend(chunk)
                value = parse_object(bytes(data))
        except (httpx.HTTPError, TimeoutError):
            raise AuthRailError("Sidecar check unavailable") from None
        if (
            value.get("requestId") != call.request_id
            or value.get("mode") != "observe"
            or value.get("enforced") is not False
            or value.get("coverage") not in ("evaluated", "uncovered", "unavailable")
            or value.get("outcome")
            not in (
                "allow",
                "deny",
                "approval_required",
                "additional_context_required",
                "indeterminate",
            )
            or (
                "recordingStatus" in value
                and value["recordingStatus"] not in ("retained", "queued", "unavailable")
            )
            or ("reportReplayed" in value and type(value["reportReplayed"]) is not bool)
            or any(
                k in value and not _matches(_UUID, value[k])
                for k in ("actionId", "certificateId", "approvalRequestId")
            )
        ):
            raise AuthRailError("Invalid sidecar decision")
        return Decision(
            call.request_id,
            cast(str, value["outcome"]),
            cast(str, value["coverage"]),
            cast(str | None, value.get("recordingStatus")),
            cast(str | None, value.get("actionId")),
            snapshot(value),
        )

    async def _check(
        self,
        call: PreparedCall,
        phase: Phase,
        result: object = None,
    ) -> tuple[Decision | None, AuthRailError | None]:
        try:
            return await self.evaluate(call, phase, result), None
        except AuthRailError as error:
            return None, error
        except Exception:
            # Do not retain provider text, exception arguments or credentials in diagnostics.
            return None, AuthRailError("Advisory check unavailable or invalid")

    def observe(
        self,
        operation: Operation,
        arguments: JSONObject,
        execute: Callable[[], Awaitable[T]],
    ) -> ObserveRun[T]:
        """Start checks and an async tool independently; preserve its result and exception."""
        if not callable(execute):
            raise AuthRailError("An async tool function is required")
        call = None
        try:
            call = self.prepare(operation, arguments)
        except Exception:
            pass

        async def run_tool() -> T:
            return await execute()

        async def missing() -> tuple[Decision | None, AuthRailError | None]:
            return None, AuthRailError("Invalid advisory action context")

        check = asyncio.create_task(self._check(call, "tool_call") if call else missing())
        result_task = asyncio.create_task(run_tool())

        async def observe_result() -> Observation:
            result_bytes: bytes | None = None
            result_error: AuthRailError | None = None
            try:
                value = await asyncio.shield(result_task)
                if type(value) is not dict:
                    raise AuthRailError("Tool result must be a bounded JSON object")
                result_bytes = snapshot(value, MAX_VALUE)
            except asyncio.CancelledError:
                if not result_task.cancelled():
                    raise
                result_error = AuthRailError("Tool result unavailable after cancellation")
            except Exception:
                result_error = AuthRailError("Tool result unavailable or not a bounded JSON object")
            decision, error = await check
            if call is None:
                return Observation(None, error, None, error)
            if result_bytes is None:
                return Observation(decision, error, None, result_error)
            result_decision, result_error = await self._check(
                call, "tool_result", parse_object(result_bytes)
            )
            return Observation(decision, error, result_decision, result_error)

        observation = asyncio.create_task(observe_result())
        self._pending.add(observation)
        observation.add_done_callback(self._pending.discard)
        return ObserveRun(result_task, observation, call)
