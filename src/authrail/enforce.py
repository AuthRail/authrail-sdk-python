"""Enforce permission, one-use approval and execution recording at a protected callback."""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
import weakref
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from types import TracebackType
from typing import Literal, cast
from urllib.parse import urlencode

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._protocol import MAX_VALUE, encode_input, parse_object, snapshot
from .guard import GuardHandler, GuardProcessing, process_guard, registered_handlers
from .observe import _REF, _UUID, AsyncObserveClient, _matches
from .types import AuthRailError, Decision, JSONObject, JSONValue, Operation, Phase, PreparedCall

ExecutionEvent = Literal[
    "started", "succeeded", "failed", "unknown", "reconciled_succeeded", "reconciled_failed"
]


@dataclass(frozen=True)
class ExecutionContext:
    """Persist with the provider request so uncertain effects can be reconciled by the same key."""

    action_id: str
    attempt_id: str
    permit_id: str | None
    input_sha256: str
    provider_idempotency_key: str
    traceparent: str | None = None

    def as_dict(self) -> JSONObject:
        return {
            "actionId": self.action_id,
            "attemptId": self.attempt_id,
            "permitId": self.permit_id,
            "inputSha256": self.input_sha256,
            "providerIdempotencyKey": self.provider_idempotency_key,
            "traceparent": self.traceparent,
        }

    @classmethod
    def from_dict(cls, value: JSONObject) -> ExecutionContext:
        """Restore only from the application's protected recovery storage."""
        data = parse_object(snapshot(value))
        if set(data) != {
            "actionId",
            "attemptId",
            "permitId",
            "inputSha256",
            "providerIdempotencyKey",
            "traceparent",
        }:
            raise AuthRailError("Invalid execution recovery context")
        context = cls(
            cast(str, data["actionId"]),
            cast(str, data["attemptId"]),
            cast(str | None, data["permitId"]),
            cast(str, data["inputSha256"]),
            cast(str, data["providerIdempotencyKey"]),
            cast(str | None, data["traceparent"]),
        )
        _validate_execution(context)
        return context


@dataclass(frozen=True)
class ApprovalContinuation:
    """Exact waiting call and decision; encrypt and tenant-scope this application-owned state."""

    organisation_id: str
    deployment_id: str
    call: PreparedCall = field(repr=False)
    decision: Decision = field(repr=False)

    def as_dict(self) -> JSONObject:
        return {
            "formatVersion": 1,
            "organisationId": self.organisation_id,
            "deploymentId": self.deployment_id,
            "actionKey": self.call.action_key,
            "traceparent": self.call.traceparent,
            "call": self.call.as_dict(),
            "decision": self.decision.as_dict(),
        }

    @classmethod
    def from_dict(cls, value: JSONObject) -> ApprovalContinuation:
        """Restore saved state; permission is still verified when the SDK claims a permit."""
        data = parse_object(snapshot(value, 256 * 1024))
        if (
            set(data)
            != {
                "formatVersion",
                "organisationId",
                "deploymentId",
                "actionKey",
                "traceparent",
                "call",
                "decision",
            }
            or type(data["formatVersion"]) is not int
            or data["formatVersion"] != 1
            or not _matches(_UUID, data["organisationId"])
            or not _matches(_UUID, data["deploymentId"])
            or not _matches(_REF, data["actionKey"])
            or type(data["call"]) is not dict
            or type(data["decision"]) is not dict
        ):
            raise AuthRailError("Invalid saved approval continuation")
        call_data = data["call"]
        decision_data = data["decision"]
        request_id = call_data.get("requestId")
        if not _matches(_UUID, request_id) or decision_data.get("requestId") != request_id:
            raise AuthRailError("Approval continuation request mismatch")
        call = PreparedCall(
            cast(str, request_id),
            cast(str, data["actionKey"]),
            cast(str | None, data["traceparent"]),
            snapshot(call_data),
        )
        decision = Decision(
            call.request_id,
            cast(str, decision_data.get("outcome")),
            cast(str, decision_data.get("coverage")),
            cast(str | None, decision_data.get("recordingStatus")),
            cast(str | None, decision_data.get("actionId")),
            snapshot(decision_data),
        )
        return cls(
            cast(str, data["organisationId"]), cast(str, data["deploymentId"]), call, decision
        )


class EnforceBlockedError(AuthRailError):
    """No permission at this phase; a result-phase block cannot undo an earlier effect."""

    def __init__(
        self,
        phase: Phase,
        effect_may_have_occurred: bool,
        decision: Decision | None = None,
        approval_continuation: ApprovalContinuation | None = None,
    ) -> None:
        super().__init__(f"AuthRail blocked the {phase}")
        self.phase = phase
        self.effect_may_have_occurred = effect_may_have_occurred
        self.decision = decision
        self.approval_continuation = approval_continuation


class EnforceOutcomeUnknownError(AuthRailError):
    """The callback or its completion acknowledgement failed; reconcile before retrying."""

    effect_may_have_occurred = True

    def __init__(self, recovery: ExecutionContext, decision: Decision) -> None:
        super().__init__("Protected operation outcome is unknown; reconcile before retrying")
        self.recovery = recovery
        self.call_decision = decision


@dataclass(frozen=True)
class ExecutionReceipt:
    """Acknowledged execution state; it remains the application's assertion about its effect."""

    receipt_id: str
    state: str
    replayed: bool


@dataclass(frozen=True)
class EnforceResult:
    """A released result with separate call/result decisions and recovery identity."""

    result: JSONObject = field(repr=False)
    call_decision: Decision
    result_decision: Decision
    execution: ExecutionContext


Executor = Callable[[JSONObject, ExecutionContext], Awaitable[JSONObject]]


def _permitted(decision: Decision) -> bool:
    value = decision.as_dict()
    return (
        value.get("mode") == "enforce"
        and value.get("enforced") is False
        and decision.coverage == "evaluated"
        and decision.outcome == "allow"
        and decision.recording_status == "retained"
        and value.get("reportReplayed") is False
        and _matches(_UUID, decision.action_id)
    )


def _approval(decision: Decision) -> bool:
    value = decision.as_dict()
    return (
        value.get("mode") == "enforce"
        and value.get("enforced") is False
        and decision.coverage == "evaluated"
        and decision.outcome == "approval_required"
        and decision.recording_status == "retained"
        and value.get("reportReplayed") is False
        and _matches(_UUID, decision.action_id)
        and _matches(_UUID, value.get("approvalRequestId"))
    )


def _validate_execution(context: ExecutionContext) -> None:
    if (
        not _matches(_UUID, context.action_id)
        or not _matches(_UUID, context.attempt_id)
        or (context.permit_id is not None and not _matches(_UUID, context.permit_id))
        or type(context.input_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", context.input_sha256) is None
        or not _matches(_REF, context.provider_idempotency_key)
    ):
        raise AuthRailError("Invalid execution recovery identity")


class AsyncEnforceClient:
    """Run only after retained permission and a fresh execution-start acknowledgement."""

    def __init__(
        self,
        *,
        sidecar_url: str,
        adapter_token: str,
        organisation_id: str,
        deployment_id: str,
        executor_private_key: bytes | Ed25519PrivateKey,
        transport: httpx.AsyncBaseTransport | None = None,
        guard_handlers: Sequence[GuardHandler] | None = None,
    ) -> None:
        self._sidecar = AsyncObserveClient(
            sidecar_url=sidecar_url,
            adapter_token=adapter_token,
            organisation_id=organisation_id,
            deployment_id=deployment_id,
            executor_private_key=executor_private_key,
            transport=transport,
        )
        self._organisation_id = organisation_id
        self._deployment_id = deployment_id
        self._guard_processing = guard_handlers is not None
        self._handlers = registered_handlers(guard_handlers)
        self._pending: weakref.WeakKeyDictionary[
            EnforceBlockedError, tuple[ApprovalContinuation, Executor]
        ] = weakref.WeakKeyDictionary()

    async def __aenter__(self) -> AsyncEnforceClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the application's local connections after in-flight workflows finish."""
        await self._sidecar.aclose()

    async def enforce(
        self,
        operation: Operation,
        arguments: JSONObject,
        execute: Executor,
    ) -> EnforceResult:
        """Check the call, retain its start, invoke once, then check the returned result."""
        if not callable(execute):
            raise AuthRailError("A protected async function is required")
        try:
            call = self._sidecar.prepare(operation, arguments)
            guard = None
            if self._guard_processing:
                guard = await self._process_guard(
                    call, "tool_call", cast(JSONObject, call.as_dict()["arguments"])
                )
                data = call.as_dict()
                data["arguments"] = guard.output
                data["guardEvidence"] = guard.evidence
                call = PreparedCall(
                    call.request_id, call.action_key, call.traceparent, snapshot(data)
                )
            decision = await self._sidecar._evaluate(call, "tool_call", "enforce")
            self._check_guard_bundle(guard, decision)
        except Exception:
            raise EnforceBlockedError("tool_call", False) from None
        if not _permitted(decision):
            continuation = (
                ApprovalContinuation(self._organisation_id, self._deployment_id, call, decision)
                if _approval(decision)
                else None
            )
            blocked = EnforceBlockedError("tool_call", False, decision, continuation)
            if continuation is not None:
                self._pending[blocked] = (continuation, execute)
            raise blocked
        return await self._execute(call, decision, execute, None)

    async def _process_guard(
        self,
        call: PreparedCall,
        phase: Phase,
        value: JSONObject,
    ) -> GuardProcessing:
        operation_id = cast(str, call.as_dict()["operationVersionId"])
        query = urlencode({"operationVersionId": operation_id, "phase": phase})
        plan = await self._sidecar._request_json(
            "/guard-requirements?" + query,
            None,
            status=200,
            deadline_seconds=4.0,
            traceparent=call.traceparent,
            method="GET",
        )
        return await process_guard(plan, operation_id, phase, value, self._handlers)

    @staticmethod
    def _check_guard_bundle(guard: GuardProcessing | None, decision: Decision) -> None:
        if guard is not None and (
            decision.as_dict().get("bundleId") != guard.bundle_id
            or decision.as_dict().get("sequence") != guard.sequence
        ):
            raise AuthRailError("Guard configuration changed before evaluation")

    async def resume_approval(self, blocked: EnforceBlockedError) -> EnforceResult:
        """Resume the original same-process callback after an exact one-use permit claim."""
        pending = self._pending.pop(blocked, None)
        if pending is None:
            raise EnforceBlockedError("tool_call", False, blocked.decision)
        return await self.resume_approval_from(*pending)

    def _restore(self, continuation: ApprovalContinuation) -> tuple[PreparedCall, Decision]:
        if (
            continuation.organisation_id != self._organisation_id
            or continuation.deployment_id != self._deployment_id
            or not _approval(continuation.decision)
        ):
            raise AuthRailError("Approval continuation does not belong to this deployment")
        data = continuation.call.as_dict()
        if set(data) - {
            "requestId",
            "operationVersionId",
            "arguments",
            "attribution",
            "factResolutions",
            "trajectory",
            "reviewSummary",
            "guardEvidence",
        }:
            raise AuthRailError("Invalid saved approval call")
        attribution = data["attribution"]
        if type(attribution) is not dict or set(attribution) != {
            "principalId",
            "sessionId",
            "resourceId",
            "principalSource",
            "resourceSource",
        }:
            raise AuthRailError("Invalid saved caller identity")
        if (
            data.get("requestId") != continuation.call.request_id
            or (continuation.decision.request_id != continuation.call.request_id)
            or not _matches(_UUID, continuation.call.request_id)
        ):
            raise AuthRailError("Invalid saved request identity")
        operation = Operation(
            version_id=cast(str, data["operationVersionId"]),
            action_key=continuation.call.action_key,
            principal_id=cast(str, attribution["principalId"]),
            session_id=cast(str, attribution["sessionId"]),
            resource_id=cast(str | None, attribution["resourceId"]),
            principal_source=cast(
                Literal["application_session", "service_identity"], attribution["principalSource"]
            ),
            resource_source=cast(
                Literal["application_lookup", "not_applicable"], attribution["resourceSource"]
            ),
            fact_resolutions=cast(list[JSONObject], data.get("factResolutions", [])),
            trajectory=cast(JSONObject | None, data.get("trajectory")),
            review_summary=cast(JSONObject | None, data.get("reviewSummary")),
            traceparent=continuation.call.traceparent,
        )
        self._sidecar.prepare(operation, cast(JSONObject, data["arguments"]))
        return continuation.call, continuation.decision

    async def resume_approval_from(
        self,
        continuation: ApprovalContinuation,
        execute: Executor,
    ) -> EnforceResult:
        """Resume a protected persisted call; this does not restore or schedule an agent session."""
        return await self._resume(continuation, execute, recover=False)

    async def recover_approval_from(
        self,
        continuation: ApprovalContinuation,
        execute: Executor,
    ) -> EnforceResult:
        """Recover an existing unstarted permit after a lost claim response; never mint another."""
        return await self._resume(continuation, execute, recover=True)

    async def _resume(
        self,
        continuation: ApprovalContinuation,
        execute: Executor,
        *,
        recover: bool,
    ) -> EnforceResult:
        if not callable(execute):
            raise AuthRailError("A protected async function is required")
        try:
            call, decision = self._restore(continuation)
            fields: JSONObject = {
                "approvalRequestId": decision.as_dict()["approvalRequestId"],
                "actionId": decision.action_id,
                "inputSha256": hashlib.sha256(
                    encode_input(call.as_dict(), "tool_call").encode()
                ).hexdigest(),
                "keySha256": self._sidecar._key_sha256(),
            }
            body: JSONObject = {
                **fields,
                "proof": self._sidecar._sign_statement("authrail.approval.claim.v1", fields),
            }
            permit = await self._sidecar._request_json(
                "/approval-permits/recover" if recover else "/approval-permits/claim",
                body,
                status=200 if recover else 201,
                deadline_seconds=3.0,
                traceparent=call.traceparent,
            )
            expiry = permit.get("expiresAt")
            if (
                not _matches(_UUID, permit.get("permitId"))
                or permit.get("actionId") != decision.action_id
                or type(expiry) is not str
            ):
                raise AuthRailError("Invalid approval permit")
            deadline = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
            if deadline.tzinfo is None or deadline.timestamp() <= time.time():
                raise AuthRailError("Approval permit expired")
        except Exception:
            raise EnforceBlockedError("tool_call", False) from None
        return await self._execute(call, decision, execute, cast(str, permit["permitId"]))

    async def report_execution(
        self,
        context: ExecutionContext,
        event: ExecutionEvent,
        provider_reference: str | None = None,
    ) -> ExecutionReceipt:
        """Record explicit executor knowledge; do not report failure solely from an exception."""
        _validate_execution(context)
        if (
            event
            not in (
                "started",
                "succeeded",
                "failed",
                "unknown",
                "reconciled_succeeded",
                "reconciled_failed",
            )
            or (provider_reference is not None and not _matches(_REF, provider_reference))
            or (event.startswith("reconciled_") and provider_reference is None)
        ):
            raise AuthRailError("Invalid execution report")
        fields: JSONObject = {
            "actionId": context.action_id,
            "attemptId": context.attempt_id,
            "permitId": context.permit_id,
            "event": event,
            "inputSha256": context.input_sha256,
            "providerIdempotencyKey": context.provider_idempotency_key,
            "providerReference": provider_reference,
            "keySha256": self._sidecar._key_sha256(),
        }
        value = await self._sidecar._request_json(
            "/execution-receipts",
            {
                **fields,
                "proof": self._sidecar._sign_statement("authrail.execution.receipt.v1", fields),
            },
            status=201,
            deadline_seconds=3.0,
            idempotency_key=f"{context.action_id}:{context.attempt_id}:{event}",
            traceparent=context.traceparent,
        )
        if (
            not _matches(_UUID, value.get("receiptId"))
            or value.get("state") not in ("executing", "succeeded", "failed", "outcome_unknown")
            or type(value.get("replayed")) is not bool
        ):
            raise AuthRailError("Invalid execution acknowledgement")
        return ExecutionReceipt(
            cast(str, value["receiptId"]), cast(str, value["state"]), cast(bool, value["replayed"])
        )

    async def reconcile(
        self,
        context: ExecutionContext,
        outcome: Literal["succeeded", "failed"],
        provider_reference: str,
    ) -> ExecutionReceipt:
        """Call only after querying the provider with the original business idempotency key."""
        if outcome not in ("succeeded", "failed"):
            raise AuthRailError("Reconciliation needs a known provider outcome")
        event: ExecutionEvent = (
            "reconciled_succeeded" if outcome == "succeeded" else "reconciled_failed"
        )
        return await self.report_execution(context, event, provider_reference)

    async def _execute(
        self,
        call: PreparedCall,
        decision: Decision,
        execute: Executor,
        permit_id: str | None,
    ) -> EnforceResult:
        if not _matches(_UUID, decision.action_id):
            raise EnforceBlockedError("tool_call", False, decision)
        context = ExecutionContext(
            cast(str, decision.action_id),
            call.request_id,
            permit_id,
            hashlib.sha256(encode_input(call.as_dict(), "tool_call").encode()).hexdigest(),
            f"ar-{decision.action_id}",
            call.traceparent,
        )
        try:
            started = await self.report_execution(context, "started")
            if started.state != "executing" or started.replayed:
                raise AuthRailError("Execution start was not fresh")
        except Exception:
            # An unknown start acknowledgement is never permission to call the provider.
            raise EnforceBlockedError("tool_call", False, decision) from None
        try:
            result = await execute(cast(JSONObject, call.as_dict()["arguments"]), context)
        except (Exception, asyncio.CancelledError):
            try:
                await self.report_execution(context, "unknown")
            except (Exception, asyncio.CancelledError):
                pass
            raise EnforceOutcomeUnknownError(context, decision) from None
        result_bytes = None
        try:
            if type(result) is dict:
                result_bytes = snapshot(result, MAX_VALUE)
        except Exception:
            pass
        try:
            completed = await self.report_execution(context, "succeeded")
            if completed.state != "succeeded":
                raise AuthRailError("Completion not retained as succeeded")
        except (Exception, asyncio.CancelledError):
            raise EnforceOutcomeUnknownError(context, decision) from None
        if result_bytes is None:
            raise EnforceBlockedError("tool_result", True)
        result = parse_object(result_bytes)
        try:
            result_call = call
            guard = None
            if self._guard_processing:
                guard = await self._process_guard(call, "tool_result", result)
                data = call.as_dict()
                evidence = cast(list[JSONValue], data.get("guardEvidence", [])) + guard.evidence
                if len(evidence) > 128:
                    raise AuthRailError("Too much Guard processing evidence")
                data["guardEvidence"] = evidence
                result_call = PreparedCall(
                    call.request_id, call.action_key, call.traceparent, snapshot(data)
                )
                result = guard.output
            checked = await self._sidecar._evaluate(result_call, "tool_result", "enforce", result)
            self._check_guard_bundle(guard, checked)
        except (Exception, asyncio.CancelledError):
            raise EnforceBlockedError("tool_result", True) from None
        checked_value = checked.as_dict()
        allowed = _permitted(checked) or (
            permit_id is not None
            and _approval(decision)
            and checked_value.get("mode") == "enforce"
            and checked_value.get("enforced") is False
            and checked.outcome == "approval_required"
            and checked.coverage == "evaluated"
            and checked.recording_status == "retained"
            and checked_value.get("reportReplayed") is False
        )
        if not allowed or checked.action_id != decision.action_id:
            raise EnforceBlockedError("tool_result", True, checked)
        return EnforceResult(result, decision, checked, context)
