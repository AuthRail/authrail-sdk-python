"""Prevent effects before retained permission and prevent recovery from executing twice.

These scripted transport tests exercise adapter behavior, not tenant E2E acceptance.
"""

import asyncio
import base64
import json
import unittest
from datetime import UTC, datetime, timedelta

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_observe import LegacySidecarTransport

from authrail import (
    ApprovalContinuation,
    AsyncEnforceClient,
    EnforceBlockedError,
    EnforceOutcomeUnknownError,
    ExecutionContext,
    Operation,
)

ORG = "00000000-0000-4000-8000-000000000001"
DEPLOYMENT = "00000000-0000-4000-8000-000000000002"
VERSION = "00000000-0000-4000-8000-000000000008"
ACTION = "00000000-0000-4000-8000-000000000010"
APPROVAL = "00000000-0000-4000-8000-000000000011"
PERMIT = "00000000-0000-4000-8000-000000000012"
RECEIPT = "00000000-0000-4000-8000-000000000013"
KEY = Ed25519PrivateKey.from_private_bytes(bytes(32))
BUNDLE = "00000000-0000-4000-8000-000000000030"


def operation():
    return Operation(
        version_id=VERSION,
        action_key="invoice-payment-001",
        principal_id="staff_123",
        session_id="task_123",
        principal_source="application_session",
        resource_source="application_lookup",
        resource_id="invoice_123",
        review_summary={"title": "Pay invoice", "fields": [{"label": "Amount", "value": "80"}]},
    )


class Transport:
    def __init__(self):
        self.requests = []
        self.call = {}
        self.result = {}
        self.start = {}
        self.fail_start = False
        self.fail_complete = False
        self.need_approval = False
        self.lost_claim = False
        self.claimed = False
        self.started = False
        self.expired = False

    def verify_proof(self, body, kind, fields):
        proof = body["proof"]
        statement = {"type": kind, "organisationId": ORG, "deploymentId": DEPLOYMENT}
        statement.update({key: body[key] for key in fields})
        statement.update({key: proof[key] for key in ["issuedAt", "expiresAt"]})
        signature = base64.urlsafe_b64decode(proof["signature"] + "==")
        KEY.public_key().verify(signature, json.dumps(statement, separators=(",", ":")).encode())

    def __call__(self, request):
        if request.method == "GET" and request.url.path == "/guard-requirements":
            return httpx.Response(
                200,
                json={
                    "formatVersion": 1,
                    "operationVersionId": VERSION,
                    "phase": request.url.params["phase"],
                    "bundleId": BUNDLE,
                    "sequence": 1,
                    "coverage": "evaluated",
                    "requirements": [],
                },
            )
        body = json.loads(request.content)
        self.requests.append((request.url.path, body))
        if request.url.path == "/evaluate":
            value = dict(
                requestId=body["requestId"],
                mode="enforce",
                enforced=False,
                coverage="evaluated",
                outcome="allow",
                recordingStatus="retained",
                reportReplayed=False,
                actionId=ACTION,
                bundleId=BUNDLE,
                sequence=1,
            )
            if self.need_approval:
                value.update(outcome="approval_required")
                if body["phase"] == "tool_call":
                    value["approvalRequestId"] = APPROVAL
            value.update(self.call if body["phase"] == "tool_call" else self.result)
            return httpx.Response(200, json=value)
        if request.url.path.startswith("/approval-permits/"):
            self.verify_proof(
                body,
                "authrail.approval.claim.v1",
                [
                    "approvalRequestId",
                    "actionId",
                    "inputSha256",
                    "keySha256",
                ],
            )
            recover = request.url.path.endswith("/recover")
            if (recover and not self.claimed) or (not recover and self.claimed):
                return httpx.Response(409)
            self.claimed = True
            if self.lost_claim and not recover:
                raise httpx.ReadError("private transport text", request=request)
            expiry = datetime.now(UTC) + timedelta(seconds=-10 if self.expired else 20)
            return httpx.Response(
                200 if recover else 201,
                json={
                    "permitId": PERMIT,
                    "actionId": ACTION,
                    "expiresAt": expiry.isoformat(),
                },
            )
        if request.url.path == "/execution-receipts":
            self.verify_proof(
                body,
                "authrail.execution.receipt.v1",
                [
                    "actionId",
                    "attemptId",
                    "permitId",
                    "event",
                    "inputSha256",
                    "providerIdempotencyKey",
                    "providerReference",
                    "keySha256",
                ],
            )
            assert request.headers["Idempotency-Key"] == (
                f"{body['actionId']}:{body['attemptId']}:{body['event']}"
            )
            if self.fail_start and body["event"] == "started":
                return httpx.Response(503)
            if self.fail_complete and body["event"] == "succeeded":
                return httpx.Response(503)
            state = {
                "started": "executing",
                "succeeded": "succeeded",
                "failed": "failed",
                "unknown": "outcome_unknown",
                "reconciled_succeeded": "succeeded",
                "reconciled_failed": "failed",
            }[body["event"]]
            replayed = self.started if body["event"] == "started" else False
            if body["event"] == "started":
                self.started = True
            value = dict(receiptId=RECEIPT, state=state, replayed=replayed)
            if body["event"] == "started":
                value.update(self.start)
            return httpx.Response(201, json=value)
        raise AssertionError(request.url.path)


def client(transport, deployment=DEPLOYMENT, **kwargs):
    return AsyncEnforceClient(
        sidecar_url="http://127.0.0.1:7078",
        adapter_token="c" * 32,
        organisation_id=ORG,
        deployment_id=deployment,
        executor_private_key=KEY,
        transport=LegacySidecarTransport(httpx.MockTransport(transport)),
        **kwargs,
    )


class EnforceTests(unittest.IsolatedAsyncioTestCase):
    async def test_slow_retention_waits_before_running_the_callback_once(self):
        transport = Transport()
        released = False
        callbacks = 0

        async def delayed(request):
            nonlocal released
            if request.url.path == "/evaluate":
                body = json.loads(request.content)
                if body["phase"] == "tool_call":
                    await asyncio.sleep(4.2)
                    released = True
            return transport(request)

        async def execute(arguments, context):
            nonlocal callbacks
            self.assertTrue(released)
            self.assertEqual(transport.requests[-1][1]["event"], "started")
            callbacks += 1
            return {"status": "done"}

        async with client(delayed) as sdk:
            result = await sdk.enforce(operation(), {"amount": 1}, execute)
        self.assertEqual(result.result, {"status": "done"})
        self.assertEqual(callbacks, 1)

    async def test_permission_and_fresh_start_gate_the_callback(self):
        failures = [
            {"outcome": "deny"},
            {"mode": "observe"},
            {"coverage": "uncovered"},
            {"recordingStatus": "queued"},
            {"recordingStatus": "unavailable"},
            {"reportReplayed": True},
            {"actionId": None},
        ]
        for failure in failures:
            transport = Transport()
            transport.call = failure
            async with client(transport) as sdk:

                async def forbidden(arguments, context):
                    self.fail("Unpermitted callback ran")

                with self.assertRaises(EnforceBlockedError) as caught:
                    await sdk.enforce(operation(), {"amount": 80}, forbidden)
                self.assertFalse(caught.exception.effect_may_have_occurred)
                self.assertEqual(len(transport.requests), 1)

    async def test_lost_or_replayed_start_cannot_run_the_callback(self):
        for start in [
            {"replayed": True},
            {"state": "succeeded"},
            {"receiptId": "invalid"},
            {"replayed": None},
            None,
        ]:
            transport = Transport()
            transport.start = start or {}
            transport.fail_start = start is None
            checkpoints = []
            async with client(transport) as sdk:

                async def forbidden(arguments, context):
                    self.fail("Unacknowledged start ran a callback")

                async def checkpoint(context, checkpoints=checkpoints):
                    checkpoints.append(context)

                with self.assertRaises(EnforceOutcomeUnknownError) as caught:
                    await sdk.enforce(
                        operation(), {"amount": 80}, forbidden, execution_checkpoint=checkpoint
                    )
            self.assertEqual(caught.exception.recovery, checkpoints[0])
            sent = transport.requests[-1][1]
            for field in [
                "actionId",
                "attemptId",
                "permitId",
                "inputSha256",
                "providerIdempotencyKey",
            ]:
                self.assertEqual(caught.exception.recovery.as_dict()[field], sent[field])

    async def test_checkpoint_persists_exact_recovery_before_start(self):
        transport = Transport()
        checkpoints = []
        async with client(transport) as sdk:

            async def checkpoint(context):
                self.assertFalse(transport.started)
                self.assertFalse(
                    any(path == "/execution-receipts" for path, _ in transport.requests)
                )
                checkpoints.append(ExecutionContext.from_dict(context.as_dict()))

            async def execute(arguments, context):
                self.assertEqual(checkpoints, [context])
                self.assertTrue(transport.started)
                return {"status": "paid"}

            result = await sdk.enforce(
                operation(), {"amount": 80}, execute, execution_checkpoint=checkpoint
            )
            # A later call on the same client must not inherit this request's save hook.
            with self.assertRaises(EnforceOutcomeUnknownError):
                await sdk.enforce(operation(), {"amount": 80}, execute)
        self.assertEqual(checkpoints, [result.execution])

    async def test_checkpoint_failure_or_cancellation_withholds_start(self):
        for failure in [RuntimeError("private storage failure"), asyncio.CancelledError()]:
            transport = Transport()
            async with client(transport) as sdk:

                async def checkpoint(context, failure=failure):
                    raise failure

                async def forbidden(arguments, context):
                    self.fail("Unpersisted request ran a callback")

                expected = (
                    asyncio.CancelledError
                    if isinstance(failure, asyncio.CancelledError)
                    else EnforceBlockedError
                )
                with self.assertRaises(expected):
                    await sdk.enforce(
                        operation(), {"amount": 80}, forbidden, execution_checkpoint=checkpoint
                    )
            self.assertFalse(transport.started)
            self.assertFalse(any(path == "/execution-receipts" for path, _ in transport.requests))

    async def test_cancellation_during_start_keeps_checkpoint_and_withholds_callback(self):
        transport = Transport()
        retained = asyncio.Event()
        checkpoints = []

        async def delayed(request):
            response = transport(request)
            if (
                request.url.path == "/execution-receipts"
                and json.loads(request.content)["event"] == "started"
            ):
                retained.set()
                await asyncio.wait_for(asyncio.Event().wait(), timeout=2)
            return response

        async with client(delayed) as sdk:

            async def checkpoint(context):
                checkpoints.append(context)

            async def forbidden(arguments, context):
                self.fail("Cancelled start ran a callback")

            task = asyncio.create_task(
                sdk.enforce(operation(), {"amount": 80}, forbidden, execution_checkpoint=checkpoint)
            )
            try:
                await asyncio.wait_for(retained.wait(), timeout=1)
                task.cancel()
                with self.assertRaises(EnforceOutcomeUnknownError) as caught:
                    await task
            finally:
                if not task.done():
                    task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, EnforceOutcomeUnknownError):
                    pass
        self.assertEqual(caught.exception.recovery, checkpoints[0])

    async def test_execution_uses_checked_arguments_and_preserves_receipt_identity(self):
        transport = Transport()
        received = []
        arguments = {"amount": 80}
        async with client(transport) as sdk:

            async def execute(checked, context):
                received.append(context)
                arguments["amount"] = 900
                checked["amount"] = 500
                self.assertEqual(transport.requests[-1][1]["event"], "started")
                return {"status": "paid"}

            result = await sdk.enforce(operation(), arguments, execute)
        self.assertEqual(result.result, {"status": "paid"})
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0].provider_idempotency_key, "ar-" + ACTION)
        result_body = transport.requests[-1][1]
        self.assertEqual(result_body["arguments"], {"amount": 80})
        self.assertNotIn("reviewSummary", result_body)
        receipts = [body for path, body in transport.requests if path == "/execution-receipts"]
        self.assertEqual([body["event"] for body in receipts], ["started", "succeeded"])
        self.assertEqual(receipts[0]["inputSha256"], receipts[1]["inputSha256"])
        restored = ExecutionContext.from_dict(result.execution.as_dict())
        self.assertEqual(restored, result.execution)

    async def test_result_denial_or_different_action_withholds_after_effect(self):
        for mismatch in [{"outcome": "deny"}, {"actionId": VERSION}, {"recordingStatus": "queued"}]:
            transport = Transport()
            transport.result = mismatch
            effects = []
            async with client(transport) as sdk:

                async def execute(arguments, context, recorded=effects):
                    recorded.append("paid")
                    return {"secret": "do not release"}

                with self.assertRaises(EnforceBlockedError) as caught:
                    await sdk.enforce(operation(), {"amount": 80}, execute)
                self.assertEqual(caught.exception.phase, "tool_result")
                self.assertTrue(caught.exception.effect_may_have_occurred)
                self.assertFalse(hasattr(caught.exception, "result"))
            self.assertEqual(effects, ["paid"])

    async def test_tool_exception_reports_unknown_never_failed_and_does_not_leak(self):
        transport = Transport()
        async with client(transport) as sdk:

            async def execute(arguments, context):
                raise RuntimeError("private provider response")

            with self.assertRaises(EnforceOutcomeUnknownError) as caught:
                await sdk.enforce(operation(), {"amount": 80}, execute)
            self.assertNotIn("private", str(caught.exception))
            self.assertEqual(caught.exception.recovery.action_id, ACTION)
        self.assertEqual(
            [body["event"] for path, body in transport.requests if path == "/execution-receipts"],
            ["started", "unknown"],
        )

    async def test_completion_failure_keeps_recovery_and_reconcile_never_reexecutes(self):
        transport = Transport()
        transport.fail_complete = True
        effects = []
        async with client(transport) as sdk:

            async def execute(arguments, context):
                effects.append(context.provider_idempotency_key)
                return {"status": "paid"}

            with self.assertRaises(EnforceOutcomeUnknownError) as caught:
                await sdk.enforce(operation(), {"amount": 80}, execute)
            recovery = ExecutionContext.from_dict(caught.exception.recovery.as_dict())
            receipt = await sdk.reconcile(recovery, "succeeded", "provider_payment_123")
            self.assertEqual(receipt.state, "succeeded")
        self.assertEqual(effects, ["ar-" + ACTION])
        self.assertEqual(transport.requests[-1][1]["event"], "reconciled_succeeded")

    async def pending(self, transport):
        transport.need_approval = True
        async with client(transport) as sdk:

            async def forbidden(arguments, context):
                self.fail("Approval-required callback ran before review")

            with self.assertRaises(EnforceBlockedError) as caught:
                await sdk.enforce(operation(), {"amount": 80}, forbidden)
            self.assertIsNotNone(caught.exception.approval_continuation)
            saved = json.loads(json.dumps(caught.exception.approval_continuation.as_dict()))
        return ApprovalContinuation.from_dict(saved)

    async def test_saved_approval_restores_original_call_and_one_use_start(self):
        transport = Transport()
        continuation = await self.pending(transport)
        effects = []
        checkpoints = []
        async with client(transport) as sdk:

            async def checkpoint(context):
                checkpoints.append(context)

            async def execute(arguments, context):
                self.assertEqual(checkpoints[-1], context)
                effects.append((arguments, context))
                return {"status": "paid"}

            result = await sdk.resume_approval_from(
                continuation, execute, execution_checkpoint=checkpoint
            )
            self.assertEqual(result.execution.permit_id, PERMIT)
            self.assertEqual(result.execution.attempt_id, continuation.call.request_id)
            self.assertEqual(result.result_decision.outcome, "approval_required")
            with self.assertRaises(EnforceOutcomeUnknownError) as caught:
                await sdk.recover_approval_from(
                    continuation, execute, execution_checkpoint=checkpoint
                )
            self.assertEqual(caught.exception.recovery, result.execution)
            self.assertEqual(checkpoints, [result.execution, result.execution])
        self.assertEqual(len(effects), 1)
        self.assertEqual(effects[0][0], {"amount": 80})

    async def test_same_process_resume_runs_only_the_original_callback_once(self):
        transport = Transport()
        transport.need_approval = True
        effects = []
        checkpoints = []
        async with client(transport) as sdk:

            async def checkpoint(context):
                self.assertFalse(transport.started)
                checkpoints.append(context)

            async def execute(arguments, context):
                self.assertEqual(checkpoints, [context])
                effects.append(arguments["amount"])
                return {"status": "paid"}

            with self.assertRaises(EnforceBlockedError) as caught:
                await sdk.enforce(operation(), {"amount": 80}, execute)
            blocked = caught.exception
            self.assertEqual(effects, [])
            await sdk.resume_approval(blocked, execution_checkpoint=checkpoint)
            with self.assertRaises(EnforceBlockedError):
                await sdk.resume_approval(blocked)
        self.assertEqual(effects, [80])

    async def test_lost_claim_response_uses_recovery_route_without_second_claim(self):
        transport = Transport()
        continuation = await self.pending(transport)
        transport.lost_claim = True
        effects = []
        checkpoints = []
        async with client(transport) as sdk:

            async def checkpoint(context):
                self.assertFalse(transport.started)
                checkpoints.append(context)

            async def execute(arguments, context):
                self.assertEqual(checkpoints, [context])
                effects.append("paid")
                return {"status": "paid"}

            with self.assertRaises(EnforceBlockedError):
                await sdk.resume_approval_from(continuation, execute)
            self.assertEqual(effects, [])
            result = await sdk.recover_approval_from(
                continuation, execute, execution_checkpoint=checkpoint
            )
            self.assertEqual(checkpoints, [result.execution])
        paths = [path for path, body in transport.requests]
        self.assertEqual(paths.count("/approval-permits/claim"), 1)
        self.assertEqual(paths.count("/approval-permits/recover"), 1)
        self.assertEqual(effects, ["paid"])

    async def test_expired_and_other_deployment_continuations_cannot_execute(self):
        transport = Transport()
        continuation = await self.pending(transport)

        async def forbidden(arguments, context):
            self.fail("Invalid approval ran a callback")

        count = len(transport.requests)
        async with client(transport, deployment=VERSION) as sdk:
            with self.assertRaises(EnforceBlockedError):
                await sdk.resume_approval_from(continuation, forbidden)
        self.assertEqual(len(transport.requests), count)
        transport.expired = True
        async with client(transport) as sdk:
            with self.assertRaises(EnforceBlockedError):
                await sdk.resume_approval_from(continuation, forbidden)
        self.assertFalse(transport.started)

    async def test_cancellation_after_callback_start_becomes_unknown(self):
        transport = Transport()
        entered = asyncio.Event()
        async with client(transport) as sdk:

            async def execute(arguments, context):
                entered.set()
                await asyncio.Event().wait()

            task = asyncio.create_task(sdk.enforce(operation(), {"amount": 80}, execute))
            await entered.wait()
            task.cancel()
            with self.assertRaises(EnforceOutcomeUnknownError):
                await task
        self.assertEqual(transport.requests[-1][1]["event"], "unknown")
