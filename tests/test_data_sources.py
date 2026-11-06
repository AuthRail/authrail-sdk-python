"""Verify trusted lookup binding, exact receipt hashes and bounded automatic reads."""

import asyncio
import hashlib
import json
import time
import unittest
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import httpx
from test_enforce import BUNDLE, VERSION, Transport, client, operation

from authrail import AuthRailError, DataSourceBinding, EnforceBlockedError
from authrail._data import registered_data_sources, resolve_data
from authrail._protocol import encode_input
from authrail.facts import CustomerReadResult

SOURCE = "77777777-7777-4777-8777-777777777777"


def contract():
    return {
        "formatVersion": 4,
        "kind": "sdk",
        "sourceIdentity": "billing.read",
        "accountBoundary": "account_1",
        "lookup": "invoice.read",
        "queryField": {"root": "arguments", "path": ["invoiceId"]},
        "factKey": "balance",
        "resultPath": ["balance"],
        "valueType": "number",
        "maxAgeSeconds": 60,
        "timeoutMs": 100,
        "failure": "unavailable",
    }


class DataTransport(Transport):
    def __init__(self):
        super().__init__()
        self.original_hash = None
        self.facts = []
        self.missing_plan = False

    def __call__(self, request):
        if request.url.path == "/data-requirements":
            if self.missing_plan:
                return httpx.Response(404)
            return httpx.Response(
                200,
                json={
                    "formatVersion": 1,
                    "operationVersionId": VERSION,
                    "phase": request.url.params["phase"],
                    "bundleId": BUNDLE,
                    "sequence": 1,
                    "coverage": "evaluated",
                    "requirements": [{"sourceVersionId": SOURCE, "contract": contract()}],
                },
            )
        if request.url.path == "/evaluate":
            body = json.loads(request.content)
            self.facts.append(body["factResolutions"])
            if body["phase"] == "tool_call":
                self.original_hash = hashlib.sha256(
                    encode_input(body, "tool_call").encode()
                ).hexdigest()
        if request.url.path in ("/execution-receipts", "/approval-permits/claim"):
            body = json.loads(request.content)
            assert body["inputSha256"] == self.original_hash, "Receipt omitted original facts"
        return super().__call__(request)


class DataSourceTests(unittest.IsolatedAsyncioTestCase):
    def binding(self, *, wrong_resource=False, wrong_account=False, hang=False):
        self.reads = 0

        def resolve(identity):
            self.assertEqual(identity.resource_id, "invoice_123")
            self.assertFalse(hasattr(identity, "arguments"))
            with self.assertRaises(FrozenInstanceError):
                identity.resource_id = "other"
            return "other" if wrong_resource else "invoice_123"

        async def read(key):
            self.reads += 1
            if hang:
                await asyncio.sleep(10)
            return CustomerReadResult(
                source_identity="billing.read",
                account_boundary="account_1",
                lookup="invoice.read",
                lookup_key=key,
                observed_at=datetime.now(UTC).isoformat(),
                value={"balance": 80},
            )

        return DataSourceBinding(
            source_version_id=SOURCE,
            kind="sdk",
            source_identity="billing.read",
            account_boundary="other" if wrong_account else "account_1",
            lookup="invoice.read",
            resolve_resource=resolve,
            read=read,
        )

    async def test_exact_facts_survive_receipts_and_approval_resume(self):
        for needs_approval in (False, True):
            transport = DataTransport()
            transport.need_approval = needs_approval
            binding = self.binding()
            async with client(transport, data_sources=[binding]) as sdk:

                async def execute(arguments, context, transport=transport):
                    self.assertEqual(arguments, {"invoiceId": "invoice_123"})
                    self.assertEqual(context.input_sha256, transport.original_hash)
                    return {"done": True}

                if needs_approval:
                    with self.assertRaises(EnforceBlockedError) as blocked:
                        await sdk.enforce(operation(), {"invoiceId": "invoice_123"}, execute)
                    saved = blocked.exception.approval_continuation
                    self.assertIsNotNone(saved)
                    self.assertEqual(saved.call.as_dict()["factResolutions"][0]["status"], "ok")
                    result = await sdk.resume_approval_from(saved, execute)
                else:
                    result = await sdk.enforce(operation(), {"invoiceId": "invoice_123"}, execute)
                self.assertEqual(result.result, {"done": True})
                self.assertEqual(self.reads, 2)
                self.assertEqual([facts[0]["status"] for facts in transport.facts], ["ok", "ok"])

    async def test_mismatched_resource_or_account_never_calls_reader(self):
        for resource in (False, True):
            transport = DataTransport()
            binding = self.binding(wrong_resource=resource, wrong_account=not resource)
            async with client(transport, data_sources=[binding]) as sdk:
                call = sdk._sidecar.prepare(operation(), {"invoiceId": "invoice_123"})
                await sdk._sidecar._evaluate(call, "tool_call", "enforce")
                self.assertEqual(self.reads, 0)
                self.assertEqual(transport.facts[0][0]["status"], "untrusted")

    async def test_missing_binding_deadline_duplicate_conflict_and_unavailable_plan(self):
        transport = DataTransport()
        async with client(transport, data_sources=[]) as sdk:
            call = sdk._sidecar.prepare(operation(), {"invoiceId": "invoice_123"})
            await sdk._sidecar._evaluate(call, "tool_call", "enforce")
            self.assertEqual(transport.facts[0][0]["status"], "unavailable")
        transport = DataTransport()
        binding = self.binding(hang=True)
        async with client(transport, data_sources=[binding]) as sdk:
            call = sdk._sidecar.prepare(operation(), {"invoiceId": "invoice_123"})
            start = time.monotonic()
            await sdk._sidecar._evaluate(call, "tool_call", "enforce")
            self.assertLess(time.monotonic() - start, 1)
            self.assertEqual(transport.facts[0][0]["status"], "unavailable")
        with self.assertRaises(AuthRailError):
            client(DataTransport(), data_sources=[binding, binding])
        transport = DataTransport()
        transport.missing_plan = True
        async with client(transport, data_sources=[binding]) as sdk:
            with self.assertRaises(EnforceBlockedError):
                await sdk.enforce(operation(), {"invoiceId": "invoice_123"}, lambda *_: None)
        transport = DataTransport()
        transport.call = {"sequence": 2}
        async with client(transport, data_sources=[self.binding()]) as sdk:
            with self.assertRaises(EnforceBlockedError):
                await sdk.enforce(operation(), {"invoiceId": "invoice_123"}, lambda *_: None)


    async def test_completed_read_snapshots_values_before_waiting_for_other_sources(self):
        second_source = "88888888-8888-4888-8888-888888888888"
        shared = {"balance": 80}

        class TwoSources(DataTransport):
            def __call__(self, request):
                response = super().__call__(request)
                if request.url.path == "/data-requirements":
                    plan = response.json()
                    plan["requirements"].append(
                        {"sourceVersionId": second_source, "contract": contract()}
                    )
                    return httpx.Response(200, json=plan)
                return response

        async def first_read(key):
            return CustomerReadResult(
                source_identity="billing.read", account_boundary="account_1",
                lookup="invoice.read", lookup_key=key,
                observed_at=datetime.now(UTC).isoformat(), value=shared,
            )

        async def second_read(key):
            await asyncio.sleep(0.02)
            shared["balance"] = 999
            return CustomerReadResult(
                source_identity="billing.read", account_boundary="account_1",
                lookup="invoice.read", lookup_key=key,
                observed_at=datetime.now(UTC).isoformat(), value={"balance": 60},
            )

        bindings = [DataSourceBinding(
            source_version_id=source_id, kind="sdk", source_identity="billing.read",
            account_boundary="account_1", lookup="invoice.read",
            resolve_resource=lambda _: "invoice_123", read=read,
        ) for source_id, read in ((SOURCE, first_read), (second_source, second_read))]
        async with client(TwoSources()) as sdk:
            call = sdk._sidecar.prepare(operation(), {"invoiceId": "invoice_123"})
            resolved, _, _ = await resolve_data(
                sdk._sidecar._http, sdk._sidecar._endpoint, sdk._sidecar._token,
                registered_data_sources(bindings), call, "tool_call",
            )
        self.assertEqual(shared["balance"], 999)
        self.assertEqual(resolved.as_dict()["factResolutions"][0]["value"]["balance"], 80)
