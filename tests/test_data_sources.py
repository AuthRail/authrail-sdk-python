"""Verify trusted lookup binding, exact receipt hashes and bounded automatic reads."""

import asyncio
import hashlib
import json
import time
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime

import httpx
from test_contextual import ENVELOPE
from test_contextual import plan as contextual_plan
from test_enforce import BUNDLE, DEPLOYMENT, KEY, ORG, VERSION, Transport, client, operation

from authrail import (
    AsyncEnforceClient,
    AsyncObserveClient,
    AuthRailError,
    DataSourceBinding,
    EnforceBlockedError,
)
from authrail._data import registered_data_sources, resolve_data
from authrail._protocol import ConfigurationChangedError, encode_input
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
                source_identity="billing.read",
                account_boundary="account_1",
                lookup="invoice.read",
                lookup_key=key,
                observed_at=datetime.now(UTC).isoformat(),
                value=shared,
            )

        async def second_read(key):
            await asyncio.sleep(0.02)
            shared["balance"] = 999
            return CustomerReadResult(
                source_identity="billing.read",
                account_boundary="account_1",
                lookup="invoice.read",
                lookup_key=key,
                observed_at=datetime.now(UTC).isoformat(),
                value={"balance": 60},
            )

        bindings = [
            DataSourceBinding(
                source_version_id=source_id,
                kind="sdk",
                source_identity="billing.read",
                account_boundary="account_1",
                lookup="invoice.read",
                resolve_resource=lambda _: "invoice_123",
                read=read,
            )
            for source_id, read in ((SOURCE, first_read), (second_source, second_read))
        ]
        async with client(TwoSources()) as sdk:
            call = sdk._sidecar.prepare(operation(), {"invoiceId": "invoice_123"})
            resolved, _, _, _ = await resolve_data(
                sdk._sidecar._http,
                sdk._sidecar._endpoint,
                sdk._sidecar._token,
                registered_data_sources(bindings),
                call,
                "tool_call",
            )
        self.assertEqual(shared["balance"], 999)
        self.assertEqual(resolved.as_dict()["factResolutions"][0]["value"]["balance"], 80)

    async def test_one_source_deadline_or_cancellation_preserves_completed_sibling_facts(self):
        second_source = "88888888-8888-4888-8888-888888888888"
        stopped = asyncio.Event()

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

        async def slow_resource(_):
            try:
                await asyncio.sleep(10)
            finally:
                stopped.set()
            return "invoice_123"

        async def cancelled_resource(_):
            raise asyncio.CancelledError

        healthy = self.binding()
        for resolve in (slow_resource, cancelled_resource):
            with self.subTest(source=resolve.__name__):
                slow = replace(healthy, source_version_id=second_source, resolve_resource=resolve)
                async with client(TwoSources()) as sdk:
                    call = sdk._sidecar.prepare(operation(), {"invoiceId": "invoice_123"})
                    resolved, _, _, _ = await resolve_data(
                        sdk._sidecar._http,
                        sdk._sidecar._endpoint,
                        sdk._sidecar._token,
                        registered_data_sources([healthy, slow]),
                        call,
                        "tool_call",
                    )
                facts = resolved.as_dict()["factResolutions"]
                self.assertEqual([fact["status"] for fact in facts], ["ok", "unavailable"])
                self.assertEqual(facts[0]["value"], {"balance": 80})
        await asyncio.wait_for(stopped.wait(), timeout=1)

    async def test_queued_sources_finish_before_returning_after_sibling_deadlines(self):
        source_ids = [f"77777777-7777-4777-8777-{index:012d}" for index in range(8)]
        started = []
        stopped = []

        class ManySources(DataTransport):
            def __call__(self, request):
                response = super().__call__(request)
                if request.url.path == "/data-requirements":
                    plan = response.json()
                    plan["requirements"] = [
                        {"sourceVersionId": source_id, "contract": contract()}
                        for source_id in source_ids
                    ]
                    return httpx.Response(200, json=plan)
                return response

        def binding(source_id):
            async def resolve(_):
                started.append(source_id)
                try:
                    await asyncio.sleep(10)
                finally:
                    stopped.append(source_id)
                return "invoice_123"

            return replace(self.binding(), source_version_id=source_id, resolve_resource=resolve)

        async with client(ManySources()) as sdk:
            call = sdk._sidecar.prepare(operation(), {"invoiceId": "invoice_123"})
            resolved, _, _, _ = await resolve_data(
                sdk._sidecar._http,
                sdk._sidecar._endpoint,
                sdk._sidecar._token,
                registered_data_sources([binding(source_id) for source_id in source_ids]),
                call,
                "tool_call",
            )
            self.assertCountEqual(started, source_ids)
            self.assertEqual(
                [fact["status"] for fact in resolved.as_dict()["factResolutions"]],
                ["unavailable"] * 8,
            )
            await asyncio.sleep(0.15)
            self.assertCountEqual(stopped, source_ids)


class CombinedTransport(DataTransport):
    """Provider-contract transport: contextual latency is real, returned envelopes opaque."""

    def __init__(self, *, slow=False, contextual=True, mode="observe"):
        super().__init__()
        self.slow = slow
        self.contextual = contextual
        self.mode = mode
        self.readings = []
        self.evaluations = []
        self.plan_reads = 0
        self.conflicting_phase = None
        self.refresh_conflict = False

    async def __call__(self, request):
        path = request.url.path
        if path == "/data-requirements":
            self.plan_reads += 1
            value = super().__call__(request).json()
            value["requirements"][0]["contract"]["maxAgeSeconds"] = 1
            if request.url.params["phase"] == self.conflicting_phase or (
                self.refresh_conflict and self.readings
            ):
                value["sequence"] = 2
            return httpx.Response(200, json=value)
        if path == "/contextual-requirements":
            value = contextual_plan(request.url.params["phase"], enabled=self.contextual)
            value["sequence"] = 1
            return httpx.Response(200, json=value)
        if path == "/contextual-readings":
            value = json.loads(request.content)
            first = not any(r["phase"] == value["phase"] for r in self.readings)
            self.readings.append(value)
            if self.slow and first:
                await asyncio.sleep(1.15)
            return httpx.Response(200, json={**ENVELOPE, "payload": value["inputSha256"]})
        if path == "/evaluate":
            value = json.loads(request.content)
            self.evaluations.append(value)
            response = super().__call__(request).json()
            response["mode"] = self.mode
            return httpx.Response(200, json=response)
        return super().__call__(request)


class CombinedFreshnessTests(unittest.IsolatedAsyncioTestCase):
    binding = DataSourceTests.binding

    # These regressions exercise the shared Observe evaluator used by Enforce as well.
    def combined_client(self, transport, bindings, *, enforce=False):
        cls = AsyncEnforceClient if enforce else AsyncObserveClient
        return cls(
            sidecar_url="http://127.0.0.1:7078",
            adapter_token="c" * 32,
            organisation_id=ORG,
            deployment_id=DEPLOYMENT,
            executor_private_key=KEY,
            transport=httpx.MockTransport(transport),
            data_sources=bindings,
        )

    async def test_slow_context_rebinds_fresh_changed_facts_in_both_phases(self):
        for phase in ("tool_call", "tool_result"):
            with self.subTest(phase=phase):
                transport = CombinedTransport(slow=True)
                binding = self.binding()
                observations = []
                original_read = binding.read

                async def changing_read(
                    key, original_read=original_read, observations=observations
                ):
                    value = await original_read(key)
                    observations.append(datetime.now(UTC))
                    return replace(value, value={"balance": 80 if self.reads == 1 else 20})

                binding = replace(binding, read=changing_read)
                async with self.combined_client(transport, [binding]) as sdk:
                    call = sdk.prepare(
                        replace(operation(), review_summary=None),
                        {"invoiceId": "invoice_123", "document": "Exact text"},
                    )
                    await sdk.evaluate(call, phase, {"document": "Exact result"})
                    self.assertEqual(self.reads, 2)
                    self.assertGreater((datetime.now(UTC) - observations[0]).total_seconds(), 1.15)
                    self.assertEqual(len(transport.readings), 2)
                    first, final = transport.readings
                    self.assertEqual(first["requestId"], final["requestId"])
                    for field in ("material", "attributionSha256", "bundleId", "assessmentId"):
                        self.assertEqual(first[field], final[field])
                    self.assertNotEqual(first["inputSha256"], final["inputSha256"])
                    evaluated = transport.evaluations[0]
                    self.assertEqual(evaluated["factResolutions"][0]["value"], {"balance": 20})
                    exact = hashlib.sha256(
                        encode_input(evaluated, phase, evaluated.get("result")).encode()
                    ).hexdigest()
                    self.assertEqual(exact, final["inputSha256"])
                    self.assertEqual(
                        evaluated["contextualFindings"], [{**ENVELOPE, "payload": exact}]
                    )
                    observed = datetime.fromisoformat(
                        evaluated["factResolutions"][0]["observedAt"].replace("Z", "+00:00")
                    )
                    self.assertLess((datetime.now(UTC) - observed).total_seconds(), 1)
                    if phase == "tool_call":
                        checked = sdk._data_calls[call]
                        self.assertEqual(
                            checked.as_dict()["factResolutions"], evaluated["factResolutions"]
                        )
                        changed = checked.as_dict()
                        changed["factResolutions"].clear()
                        self.assertNotEqual(changed, checked.as_dict())

    async def test_no_findings_skips_refresh_and_manual_unmanaged_facts_survive(self):
        for managed in (True, False):
            transport = CombinedTransport(contextual=not managed)
            binding = self.binding()
            manual = {
                "sourceVersionId": SOURCE,
                "sourceIdentity": "billing.read",
                "accountBoundary": "account_1",
                "lookup": "invoice.read",
                "lookupKey": "invoice_123",
                "authenticatedExecutor": True,
                "observedAt": datetime.now(UTC).isoformat(),
                "status": "ok",
                "value": {"balance": 12},
            }
            initial = [] if managed else [manual]
            async with self.combined_client(transport, [binding] if managed else []) as sdk:
                call = sdk.prepare(
                    replace(operation(), review_summary=None, fact_resolutions=initial),
                    {"invoiceId": "invoice_123", "document": "Exact text"},
                )
                await sdk.evaluate(call, "tool_call")
            self.assertEqual(transport.plan_reads, 1)
            self.assertEqual(self.reads, 1 if managed else 0)
            if not managed:
                self.assertEqual(transport.evaluations[0]["factResolutions"], [manual])

    async def test_unchanged_canonical_facts_reuse_binding_without_a_contextual_loop(self):
        transport = CombinedTransport()
        binding = self.binding()
        fixed = datetime.now(UTC).isoformat()

        async def read(key):
            self.reads += 1
            return CustomerReadResult(
                source_identity="billing.read",
                account_boundary="account_1",
                lookup="invoice.read",
                lookup_key=key,
                observed_at=fixed,
                value={"balance": 80},
            )

        async with self.combined_client(transport, [replace(binding, read=read)]) as sdk:
            call = sdk.prepare(
                replace(operation(), review_summary=None),
                {"invoiceId": "invoice_123", "document": "Exact text"},
            )
            await sdk.evaluate(call, "tool_call")
        self.assertEqual(self.reads, 2)
        self.assertEqual(len(transport.readings), 1)
        self.assertEqual(len(transport.evaluations), 1)

    async def test_configuration_conflict_stops_before_lookup_on_initial_and_refresh_plan(self):
        for refresh in (False, True):
            transport = CombinedTransport()
            transport.conflicting_phase = None if refresh else "tool_call"
            transport.refresh_conflict = refresh
            binding = self.binding()
            resolutions = 0

            def resolve(_):
                nonlocal resolutions
                resolutions += 1
                return "invoice_123"

            async with self.combined_client(
                transport, [replace(binding, resolve_resource=resolve)]
            ) as sdk:
                call = sdk.prepare(
                    replace(operation(), review_summary=None),
                    {"invoiceId": "invoice_123", "document": "Exact text"},
                )
                with self.assertRaises(ConfigurationChangedError):
                    await sdk._evaluate(
                        call,
                        "tool_call",
                        "observe",
                        expected_bundle={"bundleId": BUNDLE, "sequence": 1},
                    )
            self.assertEqual(resolutions, 1 if refresh else 0)
            self.assertEqual(self.reads, 1 if refresh else 0)
            self.assertEqual(transport.evaluations, [])

    async def test_changed_bundle_never_resolves_provider_resource_or_credentials(self):
        calls = []

        def resolve(_):
            calls.append("resource")
            return "in_invoice123"

        def credential():
            calls.append("credential")
            return "fixture-secret"

        def transport(request):
            self.assertEqual(request.url.path, "/data-requirements")
            return httpx.Response(
                200,
                json={
                    "formatVersion": 1,
                    "operationVersionId": VERSION,
                    "phase": "tool_call",
                    "bundleId": BUNDLE,
                    "sequence": 2,
                    "coverage": "evaluated",
                    "requirements": [
                        {
                            "sourceVersionId": SOURCE,
                            "contract": {
                                "formatVersion": 1,
                                "provider": "stripe",
                                "lookup": "invoice.retrieve",
                                "providerAccountId": "acct_12345678",
                                "resultField": "status",
                                "queryField": {"root": "arguments", "path": ["invoiceId"]},
                                "factKey": "status",
                                "maxAgeSeconds": 1,
                                "timeoutMs": 100,
                                "failure": "unavailable",
                            },
                        }
                    ],
                },
            )

        binding = DataSourceBinding(
            source_version_id=SOURCE,
            kind="stripe",
            provider_account_id="acct_12345678",
            resolve_resource=resolve,
            secret_key=credential,
        )
        async with self.combined_client(transport, [binding]) as sdk:
            call = sdk.prepare(
                replace(operation(), review_summary=None), {"invoiceId": "in_invoice123"}
            )
            with self.assertRaises(ConfigurationChangedError):
                await sdk._evaluate(
                    call,
                    "tool_call",
                    "observe",
                    expected_bundle={"bundleId": BUNDLE, "sequence": 1},
                )
        self.assertEqual(calls, [])

    async def test_enforce_retains_final_facts_in_approval_and_receipt_identity(self):
        transport = CombinedTransport(slow=True, mode="enforce")
        transport.need_approval = True
        binding = self.binding()
        callbacks = 0
        async with self.combined_client(transport, [binding], enforce=True) as sdk:

            async def execute(arguments, context):
                nonlocal callbacks
                callbacks += 1
                self.assertEqual(context.input_sha256, transport.original_hash)
                return {"document": "Exact result"}

            manual = {
                "sourceVersionId": "88888888-8888-4888-8888-888888888888",
                "lookup": "application.policy",
                "lookupKey": "invoice_123",
                "authenticatedExecutor": True,
                "status": "unavailable",
            }
            with self.assertRaises(EnforceBlockedError) as blocked:
                await sdk.enforce(
                    replace(operation(), fact_resolutions=[manual]),
                    {"invoiceId": "invoice_123", "document": "Exact text"},
                    execute,
                )
            saved = blocked.exception.approval_continuation
            self.assertIsNotNone(saved)
            self.assertIn(manual, saved.call.as_dict()["factResolutions"])
            self.assertEqual(
                saved.call.as_dict()["factResolutions"], transport.evaluations[0]["factResolutions"]
            )
            await sdk.resume_approval_from(saved, execute)
        self.assertEqual(callbacks, 1)
        self.assertEqual(len(transport.evaluations), 2)
        self.assertEqual(self.reads, 4)

    async def test_post_effect_retry_never_repeats_callback_or_reads_changed_plan(self):
        transport = CombinedTransport(contextual=False, mode="enforce")
        transport.conflicting_phase = "tool_result"
        binding = self.binding()
        callbacks = 0
        async with self.combined_client(transport, [binding], enforce=True) as sdk:

            async def execute(arguments, context):
                nonlocal callbacks
                callbacks += 1
                return {"document": "Exact result"}

            with self.assertRaises(EnforceBlockedError) as blocked:
                await sdk.enforce(operation(), {"invoiceId": "invoice_123"}, execute)
        self.assertTrue(blocked.exception.effect_may_have_occurred)
        self.assertEqual(callbacks, 1)
        self.assertEqual(self.reads, 1)
        self.assertEqual(transport.plan_reads, 3)
