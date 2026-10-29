"""Protect signing compatibility, Observe independence and local credential boundaries."""

import asyncio
import json
import unittest
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from authrail import AsyncObserveClient, AuthRailError, Operation, PreparedCall
from authrail._protocol import canonical, encode_input, parse_object, snapshot

FIXTURES = Path(__file__).parent / "fixtures"
ORG = "00000000-0000-4000-8000-000000000001"
DEPLOYMENT = "00000000-0000-4000-8000-000000000002"
VERSION = "00000000-0000-4000-8000-000000000008"


def operation(**overrides):
    values = dict(
        version_id=VERSION,
        action_key="invoice-123",
        principal_id="staff_123",
        session_id="task_123",
        principal_source="application_session",
        resource_source="not_applicable",
    )
    return Operation(**(values | overrides))


def client(transport=None, **overrides):
    values = dict(
        sidecar_url="http://127.0.0.1:7078",
        adapter_token="c" * 32,
        organisation_id=ORG,
        deployment_id=DEPLOYMENT,
        executor_private_key=Ed25519PrivateKey.from_private_bytes(bytes(32)),
        transport=transport,
    )
    return AsyncObserveClient(**(values | overrides))


def decision(request, **overrides):
    body = json.loads(request.content)
    return httpx.Response(
        200,
        json=dict(
            requestId=body["requestId"],
            mode="observe",
            enforced=False,
            coverage="evaluated",
            outcome="deny",
            recordingStatus="queued",
        )
        | overrides,
    )


class ProtocolTests(unittest.TestCase):
    def test_existing_sidecar_canonical_vectors(self):
        corpus = json.loads((FIXTURES / "canonical-input.json").read_text())
        for case in corpus["cases"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(
                    encode_input(case, case["phase"], case.get("result")), case["canonicalInput"]
                )

    def test_non_finite_unsafe_and_non_json_values_cannot_be_signed(self):
        for value in [float("nan"), float("inf"), 2**53, object(), {1: "bad"}, "\ud800"]:
            with self.subTest(value=repr(value)), self.assertRaises(AuthRailError):
                canonical(value)
        self.assertEqual(
            canonical([1.0, -0.0, 1e-7, 1e-6, 1e20, 1e21]),
            "[1,0,1e-7,0.000001,100000000000000000000,1e+21]",
        )
        encoded = snapshot({"amount": 1e20})
        self.assertEqual(snapshot(parse_object(encoded)), encoded)

    def test_go_executor_signature_matches_exactly(self):
        vector = json.loads((FIXTURES / "signed-go-evaluation.json").read_text())
        request = vector["request"]
        call = PreparedCall(
            request["requestId"],
            vector["actionKey"],
            None,
            snapshot(
                {
                    key: request[key]
                    for key in ("requestId", "operationVersionId", "arguments", "attribution")
                }
            ),
        )
        sdk = client()
        proof = sdk._proof(call, "tool_call", None, request["identityProof"]["issuedAt"])
        self.assertEqual(proof, request["identityProof"])
        changed = call.as_dict()
        changed["arguments"] = {"amount": 400}
        altered = PreparedCall(call.request_id, call.action_key, None, snapshot(changed))
        self.assertNotEqual(
            sdk._proof(altered, "tool_call", None, proof["issuedAt"])["signature"],
            proof["signature"],
        )
        asyncio.run(sdk.aclose())

    def test_only_literal_loopback_and_private_ed25519_keys_are_accepted(self):
        for url in [
            "https://127.0.0.1",
            "http://localhost:7078",
            "http://example.com",
            "http://127.0.0.1/other",
            "http://u:p@127.0.0.1",
            "http://127.0.0.1?x=1",
        ]:
            with self.subTest(url=url), self.assertRaises(AuthRailError):
                client(sidecar_url=url)
        with self.assertRaises(AuthRailError):
            client(executor_private_key=b"not-a-key")


class ObserveTests(unittest.IsolatedAsyncioTestCase):
    async def test_denial_is_advisory_and_result_check_uses_original_snapshot(self):
        release = asyncio.Event()
        seen = []

        async def transport(request):
            body = json.loads(request.content)
            seen.append(body)
            if body["phase"] == "tool_call":
                await release.wait()
            return decision(request)

        async with client(httpx.MockTransport(transport)) as sdk:
            arguments = {"amount": 40}

            async def tool():
                arguments["amount"] = 400
                return {"status": "done"}

            run = sdk.observe(operation(), arguments, tool)
            self.assertEqual(await asyncio.wait_for(run.result, 0.2), {"status": "done"})
            self.assertFalse(run.observation.done())
            release.set()
            observed = await run.observation
            self.assertEqual(observed.call_decision.outcome, "deny")
            self.assertEqual(observed.result_decision.outcome, "deny")
            self.assertEqual([v["arguments"] for v in seen], [{"amount": 40}, {"amount": 40}])
            self.assertEqual(seen[0]["requestId"], seen[1]["requestId"])

    async def test_network_failure_does_not_replace_tool_result(self):
        async def transport(request):
            raise httpx.ConnectError("private provider detail", request=request)

        async with client(httpx.MockTransport(transport)) as sdk:

            async def tool():
                return {"status": "completed"}

            run = sdk.observe(operation(), {}, tool)
            self.assertEqual(await run.result, {"status": "completed"})
            observed = await run.observation
            self.assertIsNone(observed.call_decision)
            self.assertNotIn("private", str(observed.call_error))

    async def test_original_tool_exception_is_preserved_without_result_check(self):
        seen = []

        def transport(request):
            seen.append(json.loads(request.content)["phase"])
            return decision(request)

        original = ValueError("business failure")
        async with client(httpx.MockTransport(transport)) as sdk:

            async def tool():
                raise original

            run = sdk.observe(operation(), {}, tool)
            with self.assertRaises(ValueError) as caught:
                await run.result
            self.assertIs(caught.exception, original)
            observed = await run.observation
            self.assertIsNone(observed.result_decision)
            self.assertEqual(seen, ["tool_call"])

    async def test_invalid_context_is_visible_but_tool_runs_once(self):
        effects = []

        def forbidden(request):
            self.fail("Invalid context reached transport")

        async with client(httpx.MockTransport(forbidden)) as sdk:

            async def tool():
                effects.append("ran")
                return {"ok": True}

            run = sdk.observe(operation(principal_id="untrusted value"), {}, tool)
            self.assertEqual(await run.result, {"ok": True})
            self.assertIsNotNone((await run.observation).call_error)
            self.assertEqual(effects, ["ran"])

    async def test_wrong_mode_request_and_enforcement_claims_are_rejected(self):
        for changes in [{"mode": "enforce"}, {"requestId": VERSION}, {"enforced": True}]:
            transport = httpx.MockTransport(lambda req, values=changes: decision(req, **values))
            async with client(transport) as sdk:
                with self.assertRaises(AuthRailError):
                    await sdk.evaluate(sdk.prepare(operation(), {}), "tool_call")

    async def test_redirect_does_not_forward_adapter_credential(self):
        destinations = []

        def transport(request):
            destinations.append(str(request.url))
            return httpx.Response(307, headers={"Location": "https://example.com/steal"})

        async with client(httpx.MockTransport(transport)) as sdk:
            with self.assertRaises(AuthRailError):
                await sdk.evaluate(sdk.prepare(operation(), {}), "tool_call")
        self.assertEqual(destinations, ["http://127.0.0.1:7078/evaluate"])

    async def test_oversized_or_duplicate_json_response_is_rejected(self):
        for body in [
            b'{"requestId":"a","requestId":"b"}',
            b"x" * (128 * 1024 + 1),
            '{"requestId":"a"}'.encode("utf-16"),
        ]:
            transport = httpx.MockTransport(
                lambda req, data=body: httpx.Response(200, content=data)
            )
            async with client(transport) as sdk:
                with self.assertRaises(AuthRailError):
                    await sdk.evaluate(sdk.prepare(operation(), {}), "tool_call")

    async def test_cancelled_tool_never_produces_a_result_decision(self):
        async with client(httpx.MockTransport(decision)) as sdk:
            started = asyncio.Event()

            async def tool():
                started.set()
                await asyncio.Event().wait()

            run = sdk.observe(operation(), {}, tool)
            await started.wait()
            run.result.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await run.result
            observed = await run.observation
            self.assertIsNone(observed.result_decision)
            self.assertIsNotNone(observed.result_error)
