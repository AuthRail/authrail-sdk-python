"""Setup keys cannot become permission; queued execution reports cannot claim retention."""

import json
import unittest

import httpx
from test_observe import VERSION, client, operation

from authrail import AuthRailError, discover


class SetupAndReportTests(unittest.IsolatedAsyncioTestCase):
    async def test_discovery_requires_a_confirmed_response_shape_and_does_not_authorize(self):
        requests = []

        def request(req):
            requests.append(req)
            return httpx.Response(
                201,
                json={
                    "inventoryItemId": VERSION,
                    "inventoryRevisionId": VERSION,
                    "deploymentId": VERSION,
                    "confirmationStatus": "discovered",
                },
            )

        value = await discover(
            control_plane_url="https://api.example.com",
            setup_key="setup-only",
            agent_key="agent_123",
            transport=httpx.MockTransport(request),
        )
        self.assertEqual(value["confirmationStatus"], "discovered")
        self.assertNotIn("permitId", value)
        self.assertEqual(json.loads(requests[0].content), {"agentKey": "agent_123"})
        self.assertEqual(requests[0].headers["Authorization"], "Bearer setup-only")

    async def test_discovery_redirect_and_invalid_identity_are_rejected(self):
        for response in [
            httpx.Response(302, headers={"Location": "https://other.example"}),
            httpx.Response(201, json={"deploymentId": "wrong"}),
        ]:
            transport = httpx.MockTransport(lambda req, reply=response: reply)
            with self.assertRaises(AuthRailError):
                await discover(
                    control_plane_url="https://api.example.com",
                    setup_key="setup-only",
                    agent_key="agent_123",
                    transport=transport,
                )
        with self.assertRaises(AuthRailError):
            await discover(
                control_plane_url="http://remote.example",
                setup_key="setup-only",
                agent_key="agent_123",
            )

    async def test_observed_execution_distinguishes_queue_from_retention(self):
        seen = []

        def request(req):
            seen.append(json.loads(req.content))
            return httpx.Response(202, json={"recordingStatus": "queued"})

        async with client(httpx.MockTransport(request)) as sdk:
            call = sdk.prepare(operation(), {"amount": 80})
            value = await sdk.report_observed_execution(
                call,
                event="unknown",
                provider_idempotency_key="business-request-001",
                provider_reference=None,
            )
        self.assertEqual(value, {"recordingStatus": "queued"})
        self.assertEqual(seen[0]["attemptId"], call.request_id)
        self.assertNotIn("arguments", seen[0])
        self.assertNotIn("result", seen[0])
        self.assertEqual(seen[0]["event"], "unknown")

    async def test_reconciled_outcome_requires_provider_reference_before_network(self):
        def forbidden(req):
            self.fail("Unproven reconciliation reached transport")

        async with client(httpx.MockTransport(forbidden)) as sdk:
            call = sdk.prepare(operation(), {})
            with self.assertRaises(AuthRailError):
                await sdk.report_observed_execution(
                    call,
                    event="reconciled_succeeded",
                    provider_idempotency_key="business-request-001",
                    provider_reference=None,
                )

    async def test_created_response_with_queued_status_is_not_retained(self):
        async with client(
            httpx.MockTransport(lambda req: httpx.Response(201, json={"recordingStatus": "queued"}))
        ) as sdk:
            with self.assertRaises(AuthRailError):
                await sdk.report_observed_execution(
                    sdk.prepare(operation(), {}),
                    event="succeeded",
                    provider_idempotency_key="business-request-001",
                    provider_reference=None,
                )
