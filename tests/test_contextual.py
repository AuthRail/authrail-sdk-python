"""Protect disclosure selection and signed finding transport at the SDK boundary."""

import base64
import hashlib
import json
import unittest

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_observe import DEPLOYMENT, ORG, VERSION, operation

from authrail import AsyncObserveClient, AuthRailError, PreparedCall
from authrail._protocol import canonical, snapshot

BUNDLE = "00000000-0000-4000-8000-000000000030"
RAIL = "00000000-0000-4000-8000-000000000031"
KEY = Ed25519PrivateKey.from_private_bytes(bytes(32))
ENVELOPE = {
    "payload": "signed-answer",
    "keyId": "public-key",
    "algorithm": "ECDSA_SHA_256",
    "signature": "signature",
}


def plan(phase, *, enabled=True, processing=False):
    return {
        "formatVersion": 1,
        "operationVersionId": VERSION,
        "phase": phase,
        "coverage": "evaluated",
        "bundleId": BUNDLE,
        "disclosureProcessing": processing,
        "disclosureRequirements": [
            {
                "railVersionId": RAIL,
                "ruleId": "filter_document",
                "kind": "sanitize",
                "handlerId": "redact",
                "handlerVersion": "a" * 64,
                "target": {
                    "root": "arguments" if phase == "tool_call" else "result",
                    "path": ["document"],
                },
            }
        ]
        if processing
        else [],
        "requirements": [
            {
                "railVersionId": RAIL,
                "assessment": {
                    "id": "review_change",
                    "phase": phase,
                    "fields": [
                        {
                            "root": "arguments" if phase == "tool_call" else "result",
                            "path": ["document"],
                        }
                    ],
                },
            }
        ]
        if enabled
        else [],
    }


def client(transport):
    return AsyncObserveClient(
        sidecar_url="http://127.0.0.1:7078",
        adapter_token="c" * 32,
        organisation_id=ORG,
        deployment_id=DEPLOYMENT,
        executor_private_key=KEY,
        transport=httpx.MockTransport(transport),
    )


def decision(request):
    value = json.loads(request.content)
    return httpx.Response(
        200,
        json={
            "requestId": value["requestId"],
            "mode": "observe",
            "enforced": False,
            "coverage": "evaluated",
            "outcome": "deny",
        },
    )


class ContextualTests(unittest.IsolatedAsyncioTestCase):
    async def test_both_phases_select_only_reviewed_text_and_sign_its_exact_binding(self):
        readings, evaluations = [], []
        documents = {"tool_call": "Review <diff> & code", "tool_result": "Review returned document"}

        def transport(request):
            self.assertEqual(request.headers["Authorization"], "Bearer " + "c" * 32)
            self.assertEqual(request.url.host, "127.0.0.1")
            if request.url.path == "/contextual-requirements":
                return httpx.Response(200, json=plan(request.url.params["phase"]))
            value = json.loads(request.content)
            if request.url.path == "/contextual-readings":
                readings.append(value)
                material = base64.urlsafe_b64decode(value["material"] + "==")
                self.assertEqual(json.loads(material), [documents[value["phase"]]])
                self.assertNotIn("private-token", material.decode())
                attribution = {
                    "principalId": "staff_123",
                    "sessionId": "task_123",
                    "resourceId": None,
                    "principalSource": "application_session",
                    "resourceSource": "not_applicable",
                }
                self.assertEqual(
                    value["attributionSha256"],
                    hashlib.sha256(
                        json.dumps(attribution, separators=(",", ":")).encode()
                    ).hexdigest(),
                )
                proof = value["proof"]
                statement = {
                    "type": "authrail.contextual.request.v1",
                    "organisationId": ORG,
                    "deploymentId": DEPLOYMENT,
                    **{
                        key: value[key]
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
                    "materialSha256": hashlib.sha256(material).hexdigest(),
                    "keySha256": value["keySha256"],
                    "issuedAt": proof["issuedAt"],
                    "expiresAt": proof["expiresAt"],
                }
                KEY.public_key().verify(
                    base64.urlsafe_b64decode(proof["signature"] + "=="),
                    json.dumps(statement, separators=(",", ":")).encode(),
                )
                return httpx.Response(200, json=ENVELOPE)
            evaluations.append(value)
            return decision(request)

        async with client(transport) as sdk:
            call = sdk.prepare(
                operation(), {"document": documents["tool_call"], "secret": "private-token"}
            )
            await sdk.evaluate(call, "tool_call")
            await sdk.evaluate(
                call,
                "tool_result",
                {"document": documents["tool_result"], "secret": "private-token"},
            )
        self.assertEqual(len(readings), 2)
        self.assertNotEqual(readings[0]["inputSha256"], readings[1]["inputSha256"])
        self.assertTrue(all(item["contextualFindings"] == [ENVELOPE] for item in evaluations))

    async def test_disabled_missing_large_or_unprocessed_material_is_not_disclosed(self):
        for case in ("disabled", "missing", "large", "unprocessed"):
            with self.subTest(case=case):

                def transport(request, case=case):
                    if request.url.path == "/contextual-requirements":
                        return httpx.Response(
                            200,
                            json=plan(
                                "tool_call",
                                enabled=case != "disabled",
                                processing=case == "unprocessed",
                            ),
                        )
                    self.assertEqual(request.url.path, "/evaluate")
                    self.assertNotIn("contextualFindings", json.loads(request.content))
                    return decision(request)

                async with client(transport) as sdk:
                    args = (
                        {}
                        if case == "missing"
                        else {"document": "x" * (16_385 if case == "large" else 1)}
                    )
                    await sdk.evaluate(sdk.prepare(operation(), args), "tool_call")

    async def test_processing_uses_transformed_material_and_failure_never_invents_an_answer(self):
        readings = []

        def transport(request):
            if request.url.path == "/contextual-requirements":
                return httpx.Response(200, json=plan("tool_call", processing=True))
            if request.url.path == "/contextual-readings":
                reading = json.loads(request.content)
                readings.append(json.loads(base64.urlsafe_b64decode(reading["material"] + "==")))
                return httpx.Response(503)
            self.assertNotIn("contextualFindings", json.loads(request.content))
            return decision(request)

        async with client(transport) as sdk:
            original = sdk.prepare(operation(), {"document": "[removed]"})
            body = original.as_dict()
            body["guardEvidence"] = [
                {
                    "phase": "tool_call",
                    "bundleId": BUNDLE,
                    "kind": "sanitize",
                    "handlerId": "redact",
                    "handlerVersion": "a" * 64,
                    "target": {"root": "arguments", "path": ["document"]},
                    "outputSha256": hashlib.sha256(canonical("[removed]").encode()).hexdigest(),
                }
            ]
            call = PreparedCall(original.request_id, original.action_key, None, snapshot(body))
            await sdk.evaluate(call, "tool_call")
        self.assertEqual(readings, [["[removed]"]])

    async def test_stale_unrelated_duplicate_or_changed_evidence_cannot_disclose(self):
        for changed in (
            {"bundleId": RAIL},
            {"handlerId": "unrelated"},
            {"handlerVersion": "b" * 64},
            {"outputSha256": "f" * 64},
            {"target": {"root": "arguments", "path": ["other"]}},
            {"duplicate": True},
        ):

            def transport(request):
                if request.url.path == "/contextual-requirements":
                    return httpx.Response(200, json=plan("tool_call", processing=True))
                self.assertEqual(request.url.path, "/evaluate")
                self.assertNotIn("contextualFindings", json.loads(request.content))
                return decision(request)

            async with client(transport) as sdk:
                original = sdk.prepare(operation(), {"document": "[removed]"})
                body = original.as_dict()
                item = {
                    "phase": "tool_call",
                    "bundleId": BUNDLE,
                    "kind": "sanitize",
                    "handlerId": "redact",
                    "handlerVersion": "a" * 64,
                    "target": {"root": "arguments", "path": ["document"]},
                    "outputSha256": hashlib.sha256(canonical("[removed]").encode()).hexdigest(),
                }
                item.update({key: value for key, value in changed.items() if key != "duplicate"})
                body["guardEvidence"] = [item, item] if changed.get("duplicate") else [item]
                await sdk.evaluate(
                    PreparedCall(original.request_id, original.action_key, None, snapshot(body)),
                    "tool_call",
                )

    async def test_invalid_or_unavailable_requirements_stop_the_check(self):
        for status in (200, 503):

            def transport(request, status=status):
                self.assertEqual(request.url.path, "/contextual-requirements")
                return httpx.Response(status, json={**plan("tool_call"), "phase": "tool_result"})

            async with client(transport) as sdk:
                with self.assertRaises(AuthRailError):
                    await sdk.evaluate(
                        sdk.prepare(operation(), {"document": "a diff"}), "tool_call"
                    )

    async def test_result_assessment_of_request_fields_checks_call_processing(self):
        for stale in (False, True):
            readings = []

            def transport(request, readings=readings):
                if request.url.path == "/contextual-requirements":
                    selected = plan("tool_call", processing=True)
                    selected["phase"] = "tool_result"
                    return httpx.Response(200, json=selected)
                if request.url.path == "/contextual-readings":
                    readings.append(request.content)
                    return httpx.Response(503)
                return decision(request)

            async with client(transport) as sdk:
                original = sdk.prepare(operation(), {"document": "[removed]"})
                body = original.as_dict()
                body["guardEvidence"] = [{
                    "phase": "tool_call", "bundleId": RAIL if stale else BUNDLE,
                    "kind": "sanitize", "handlerId": "redact", "handlerVersion": "a" * 64,
                    "target": {"root": "arguments", "path": ["document"]},
                    "outputSha256": hashlib.sha256(canonical("[removed]").encode()).hexdigest(),
                }]
                call = PreparedCall(original.request_id, original.action_key, None, snapshot(body))
                await sdk.evaluate(call, "tool_result", {})
            self.assertEqual(len(readings), 0 if stale else 1)
