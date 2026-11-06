"""Protect exact target/version processing and reject stale plans before effects."""

import asyncio
import copy
import hashlib
import json
import unittest

import httpx
from test_enforce import ACTION, VERSION, Transport, client, operation

from authrail import AuthRailError, EnforceBlockedError, GuardHandler
from authrail._protocol import canonical
from authrail.guard import process_guard, registered_handlers

BUNDLE = "00000000-0000-4000-8000-000000000030"
HANDLER_VERSION = "a" * 64
BUILTIN_ID = "authrail_redact_credentials_v1"
BUILTIN_VERSION = "cea4d8ac57cc39a33a9584742b56e412ff889026cb6b69b086bccbe4cc25d833"


def plan(phase="tool_call"):
    return {
        "formatVersion": 1,
        "operationVersionId": VERSION,
        "phase": phase,
        "bundleId": BUNDLE,
        "sequence": 1,
        "coverage": "evaluated",
        "requirements": [
            {
                "railVersionId": ACTION,
                "ruleId": "clean",
                "kind": "sanitize",
                "handlerId": "redact",
                "handlerVersion": HANDLER_VERSION,
                "target": {
                    "root": "arguments" if phase == "tool_call" else "result",
                    "path": ["message"],
                },
            }
        ],
    }


def handler():
    return GuardHandler(
        id="redact",
        version=HANDLER_VERSION,
        kind="sanitize",
        process=lambda text: text.replace("SECRET", "[removed]"),
    )


class GuardTests(unittest.IsolatedAsyncioTestCase):
    async def test_builtin_redacts_supported_credentials_without_custom_registration(self):
        value = plan()
        value["requirements"][0].update(handlerId=BUILTIN_ID, handlerVersion=BUILTIN_VERSION)
        credentials = [
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            *["gh" + prefix + "_" + "a" * 36 for prefix in "pousr"],
            "github_pat_" + "a_" * 41,
            "AKIA" + "A1" * 8,
            "ASIA" + "Z9" * 8,
        ]
        for credential in credentials:
            with self.subTest(credential=credential[:20]):
                original = {"message": "before: " + credential + " after", "other": "safe"}
                result = await process_guard(
                    value, VERSION, "tool_call", original, registered_handlers(None)
                )
                self.assertEqual(result.output, {"message": "[REDACTED]", "other": "safe"})
                self.assertNotEqual(original, result.output)
                self.assertEqual(result.evidence[0]["handlerVersion"], BUILTIN_VERSION)

    async def test_builtin_preserves_safe_text_and_requires_exact_ascii_token_boundaries(self):
        value = plan()
        value["requirements"][0].update(handlerId=BUILTIN_ID, handlerVersion=BUILTIN_VERSION)
        token = "ghp_" + "a" * 36
        for text in [
            "ordinary message", "DEMO_SECRET", "ghp_" + "a" * 35,
            token + "a", "a" + token, "_" + token, token + "_",
            "github_pat_" + "a" * 81, "github_pat_" + "a" * 83,
            "AKIA" + "a" * 16, "AKIA" + "A" * 17,
        ]:
            with self.subTest(text=text):
                result = await process_guard(
                    value, VERSION, "tool_call", {"message": text}, registered_handlers([])
                )
                self.assertEqual(result.output["message"], text)
        result = await process_guard(
            value, VERSION, "tool_call", {"message": "é" + token + "é"}, registered_handlers(None)
        )
        self.assertEqual(result.output["message"], "[REDACTED]")

    async def test_builtin_identity_cannot_be_overridden_even_at_a_different_version(self):
        for version, kind in [(BUILTIN_VERSION, "sanitize"), ("a" * 64, "transform")]:
            with self.assertRaises(AuthRailError):
                registered_handlers([GuardHandler(
                    id=BUILTIN_ID, version=version, kind=kind, process=lambda text: text
                )])

    async def test_default_enforce_processes_builtin_before_call_and_result_release(self):
        transport = Transport()
        checked = []

        def request(req):
            if req.method == "GET":
                value = plan(req.url.params["phase"])
                value["requirements"][0].update(
                    handlerId=BUILTIN_ID, handlerVersion=BUILTIN_VERSION
                )
                return httpx.Response(200, json=value)
            if req.url.path == "/evaluate":
                checked.append(json.loads(req.content))
            return transport(req)

        async with client(request) as sdk:
            async def execute(arguments, context):
                self.assertEqual(arguments["message"], "[REDACTED]")
                return {"message": "-----BEGIN PRIVATE KEY-----"}

            result = await sdk.enforce(operation(), {"message": "ghp_" + "a" * 36}, execute)
        self.assertEqual(result.result, {"message": "[REDACTED]"})
        self.assertEqual(checked[0]["arguments"]["message"], "[REDACTED]")
        self.assertEqual(len(checked[1]["guardEvidence"]), 2)

    async def test_sensitive_data_processors_and_withholding_bind_exact_output(self):
        handlers = [
            ("authrail_redact_email_v1",
             "9773bce1f804773de4e773f4fedbc3f8a15785d26e70e49ad7b600eb631ea49d",
             "[REDACTED]", [
                 ("Contact jane.doe+test@example.co.uk.", True), ("a@EXAMPLE.COM", True),
                 ("a..b@example.com", False), ("a.@example.com", False),
                 ("a@example.c", False), ("_name@example.com", False),
                 ("name@example.com_", False), ("a" * 65 + "@example.com", False),
                 ("ordinary reply", False),
             ]),
            ("authrail_redact_payment_card_v1",
             "01c828b26465d66ad89cb6a350c82d9afa1d8673ee8e167acfc33bde27c1535b",
             "[REDACTED]", [
                 ("Card 4111 1111 1111 1111.", True), ("378282246310005", True),
                 ("4242-4242-4242-4242", True), ("4111111111111112", False),
                 ("0000000000000000", False), ("41111111111111111111", False),
                 ("４１１１１１１１１１１１１１１１", False), ("invoice 123456", False),
             ]),
            ("authrail_withhold_field_v1",
             "3ebd6aaea66cbd30459938a624b0f74d6bea612e28d6638273a67145b2fe5555",
             "[WITHHELD]", [("arbitrary protected information", True), ("", True)]),
        ]
        for identifier, version, replacement, samples in handlers:
            for phase in ["tool_call", "tool_result"]:
                for text, detected in samples:
                    with self.subTest(handler=identifier, phase=phase, text=text):
                        value = plan(phase)
                        value["requirements"][0].update(
                            handlerId=identifier, handlerVersion=version
                        )
                        original = {"message": text, "kept": True}
                        result = await process_guard(
                            value, VERSION, phase, original, registered_handlers(None)
                        )
                        expected = replacement if detected else text
                        self.assertEqual(result.output, {"message": expected, "kept": True})
                        self.assertEqual(original["message"], text)
                        self.assertEqual(result.evidence[0]["outputSha256"],
                                         hashlib.sha256(canonical(expected).encode()).hexdigest())
            with self.assertRaises(AuthRailError):
                registered_handlers([GuardHandler(id=identifier, version="f" * 64,
                                                  kind="sanitize", process=lambda text: text)])

    async def test_exact_handler_processes_a_copy_and_binds_output_digest(self):
        original = {"message": "SECRET", "untouched": "value"}
        result = await process_guard(
            plan(), VERSION, "tool_call", original, registered_handlers([handler()])
        )
        self.assertEqual(original["message"], "SECRET")
        self.assertEqual(result.output, {"message": "[removed]", "untouched": "value"})
        evidence = result.evidence[0]
        self.assertEqual(
            evidence["outputSha256"], hashlib.sha256(canonical("[removed]").encode()).hexdigest()
        )
        self.assertEqual(evidence["bundleId"], BUNDLE)

    async def test_missing_version_isolation_and_overlapping_targets_stop_processing(self):
        for mutate in [
            lambda value: value["requirements"][0].update(handlerVersion="b" * 64),
            lambda value: value["requirements"][0].update(kind="isolate"),
            lambda value: value["requirements"].append(
                {
                    **value["requirements"][0],
                    "handlerId": "other",
                    "target": {"root": "arguments", "path": ["message", "part"]},
                }
            ),
            lambda value: value.update(coverage="unavailable"),
        ]:
            value = plan()
            mutate(value)
            with self.assertRaises(AuthRailError):
                await process_guard(
                    value,
                    VERSION,
                    "tool_call",
                    {"message": "SECRET"},
                    registered_handlers([handler()]),
                )

    async def test_duplicate_requirement_is_processed_once(self):
        value = plan()
        value["requirements"].append(copy.deepcopy(value["requirements"][0]))
        processed = await process_guard(
            value, VERSION, "tool_call", {"message": "SECRET"}, registered_handlers([handler()])
        )
        self.assertEqual(len(processed.evidence), 1)

    async def test_stale_bundle_cannot_reach_protected_function(self):
        transport = Transport()

        def request(req):
            if req.method == "GET":
                return httpx.Response(200, json=plan())
            response = transport(req)
            if req.url.path == "/evaluate":
                body = json.loads(response.content)
                return httpx.Response(200, json={**body, "bundleId": BUNDLE, "sequence": 2})
            return response

        async with client(request, guard_handlers=[handler()]) as sdk:

            async def forbidden(arguments, context):
                self.fail("Changed Guard bundle reached business effect")

            with self.assertRaises(EnforceBlockedError):
                await sdk.enforce(operation(), {"message": "SECRET"}, forbidden)

    async def test_both_boundaries_apply_and_receipts_use_processed_call(self):
        transport = Transport()
        checked = []

        def request(req):
            if req.method == "GET":
                return httpx.Response(200, json=plan(req.url.params["phase"]))
            response = transport(req)
            if req.url.path == "/evaluate":
                body = json.loads(req.content)
                checked.append(body)
                return httpx.Response(
                    200, json={**json.loads(response.content), "bundleId": BUNDLE, "sequence": 1}
                )
            return response

        async with client(request, guard_handlers=[handler()]) as sdk:

            async def execute(arguments, context):
                self.assertEqual(arguments["message"], "[removed]")
                return {"message": "response SECRET"}

            result = await sdk.enforce(operation(), {"message": "SECRET"}, execute)
        self.assertEqual(result.result, {"message": "response [removed]"})
        self.assertEqual(checked[0]["arguments"]["message"], "[removed]")
        self.assertEqual(len(checked[1]["guardEvidence"]), 2)

    async def test_reader_deadline_does_not_accept_a_late_answer(self):
        from authrail._async import with_deadline

        async def ignores_cancel_once():
            try:
                await asyncio.sleep(1)
            except asyncio.CancelledError:
                await asyncio.sleep(0.02)
                return "late"

        with self.assertRaises(AuthRailError):
            await with_deadline(ignores_cancel_once(), 0.01)
        await asyncio.sleep(0.03)
