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
