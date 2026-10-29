"""Check wire/proof interoperability without a server process, database or tenant credentials."""

import asyncio
import hashlib
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from authrail import AsyncEnforceClient, AsyncObserveClient, EnforceBlockedError, Operation
from authrail._protocol import encode_input

ORG = "00000000-0000-4000-8000-000000000001"
DEPLOYMENT = "00000000-0000-4000-8000-000000000002"
VERSION = "00000000-0000-4000-8000-000000000008"
ACTION = "00000000-0000-4000-8000-000000000010"
PERMIT = "00000000-0000-4000-8000-000000000011"
KEY = Ed25519PrivateKey.from_private_bytes(bytes(32))


async def collect():
    records = []
    needs_approval = False

    def request(req):
        body = json.loads(req.content)
        record = {"path": req.url.path, "body": body}
        records.append(record)
        if req.url.path == "/evaluate":
            executor = {
                "requestId": body["requestId"],
                "actionKey": req.headers["Idempotency-Key"],
                "operationVersionId": body["operationVersionId"],
                "phase": body["phase"],
                "inputSha256": hashlib.sha256(
                    encode_input(body, body["phase"], body.get("result")).encode()
                ).hexdigest(),
                "attribution": body["attribution"],
            }
            if "reviewSummary" in body:
                summary = body["reviewSummary"]
                ordered = {
                    "title": summary["title"],
                    "fields": [
                        {"label": item["label"], "value": item["value"]}
                        for item in summary["fields"]
                    ],
                }
                executor["reviewSummarySha256"] = hashlib.sha256(
                    json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode()
                ).hexdigest()
            record["executor"] = executor
            value = {
                "requestId": body["requestId"],
                "mode": "enforce",
                "enforced": False,
                "coverage": "evaluated",
                "outcome": "approval_required" if needs_approval else "allow",
                "recordingStatus": "retained",
                "reportReplayed": False,
                "actionId": ACTION,
            }
            if needs_approval and body["phase"] == "tool_call":
                value["approvalRequestId"] = VERSION
            return httpx.Response(200, json=value)
        if req.url.path.startswith("/approval-permits/"):
            return httpx.Response(
                201,
                json={
                    "permitId": PERMIT,
                    "actionId": ACTION,
                    "expiresAt": (datetime.now(UTC) + timedelta(seconds=20)).isoformat(),
                },
            )
        if req.url.path == "/execution-receipts":
            return httpx.Response(
                201,
                json={
                    "receiptId": VERSION,
                    "replayed": False,
                    "state": "executing" if body["event"] == "started" else "succeeded",
                },
            )
        return httpx.Response(202, json={"recordingStatus": "queued"})

    config = {
        "sidecar_url": "http://127.0.0.1:7078",
        "adapter_token": "c" * 32,
        "organisation_id": ORG,
        "deployment_id": DEPLOYMENT,
        "executor_private_key": KEY,
    }
    operation = Operation(
        version_id=VERSION,
        action_key="protocol-check",
        principal_id="staff_123",
        session_id="task_123",
        principal_source="application_session",
        resource_source="not_applicable",
        review_summary={"title": "Review invoice", "fields": [{"label": "Amount", "value": "80"}]},
    )

    async def callback(arguments, context):
        return {"status": "read"}

    async with AsyncEnforceClient(**config, transport=httpx.MockTransport(request)) as client:
        await client.enforce(operation, {"amount": 80}, callback)
        needs_approval = True
        try:
            await client.enforce(operation, {"amount": 80}, callback)
        except EnforceBlockedError as blocked:
            assert blocked.approval_continuation is not None
            await client.resume_approval_from(blocked.approval_continuation, callback)
    async with AsyncObserveClient(**config, transport=httpx.MockTransport(request)) as client:
        from dataclasses import replace

        call = client.prepare(replace(operation, review_summary=None), {"amount": 80})
        await client.report_observed_execution(
            call,
            event="unknown",
            provider_idempotency_key="protocol-business-key",
            provider_reference=None,
        )
    return records


def main():
    repository = Path(__file__).resolve().parents[1]
    server = repository.parent / "authrail-server"
    loader = server / "node_modules/tsx/dist/loader.mjs"
    if not loader.is_file():
        raise SystemExit(
            "Install the sibling authrail-server's dependencies before protocol verification."
        )
    records = asyncio.run(collect())
    data = {
        "records": records,
        "organisationId": ORG,
        "deploymentId": DEPLOYMENT,
        "publicKey": KEY.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode(),
    }
    subprocess.run(
        [
            "node",
            "--import",
            str(loader),
            str(repository / "verification/server_protocol.mjs"),
            str(server),
        ],
        input=json.dumps(data),
        text=True,
        check=True,
        timeout=30,
    )


if __name__ == "__main__":
    main()
