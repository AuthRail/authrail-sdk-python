"""Exercise an installed SDK against the isolated real-server verification harness."""

import asyncio
import json
import os
import sqlite3
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from authrail import ApprovalContinuation, AsyncEnforceClient, EnforceBlockedError, Operation


async def main() -> None:
    os.umask(0o077)
    directory = Path(os.environ["AUTHRAIL_VERIFY_DIRECTORY"])
    ledger = sqlite3.connect(directory / "python-effects.sqlite")
    ledger.execute("CREATE TABLE effects (provider_key TEXT PRIMARY KEY, amount INTEGER NOT NULL)")
    config = {
        "sidecar_url": os.environ["AUTHRAIL_SIDECAR_URL"],
        "adapter_token": os.environ["AUTHRAIL_ADAPTER_TOKEN"],
        "organisation_id": os.environ["AUTHRAIL_ORGANISATION_ID"],
        "deployment_id": os.environ["AUTHRAIL_DEPLOYMENT_ID"],
        "executor_private_key": await asyncio.to_thread(
            Path(os.environ["AUTHRAIL_EXECUTOR_PRIVATE_KEY_FILE"]).read_bytes
        ),
    }

    def operation(case: str) -> Operation:
        return Operation(
            version_id=os.environ["AUTHRAIL_OPERATION_VERSION_ID"],
            action_key=f"python-connected-{case}",
            principal_id="isolated-python-executor",
            session_id="isolated-python-session",
            principal_source="service_identity",
            resource_source="not_applicable",
            review_summary={
                "title": "Review simulated payment",
                "fields": [{"label": "Purpose", "value": "Isolated Python SDK verification"}],
            },
        )

    async def execute(arguments, context):
        # This durable isolated ledger is the only effect; no provider is called.
        ledger.execute(
            "INSERT INTO effects VALUES (?, ?)",
            (context.provider_idempotency_key, arguments["amount"]),
        )
        ledger.commit()
        return {"accepted": True}

    def effect_count() -> int:
        return ledger.execute("SELECT count(*) FROM effects").fetchone()[0]

    async with AsyncEnforceClient(**config) as client:
        allowed = await client.enforce(operation("allow"), {"amount": 40}, execute)
        assert allowed.result == {"accepted": True}
        assert allowed.call_decision.recording_status == "retained"
        assert allowed.result_decision.recording_status == "retained"
        assert effect_count() == 1
        try:
            await client.enforce(operation("deny"), {"amount": 140}, execute)
        except EnforceBlockedError as blocked:
            assert not blocked.effect_may_have_occurred
            assert blocked.decision is not None and blocked.decision.outcome == "deny"
            assert blocked.decision.recording_status == "retained"
        else:
            raise AssertionError("Denied payment was not stopped")
        assert effect_count() == 1
        try:
            await client.enforce(operation("approval"), {"amount": 70}, execute)
        except EnforceBlockedError as blocked:
            continuation = blocked.approval_continuation
            assert continuation is not None
            assert not blocked.effect_may_have_occurred
            assert continuation.decision.recording_status == "retained"
        else:
            raise AssertionError("Approval did not pause execution")
        assert effect_count() == 1
        # Fixture-owned storage keeps the saved continuation encrypted. The key is
        # separate, private application state, never included in the agent request.
        key = AESGCM.generate_key(bit_length=256)
        (directory / "workflow-storage.key").write_bytes(key)
        nonce = os.urandom(12)
        aad = f"{config['organisation_id']}:{config['deployment_id']}".encode()
        sealed = nonce + AESGCM(key).encrypt(
            nonce, json.dumps(continuation.as_dict()).encode(), aad
        )
        (directory / "continuation.sealed").write_bytes(sealed)
        decision = continuation.decision.as_dict()
        pending = directory / "approval-request.json"
        temporary = directory / "approval-request.tmp"
        temporary.write_text(
            json.dumps(
                {
                    "approvalRequestId": decision["approvalRequestId"],
                    "actionId": decision["actionId"],
                }
            )
        )
        temporary.replace(pending)

    for _ in range(300):
        if (directory / "approval-ready").is_file():
            break
        await asyncio.sleep(0.1)
    else:
        raise AssertionError("Named reviewer did not approve the isolated request")

    sealed = (directory / "continuation.sealed").read_bytes()
    saved = AESGCM((directory / "workflow-storage.key").read_bytes()).decrypt(
        sealed[:12], sealed[12:], aad
    )
    restored = ApprovalContinuation.from_dict(json.loads(saved))
    async with AsyncEnforceClient(**config) as restarted:
        approved = await restarted.resume_approval_from(restored, execute)
        assert approved.result == {"accepted": True}
        assert approved.result_decision.recording_status == "retained"
        assert effect_count() == 2
        try:
            await restarted.resume_approval_from(restored, execute)
        except EnforceBlockedError as blocked:
            assert not blocked.effect_may_have_occurred
        else:
            raise AssertionError("A consumed approval was reused")
    assert effect_count() == 2
    assert ledger.execute("SELECT sum(amount) FROM effects").fetchone()[0] == 110
    ledger.close()
    print(json.dumps({"effects": 2, "replayBlocked": True}))


if __name__ == "__main__":
    asyncio.run(main())
