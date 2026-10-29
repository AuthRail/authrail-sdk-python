"""Run Python against the sibling Go sidecar without changing either deployment."""

import asyncio
import shutil
import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from authrail import (
    AsyncEnforceClient,
    AsyncObserveClient,
    EnforceBlockedError,
    GuardHandler,
    Operation,
)


async def verify(url: str) -> None:
    async with AsyncObserveClient(
        sidecar_url=url,
        adapter_token="c" * 32,
        organisation_id="00000000-0000-4000-8000-000000000001",
        deployment_id="00000000-0000-4000-8000-000000000002",
        executor_private_key=Ed25519PrivateKey.from_private_bytes(bytes(32)),
    ) as client:
        effects = []
        for amount, expected in [(40, "allow"), (140, "deny")]:
            operation = Operation(
                version_id="00000000-0000-4000-8000-000000000008",
                action_key=f"isolated-{amount}",
                principal_id="staff_123",
                session_id="task_123",
                principal_source="application_session",
                resource_source="not_applicable",
            )

            async def read_invoice(value=amount):
                effects.append(value)
                return {"status": "read", "amount": value}

            run = client.observe(operation, {"amount": amount}, read_invoice)
            assert await run.result == {"status": "read", "amount": amount}
            observation = await run.observation
            for decision in [observation.call_decision, observation.result_decision]:
                assert decision is not None, observation
                assert decision.coverage == "evaluated", decision.as_dict()
                assert decision.outcome == expected, decision.as_dict()
                assert decision.recording_status == "queued", decision.as_dict()
            assert run.call is not None
            recorded = await client.report_observed_execution(
                run.call,
                event="succeeded",
                provider_idempotency_key=f"isolated-read-{amount}",
                provider_reference=f"local-read-{amount}",
            )
            assert recorded == {"recordingStatus": "queued"}, recorded
        assert effects == [40, 140], effects
    print(
        "Real Go sidecar: signed call/result allow and deny accepted; Observe ran both callbacks; "
        "reports queued locally without claiming central retention."
    )


async def verify_enforce_unavailable(url: str) -> None:
    async with AsyncEnforceClient(
        sidecar_url=url,
        adapter_token="c" * 32,
        organisation_id="00000000-0000-4000-8000-000000000001",
        deployment_id="00000000-0000-4000-8000-000000000002",
        executor_private_key=Ed25519PrivateKey.from_private_bytes(bytes(32)),
    ) as client:
        for amount in [40, 140]:
            operation = Operation(
                version_id="00000000-0000-4000-8000-000000000008",
                action_key=f"enforce-isolated-{amount}",
                principal_id="staff_123",
                session_id="task_123",
                principal_source="application_session",
                resource_source="not_applicable",
                review_summary={
                    "title": "Review invoice",
                    "fields": [{"label": "Amount", "value": str(amount)}],
                },
            )

            async def forbidden(arguments, context):
                raise AssertionError("Unavailable central retention allowed an effect")

            try:
                await client.enforce(operation, {"amount": amount}, forbidden)
            except EnforceBlockedError as error:
                assert not error.effect_may_have_occurred
                assert error.decision is not None
                assert error.decision.recording_status == "queued"
                assert error.decision.outcome == ("allow" if amount == 40 else "deny")
            else:
                raise AssertionError("Enforce released an unretained request")
    print("Real Go sidecar: Enforce kept both callbacks stopped when reports were queued.")


def main() -> None:
    repository = Path(__file__).resolve().parents[1]
    sidecar = repository.parent / "authrail-sidecar"
    if not (sidecar / "go.mod").is_file():
        raise SystemExit("Clone authrail-sidecar beside this repository before verification.")
    with tempfile.TemporaryDirectory(prefix="authrail-python-observe-") as directory:
        work = Path(directory)
        shutil.copyfile(repository / "verification/sidecar/main.go", work / "main.go")
        (work / "go.mod").write_text(
            "module authrail-python-verification\n\ngo 1.26.0\n\n"
            "require github.com/AuthRail/authrail-sidecar v0.0.0\n"
        )
        subprocess.run(
            ["go", "mod", "edit", "-replace", f"github.com/AuthRail/authrail-sidecar={sidecar}"],
            cwd=work,
            check=True,
        )
        subprocess.run(
            ["go", "build", "-mod=mod", "-o", "verify-sidecar", "."],
            cwd=work,
            check=True,
            timeout=180,
        )
        for name, mode, check, extras in [
            ("observe", "observe", verify, []),
            ("enforce", "enforce", verify_enforce_unavailable, []),
            ("guard", "enforce", verify_guard, ["guard"]),
        ]:
            state = work / name
            state.mkdir(mode=0o700)
            process = subprocess.Popen(
                [str(work / "verify-sidecar"), str(state), mode, *extras],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
            )
            try:
                assert process.stdout is not None
                url = process.stdout.readline().strip()
                if not url.startswith("http://127.0.0.1:"):
                    raise RuntimeError("Isolated sidecar did not start")
                asyncio.run(check(url))
            finally:
                process.communicate("\n", timeout=10)
                if process.returncode:
                    raise RuntimeError("Isolated sidecar exited unsuccessfully")


async def verify_guard(url: str) -> None:
    handlers = [
        GuardHandler(
            id="redact",
            version="a" * 64,
            kind="sanitize",
            process=lambda text: text.replace("SECRET", "[removed]"),
        )
    ]
    async with AsyncEnforceClient(
        sidecar_url=url,
        adapter_token="c" * 32,
        organisation_id="00000000-0000-4000-8000-000000000001",
        deployment_id="00000000-0000-4000-8000-000000000002",
        executor_private_key=Ed25519PrivateKey.from_private_bytes(bytes(32)),
        guard_handlers=handlers,
    ) as client:
        operation = Operation(
            version_id="00000000-0000-4000-8000-000000000008",
            action_key="isolated-guard",
            principal_id="staff_123",
            session_id="task_123",
            principal_source="application_session",
            resource_source="not_applicable",
        )

        async def forbidden(arguments, context):
            raise AssertionError("Queued permission ran a callback")

        try:
            await client.enforce(operation, {"amount": 40, "message": "SECRET"}, forbidden)
        except EnforceBlockedError as error:
            assert error.decision is not None
            assert error.decision.outcome == "allow", error.decision.as_dict()
            obligations = error.decision.as_dict().get("obligations")
            assert obligations and all(item["status"] == "fulfilled" for item in obligations), (
                obligations
            )
        else:
            raise AssertionError("Queued permission allowed execution")
    print(
        "Real Go sidecar: exact Python Guard processing evidence accepted; queued permission held."
    )


if __name__ == "__main__":
    main()
