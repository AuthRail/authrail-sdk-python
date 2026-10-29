"""Run Python against the sibling Go sidecar without changing either deployment."""

import asyncio
import shutil
import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from authrail import AsyncObserveClient, Operation


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
        assert effects == [40, 140], effects
    print(
        "Real Go sidecar: signed call/result allow and deny accepted; Observe ran both callbacks; "
        "reports queued locally without claiming central retention."
    )


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
        process = subprocess.Popen(
            [str(work / "verify-sidecar"), directory],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert process.stdout is not None
            url = process.stdout.readline().strip()
            if not url.startswith("http://127.0.0.1:"):
                raise RuntimeError("Isolated sidecar did not start")
            asyncio.run(verify(url))
        finally:
            process.communicate("\n", timeout=10)
            if process.returncode:
                raise RuntimeError("Isolated sidecar exited unsuccessfully")


if __name__ == "__main__":
    main()
