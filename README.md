<p align="center"><img src="assets/authrail-logo.png" alt="AuthRail" width="96" /></p>

# AuthRail Python

Connect your Python application's tools to AuthRail so your team can inspect
the requests an AI agent makes and see how your rules apply to them.

AuthRail is where your organisation reviews AI systems, defines rules and
investigates activity. This library connects your Python functions to a local
**sidecar**, the service that checks your deployment's selected rules. Your
application keeps its business logic and provider credentials.

`AsyncObserveClient` checks a function's request and result in **Observe**. The
function keeps running even when a rule would deny it or the sidecar cannot be
reached. The observation tells you what was checked and what the rules decided.
Observe is advisory; it does not prevent an operation.

[Documentation](https://docs.authrail.io) ·
[Sidecar](https://github.com/AuthRail/authrail-sidecar) ·
[Node SDK](https://github.com/AuthRail/authrail-sdk-node) ·
[Go SDK](https://github.com/AuthRail/authrail-sdk-go)

## Prepare your connection

You need Python 3.11 or newer and an AuthRail workspace. Follow
[Connect your first application](https://docs.authrail.io/docs/getting-started)
to register your action, confirm it, publish its Rails and create an Observe
deployment. The action's inputs and results must match your function.

From the deployment's **Integration setup**, copy the organisation and deployment
IDs. From the confirmed action's details, copy the **Reviewed Operation Version
ID**. Follow the [identity guide](https://docs.authrail.io/docs/identity) to
generate your application's Ed25519 key pair and register its public key.

Start the sidecar with that deployment's configuration. Your Python process
needs its loopback URL, the local adapter token and the executor **private** key.
The sidecar holds the deployment token and executor **public** key. Keep these
credentials outside the agent's reach.

Use the [native sidecar](https://docs.authrail.io/docs/native) when Python runs
directly on your host. With [Docker](https://docs.authrail.io/docs/docker), the
Python application joins the sidecar's network namespace.

## Install from source

These commands install this checkout, without relying on a PyPI release:

```sh
git clone --branch feat/runtime-observe-adapter https://github.com/AuthRail/authrail-sdk-python.git
cd authrail-sdk-python
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

Check `python --version` after activation. If your machine has several Python
versions, create the environment with the intended interpreter, such as
`python3.11 -m venv .venv`.

## Observe a function

This example reads a local invoice file. It does not transfer money or contact
a provider. Create a private directory at `~/authrail` containing:

- `connection.json`, with the copied IDs under the keys below.
- `adapter-token`, containing the token configured for your local sidecar.
- `executor-private.pem`, containing your application's private key.
- `invoice.json`, a safe record such as `{"invoiceId":"invoice_123","status":"open"}`.

Use this shape for `connection.json`, replacing every placeholder:

```json
{
  "organisation_id": "YOUR_ORGANISATION_ID",
  "deployment_id": "YOUR_DEPLOYMENT_ID",
  "operation_version_id": "YOUR_REVIEWED_OPERATION_VERSION_ID"
}
```

Your reviewed action must accept a text `invoiceId` and return the invoice
fields below. Keep the files outside your checkout and readable only by your
application user. Use your deployment's secret store for a hosted application.

```python
import asyncio
import json
from pathlib import Path

from authrail import AsyncObserveClient, Operation


async def main():
    private = Path.home() / "authrail"
    settings = json.loads((private / "connection.json").read_text())
    async with AsyncObserveClient(
        sidecar_url="http://127.0.0.1:7078",
        adapter_token=(private / "adapter-token").read_text().strip(),
        organisation_id=settings["organisation_id"],
        deployment_id=settings["deployment_id"],
        executor_private_key=(private / "executor-private.pem").read_bytes(),
    ) as client:
        operation = Operation(
            version_id=settings["operation_version_id"],
            action_key="read-invoice-123-request-001",
            principal_id="staff_123",
            session_id="task_123",
            principal_source="application_session",
            resource_source="application_lookup",
            resource_id="invoice_123",
        )

        async def read_invoice():
            text = await asyncio.to_thread((private / "invoice.json").read_text)
            invoice = json.loads(text)
            if invoice["invoiceId"] != "invoice_123":
                raise ValueError("Invoice does not match this request")
            return invoice

        run = client.observe(operation, {"invoiceId": "invoice_123"}, read_invoice)
        invoice = await run.result
        observation = await run.observation
        print("Invoice status:", invoice["status"])
        for phase, decision, error in [
            ("call", observation.call_decision, observation.call_error),
            ("result", observation.result_decision, observation.result_error),
        ]:
            if error:
                print(phase, "check unavailable:", error)
            else:
                print(phase, decision.outcome, decision.recording_status)


asyncio.run(main())
```

`run.result` returns the function's original result or raises its original
exception. `run.observation` completes separately with the call and result
checks. Await both before closing the client or ending the process. Reuse a
client across requests instead of creating a connection pool for each call.

The user, session and invoice IDs above are fixed for demonstration. Derive
them from authenticated application state and trusted resource lookups in your
own application. Do not accept identity claims from the agent. Keep an action
key stable for retries of the same business request; another request needs
another key.

## Inspect the decisions

Open your deployment's **Actions & decisions**. An advisory `deny` can appear
alongside a successful function result: Observe shows what the rules would
decide while your function runs.

- `retained`: the report reached AuthRail.
- `queued`: the sidecar saved the report locally for delivery.
- `unavailable`: recording could not be established.

A decision is separate from an execution receipt or proof of a provider effect.
This wrapper does not infer execution success from a rule outcome. A function
exception does not manufacture a successful result check. For missing checks,
inspect their errors and the [sidecar logs](https://docs.authrail.io/docs/operations).

Arguments and results must be JSON objects, each at most 64 KiB. Context is
copied before asynchronous checks so caller changes cannot alter signed input.
Non-finite numbers, unsupported Python objects and integers outside the safe
JSON integer range are rejected. Represent large identifiers as strings.

## Verify a source change

```sh
python -m pip install -e '.[dev]'
python -m unittest discover -s tests -v
ruff check src tests verification
mypy src
python -m build
```

The fixtures under `tests/fixtures` come from the sidecar's `conformance/v1`
corpus. They verify signing compatibility with Go. Transport tests check
advisory behavior and credential handling; they do not prove a connected tenant
deployment works.

For a real Go handler check, clone `authrail-sidecar` beside this repository,
install the Go version required by its `go.mod`, then run:

```sh
python verification/observe_sidecar.py
```

This uses disposable signed rules and local state. It verifies call/result
allow and deny decisions, preserves Observe execution and checks undelivered
reports are queued. It does not use tenant credentials, touch an existing
sidecar or perform a provider operation.
