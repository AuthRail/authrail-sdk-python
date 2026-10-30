<p align="center"><img src="https://raw.githubusercontent.com/AuthRail/authrail-sdk-python/v0.1.1/assets/authrail-logo.png" alt="AuthRail" width="96" /></p>

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

Use `AsyncEnforceClient` when the function must wait for permission. It checks
the call, records the execution start, invokes your function and checks the
result before releasing it. The setup uses the same sidecar and application key.

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

## Install

Create a virtual environment in your application directory and install the
[PyPI package](https://pypi.org/project/authrail/):

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install authrail==0.1.1
```

Check `python --version` after activation. Use Python 3.11 or newer; if several
versions are installed, create the environment with your intended interpreter,
such as `python3.11 -m venv .venv`. Installing the SDK does not start the sidecar.

<details>
<summary>Install from source when contributing</summary>

```sh
git clone https://github.com/AuthRail/authrail-sdk-python.git
cd authrail-sdk-python
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

Follow [Verify a source change](#verify-a-source-change) before submitting changes.

</details>

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

## Require permission with Enforce

Before changing your deployment to Enforce, review
[Observe and Enforce](https://docs.authrail.io/docs/modes) and the
[execution boundary](https://docs.authrail.io/docs/security). The agent must not
have another route to your protected function or provider credentials.

Create `AsyncEnforceClient` with the same connection arguments used above.
Its callback receives the **checked arguments** and an **execution context**:

```python
async def read_invoice(checked_arguments, execution):
    text = await asyncio.to_thread((private / "invoice.json").read_text)
    invoice = json.loads(text)
    if invoice["invoiceId"] != checked_arguments["invoiceId"]:
        raise ValueError("Invoice does not match this request")
    return invoice

checked = await client.enforce(operation, {"invoiceId": "invoice_123"}, read_invoice)
invoice = checked.result
```

This replaces the `observe` call and its two awaitables in the earlier example.
The function runs only after the call is allowed, its decision is retained in
AuthRail, and a fresh execution-start report is acknowledged. A queued decision
is insufficient. After the callback, completion is reported and its result is
checked. An allowed call does not guarantee that its result will be released.

For a function that changes provider data, persist `execution.as_dict()` with
your business request before the provider call, and use
`execution.provider_idempotency_key` as the provider's idempotency key. This
lets your workflow investigate an uncertain attempt without creating another
payment or write. Your callback owns the provider credential and business logic.

### When human approval is required

Supply `Operation(review_summary=...)` with a short title and safe labelled
fields for the reviewer. Configure named reviewers on the connected action
as described in [Human approvals](https://docs.authrail.io/docs/approvals).

An `EnforceBlockedError` identifies the blocked `phase` and whether an effect
may already have occurred. For an eligible retained approval request, its
`approval_continuation` holds the exact call and decision needed later.

Save `approval_continuation.as_dict()` in your application's private, encrypted
storage with its tenant, user and workflow identity. Save the conversation or
task state separately; the SDK does not store the entire agent session. Return
“Awaiting approval” instead of leaving the original HTTP request open.

After the request is approved:

- In the same process, `resume_approval(blocked_error)` uses the original callback.
- After a restart, restore with `ApprovalContinuation.from_dict(saved_value)`
  and call `resume_approval_from(continuation, callback)`.
- If the permit claim response was lost, use
  `recover_approval_from(continuation, callback)`. This reads the existing permit
  rather than issuing another one.

Your application must arrange the later resume step. An approval does not
automatically wake a worker or make a payment. Expired, mismatched and replayed
requests cannot authorize another callback. Do not change the approved amount
or recipient; a different request needs a new check.

### When the outcome is uncertain

`EnforceOutcomeUnknownError` carries `recovery`, an `ExecutionContext`. A callback
exception or cancellation does not prove a provider operation failed. Losing
the completion acknowledgement also leaves the outcome uncertain.

Restore the saved context with `ExecutionContext.from_dict`. Query the provider
using its original idempotency key and establish the real outcome. Then call
`reconcile(context, "succeeded", provider_reference)` or
`reconcile(context, "failed", provider_reference)` as appropriate. Reconciliation
records that knowledge; it does not run the business callback again.

A result-phase `EnforceBlockedError` has `effect_may_have_occurred=True`. The
operation may have completed even though its result was withheld. Follow
[execution recovery](https://docs.authrail.io/docs/recovery) before retrying.

## Read business information for a rule

A rule may need information the agent's arguments do not establish. Before paying
an invoice, for example, it may need the remaining balance from the correct
QuickBooks account. That lookup produces a **fact**; the Rail uses the fact to
decide permission.

Create and review the source in **Rails → Create Rail → Data Rail → Continue**.
Choose the provider or application source, then select it for the action's Data
Rail. Open that Rail's **Integration details** (or **Source details for
developers** in its editor) to obtain the exact source version ID and reviewed
settings. A displayed version number such as `1` is not its UUID.

Choose the reader that matches that reviewed source:

| Helper | What it reads |
| --- | --- |
| `lookup_stripe_invoice_status` | One invoice's status after verifying the reviewed Stripe account. Supports explicit Connect-account selection. |
| `lookup_quickbooks_invoice_balance` | `Invoice.Balance` for one invoice in the reviewed company/realm. Currency needs a separate reviewed source. |
| `lookup_customer_fact` | A bounded application-owned API/database/SDK read with exact source, account and resource identity. |
| `new_customer_api_reader` | A fixed HTTPS GET reader used with `lookup_customer_fact`. |

The returned resolution is a JSON object. Add it to
`Operation(fact_resolutions=[resolution])` before checking the operation. These
helpers perform reads; they do not execute the payment or write being checked.

Your application holds provider credentials and owns OAuth consent, refresh,
storage and revocation. A management-plane Connection in AuthRail does not
provide Runtime write credentials. Never let the agent choose the source URL,
provider account, access token or lookup implementation.

An unavailable source produces `unavailable`; an account/resource mismatch or
invalid value produces `untrusted`. Neither supplies a passing fact. Do not
replace an unread balance with zero. The sidecar checks the reviewed source's
freshness and failure rules.

## Use contextual AI when the answer needs interpretation

AuthRail's contextual AI uses a model to answer a specific question about text
selected by your application. It can classify a payment justification, inspect
an export or identify destructive work in a change plan. The model returns a
Yes/No answer, category or score; your published Rail determines permission.

The supplied extractor uses **OpenAI Decisions with GPT-6 Luna**, through your
own OpenAI account and API key. It is separate from the agent's model. The
sidecar does not select or call that model for you.

1. Choose the question and confidence requirement in application configuration.
2. Calculate `openai_decisions_config_sha256(question)`. In the tenant source
   setup, choose **AI context** and record the model, fingerprint, instructions
   version, account, result field and limits under **Required AI reading
   configuration**. Confirm the source and select it for the Data Rail.
3. Copy its reviewed source version ID and use those same settings in the SDK.
   The server stores the reviewed setup, while your application supplies the
   actual question text and model credential.
4. Give the extractor only the selected text that may be disclosed. Validate
   the returned fact, then include it in the operation's `fact_resolutions`.

The following shows the SDK part after that review. Replace the source ID and
account with your actual reviewed values; the other settings must also match
what you reviewed:

```python
from authrail import (
    DECISIONS_MODEL,
    DecisionsQuestion,
    ExtractionSource,
    extract_context_fact,
    new_openai_decisions_extractor,
    openai_decisions_config_sha256,
)
from datetime import UTC, datetime

question = DecisionsQuestion(
    type="predicate",
    instructions="Does this change plan describe deleting stored data?",
    min_confidence=0.8,
)
source = ExtractionSource(
    source_version_id="YOUR_REVIEWED_SOURCE_VERSION_ID",
    source_identity="change-review",
    account_boundary="YOUR_REVIEWED_ACCOUNT_ID",
    lookup="change.read",
    timeout_ms=2000,
    result_path=("destructive",),
    value_type="boolean",
    model_id=DECISIONS_MODEL,
    model_config_sha256=openai_decisions_config_sha256(question),
    prompt_version="change-review-v1",
    max_input_bytes=65536,
    max_output_bytes=4096,
)
extractor = new_openai_decisions_extractor(
    source=source,
    question=question,
    api_key=(private / "openai-key").read_text().strip(),
)
resolution = await extract_context_fact(
    source,
    "change_123",
    "record:change_123",
    datetime.now(UTC).isoformat(),
    b"Remove the archived tables after the retention review.",
    extractor,
)
```

Run this inside your async application; `private` is the protected directory
used in the earlier example. `openai-key` contains your own provider credential.
The selected text is sent to OpenAI. This helper does not automatically remove
protected information: select or redact fields in trusted application code
before calling it. Do not send material the provider is not permitted to receive.

The fact report contains the answer and source/model metadata, not those raw
bytes. A refusal or low confidence stays `uncertain`; a timeout stays
`unavailable`. A malformed or mismatched extraction cannot become a trusted
answer. Model confidence does not override a denial or missing approval.

The fingerprint helper uses Go-compatible settings bytes. The extractor also
recognises the existing Node encoding for the exact same question/settings, so
reviewed Node sources with HTML characters in their instructions can be reused.

## Apply a reviewed Guard handler

A Guard may require sanitizing or transforming a particular string before the
call or result check. Register the exact handler ID, version and kind on
`AsyncEnforceClient(guard_handlers=[...])`:

```python
from authrail import GuardHandler

handler = GuardHandler(
    id="remove-demo-marker",
    version="YOUR_REVIEWED_HANDLER_SHA256",
    kind="sanitize",
    process=lambda value: value.replace("DEMO_SECRET", "[removed]"),
)
```

This removes a demo marker, not arbitrary sensitive data. Use your reviewed
implementation and its exact 64-character hexadecimal version fingerprint.
The sidecar's plan selects the field; a handler cannot choose another target.
Processing uses a copy, signs evidence for the changed string and checks the
same bundle before proceeding. Missing handlers, unsupported isolation or a
changed configuration stop the boundary. Observe does not run handlers.

Handlers may be synchronous or async, but must be pure string processing with
no business effects. Late answers are rejected. Custom readers and handlers
must still cooperate with cancellation; the SDK cannot terminate arbitrary
application code or a running thread.

## Record execution and session history explicitly

An Observe decision does not establish what the application did. If your
application knows the outcome, use `report_observed_execution` with the original
`run.call`, its provider idempotency key and explicit `succeeded`, `failed` or
`unknown` event. Reconciled events also need a provider reference. A queued
receipt remains local; do not rerun an effect just because reporting failed.

For trajectory-sensitive rules, supply `Operation(trajectory=...)` from the
application's durable, authenticated session history, including its session ID,
start/complete markers and prior-read Operation Version IDs. The sidecar checks
it against its private ledger. Do not turn the agent's claim that it read or
approved something into trusted history.

`discover` is an optional setup helper using a short-lived tenant setup key and
stable agent key. It can return a discovered Inventory identity; that identity
still needs tenant confirmation and an authenticated deployment before Enforce.
Discovery does not grant permission or create a provider credential.

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
sidecar or perform a provider operation. It also verifies that the real handler
keeps Enforce callbacks stopped when reporting is unavailable. Scripted
transport tests cover the successful Enforce sequence, permit recovery and
receipts; these are separate from a tenant-backed payment/approval E2E test.

With the sibling server's dependencies installed, also run:

```sh
python verification/server_protocol.py
```

This sends Python-generated proofs to the server's actual parsers and signature
validators. It checks call, approval claim, execution receipt and Observe receipt
formats, including rejection of changed deployment/input. It does not start a
server, read tenant credentials or mutate a database.

### Continuous integration

Pull requests and pushes to main and the existing feature branch run SDK CI on
Python 3.11–3.14. It checks lint, types, tests and distribution metadata, then
installs both the wheel and source package in separate environments and reruns
the tests outside the checkout. Run `python verification/check_package.py` after
`python -m build` to check those installations locally. Use a clean `dist`
directory containing only the two artifacts for the version being checked.

The compatibility job uses real handlers from a pinned sidecar commit and
disposable local state. It needs no customer credentials and does not establish
tenant or provider acceptance. CI does not publish packages.

Maintainers: see [Releasing](https://github.com/AuthRail/authrail-sdk-python/blob/main/RELEASING.md) for checked artifacts and publication setup.

### Connected server verification

Maintainers with the sibling server checkout and its dependencies can check a
built wheel against real AuthRail services and a disposable PostgreSQL container
on macOS or Linux:

```bash
python verification/connected_server.py \
  --wheel /absolute/path/authrail-0.1.1-py3-none-any.whl \
  --sidecar /absolute/path/authrail-sidecar
```

Verify downloaded candidate checksums first. This installs the wheel in a fresh
virtual environment, migrates a separate temporary database and checks allowed,
denied and approved execution with saved continuation recovery. The server also
checks reviewer-only inbox/email records and duplicate delivery handling. Mail
and stream transport wake-ups are captured; no provider payment or live email
is sent. Existing environment files, deployments and data are not used. Node
and Go are not rerun by this Python-specific check.
