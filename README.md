<p align="center"><img src="https://raw.githubusercontent.com/AuthRail/authrail-sdk-python/v0.1.1/assets/authrail-logo.png" alt="AuthRail" width="96" /></p>

# AuthRail Python

AuthRail helps organisations control what connected AI agents may do and
understand what happened when they acted. In the workspace, you describe an
action, publish rules for it and review the decisions and completion reports.
Those rules are called **Rails**.

This SDK connects a Python function to those Rails. For example, you can wrap an
invoice reader so each agent request and returned invoice are checked by a
**sidecar**, a small service running beside your application. The application
keeps the business function and its provider credentials; the sidecar evaluates
the selected rules and sends decision records to AuthRail.

Start in **Observe** to see how the rules apply while the function continues
running. Switch to **Enforce** when the function should wait for permission;
the SDK also checks its result before returning it to the agent. A decision
explains permission, while a completion report describes what the application
says it did. When an operation affects an external provider, check that provider’s
record to establish its effect independently.

[Documentation](https://docs.authrail.io) ·
[Sidecar](https://github.com/AuthRail/authrail-sidecar) ·
[Node.js SDK](https://github.com/AuthRail/authrail-sdk-node) ·
[Go SDK](https://github.com/AuthRail/authrail-sdk-go) ·
[Python SDK](https://github.com/AuthRail/authrail-sdk-python)

## Choose a version

The install command below selects SDK **0.1.1**, which supports Observe and
Enforce, saved approval continuations, reconciliation, custom Guard handlers
and explicit fact readers. The [first-application guide](https://docs.authrail.io/docs/getting-started)
uses this release with a simple Policy Rail and a local invoice reader.

Some sections below also describe newer repository source. Execution checkpoints,
automatic Rail-owned Contextual AI, expanded built-in Guards and automatic Data reader
bindings are not part of SDK 0.1.1. Check
[compatibility](https://docs.authrail.io/docs/compatibility) before enabling those
requirements. The setup executable and native Runtime are version **0.2.0**,
while its Docker installer selects Runtime **0.1.0**; they have separate version
identities.

## Prepare your connection

You need Python 3.11 or newer and an AuthRail workspace. Follow
[Connect your first application](https://docs.authrail.io/docs/getting-started)
to register your action, confirm it, publish its Rails and create an Observe
deployment. The action's inputs and results must match your function.

Run [sidecar setup](https://docs.authrail.io/docs/native) with the API address
supplied by your installation administrator. Sign in through the browser and
choose the deployment. Setup creates keys and tokens in a private directory,
registers the public key and writes `connection.json` and `integration.json`.
Your application uses the saved `adapter-token` and `executor-private.pem`;
the sidecar receives the deployment token and public key. Keep the generated
files private and preserve them across restarts.

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

This example reads a local invoice file without contacting a provider.
Use the private directory created by guided setup; this example uses
`$HOME/.local/share/authrail/my-deployment`. Keep its original `connection.json`,
`adapter-token` and `executor-private.pem`. Add two separate files:

- `example-config.json`, containing the exact action version below.
- `invoice.json`, with safe data such as `{"invoiceId":"invoice_123","status":"open"}`.

Use this shape for `example-config.json`, replacing the placeholder:

```json
{"operation_version_id":"YOUR_REVIEWED_OPERATION_VERSION_ID"}
```

Keep setup’s `connection.json` alongside these files, because it identifies
the installation that the SDK will connect to.

Your reviewed action must accept a text `invoiceId` and return the invoice
fields below. Keep the files outside your checkout and readable only by your
application user. Use your deployment's secret store for a hosted application.

```python
import asyncio
import json
from pathlib import Path

from authrail import AsyncObserveClient, Operation


async def main():
    private = Path.home() / ".local/share/authrail/my-deployment"
    connection = json.loads((private / "connection.json").read_text())
    settings = json.loads((private / "example-config.json").read_text())
    async with AsyncObserveClient(
        sidecar_url="http://127.0.0.1:7078",
        adapter_token=(private / "adapter-token").read_text().strip(),
        organisation_id=connection["organisationId"],
        deployment_id=connection["deploymentId"],
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

The sample uses fixed user, session and invoice IDs so you can try the SDK
without building a login flow. In your application, get the caller from login
or service authentication and look up the invoice that caller may access.
Reuse the action key when recovering the same request and choose another key
for new work.

## Inspect the decisions

Open your deployment's **Actions & decisions**. An advisory `deny` can appear
alongside a successful function result: Observe shows what the rules would
decide while your function runs.

- `retained`: the report reached AuthRail.
- `queued`: the sidecar saved the report locally for delivery.
- `unavailable`: recording could not be established.

The decision tells you how the rule applied; the function result tells you
what your code returned. A failed function has no successful result to check.
If either check is missing, inspect its error and the
[sidecar logs](https://docs.authrail.io/docs/operations). You would also check
the provider’s own record before treating a write as independently verified.

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
Its callback receives the **checked arguments** and an **execution context**,
which identifies the attempt and carries the provider idempotency key used
for recovery:

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

Replace the earlier `observe` call and its two awaitables with this pattern.
Before invoking the callback, the SDK obtains permission and waits for AuthRail
to save both the decision and execution-start report. A report still queued
locally cannot authorise execution. After the callback returns, the SDK reports
completion and checks the result; that check may withhold output even though
the operation has already happened.

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

Your application arranges the later resume step, for example through its
existing task worker. Approval itself does not wake that worker or make a
payment. Resumption uses the original request while its permission is valid;
changing the amount or recipient needs a new check. An expired, mismatched
or already-used request cannot start another callback.

### When the outcome is uncertain

**Current source; not released in SDK 0.1.1:** pass an async application-owned save
as `execution_checkpoint=save_recovery` to `enforce`, `resume_approval`,
`resume_approval_from` or `recover_approval_from`. The SDK awaits this callback with
an immutable `ExecutionContext` before reporting execution start. Persist
`context.as_dict()` in protected storage; a failed save withholds both start and
the business callback. The hook is specific to that call and does not change the
shared client. The SDK does not select or write PostgreSQL, and this hook alone
does not provide shared storage or worker integration.

`EnforceOutcomeUnknownError` carries `recovery`, an `ExecutionContext`. A callback
exception or cancellation does not prove a provider operation failed. Losing
the completion acknowledgement also leaves the outcome uncertain. Current source
also retains this recovery identity when the start acknowledgement is missing,
invalid or replayed; the business callback stays stopped. Cancellation during the
checkpoint propagates before start, while cancellation during start preserves
the uncertain execution identity.

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

Create the source in **Rails → Create Rail → Data Rail → Continue** and select
it for the action’s Data Rail. In **Integration details**, or **Source details
for developers** in the editor, copy the source version ID and its settings.
That ID identifies the source definition the sidecar will check; a displayed
revision number such as `1` is not the ID. Use the reader for that source:

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

If the source cannot be read, the result is `unavailable`. A mismatched
account or record, or an invalid value, is `untrusted`. The sidecar applies the
source’s freshness and failure rules to those states; an unread balance remains
unknown rather than becoming zero.

## Use AuthRail Contextual AI

The integration in this section is available in current source, but not in
published SDK 0.1.1. Choose a compatible released SDK and Runtime before using
it in an installed application.

Some rules need to understand meaning as well as compare values. For example,
a release rule might ask whether a code change weakens authentication. Enable
**AuthRail Contextual AI** on the Guard or Policy Rail, describe the rule and
review the question, permitted fields and answer that AuthRail prepares. Test
those choices before publishing the Rail.

During a call or result check, the SDK obtains that assessment from the sidecar,
applies any required local processing and selects the permitted material. It
sends that material through the sidecar to AuthRail for interpretation. AuthRail
returns a signed finding, which the sidecar verifies against the request,
caller, material and Rail version before using it in the rule. AuthRail operates
the interpretation service, so your application does not need model credentials,
a prompt or a separately configured extractor.

If Contextual AI is off for the Rail, it sends no contextual request. If the
assessment is uncertain, material is missing or the service is unavailable, the
rule cannot pass using an invented answer. Ordinary authentication, data lookups
and human approval still apply; interpretation supplies information to a rule,
not permission to perform the action.

Review disclosure before publication because AuthRail receives the selected
material for transient processing. Normal Actions, logs and traces exclude that
material and retain the assessment status and finding instead. The
[Contextual AI guide](https://docs.authrail.io/docs/facts) explains this flow
and its failure handling.

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

This example removes only the literal `DEMO_SECRET` marker. It is useful for
learning the handler interface, rather than detecting arbitrary sensitive
information. For your own handler, use its 64-character hexadecimal version
fingerprint and the ID and kind configured in the Guard.

The sidecar’s plan selects the string field. The SDK processes a copy, signs
the input and output digests and checks that the same rule bundle still
applies. If a handler is missing, the configuration changes or isolation
cannot be provided, Enforce stops. Observe does not run these handlers.

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


## Current source: durable approval and configuration renewal

This section describes unreleased source. Use it with the matching updated sidecar
source. Published SDK 0.1.1 and sidecar 0.2.0 do not establish support for these new
contracts. A new SDK fails closed against an older sidecar that rejects the
configuration expectation; it does not silently omit that check.

The SDK prepares Guard processing, Data facts and permitted contextual material
for an exact bundle. It sends that bundle/sequence as a denial-only expectation.
If configuration changed before the sidecar retained a decision, the sidecar
returns the exact `configuration_changed` conflict. The SDK rebuilds preparation
once from the original private input. A generic conflict, denied decision, network
error or execution-start uncertainty never triggers this retry. This keeps an
unchanged renewal from double-transforming input or repeating a business effect.

After a completed effect, the same bounded retry can repeat result preparation
and checking only. If current argument processing is needed for contextual
material disclosure, its output must still equal the executed input. A changed
output, unsupported requirement or repeated configuration change withholds the
result. Result withholding does not undo an effect or authorise another call.

Pending human requests survive the `expiresAt` freshness deadline. Read their
current state and `requiresRefresh` separately. A fresh decision is needed before
stale work can execute; earlier votes do not approve that new decision. Refresh
keeps the original business key, caller, resource and exact processed arguments,
uses a new attempt, and rereads configured Data sources. Applications supply
current manual facts/trajectory explicitly when needed. A valid existing permit
is recovered through the original recover method; unknown effects are reconciled
using their original recovery identity.

New approval continuations retain original private arguments alongside the
processed call so refresh never transforms already transformed input. Encrypt
and tenant-scope that state in application-owned storage. Existing saved
continuations still support exact claim/recovery. A legacy continuation with
processing evidence and no original input cannot safely refresh transformed
arguments; restore that input through the application's protected workflow.

Provider references in execution/reconciliation receipts are opaque UTF-8 evidence
of at most 4000 bytes, with no control characters or surrounding whitespace. They
may contain paths and punctuation. They never select a provider endpoint or grant
execution authority. The business idempotency key retains its separate strict
format. A `started` receipt has no provider reference; reconciliation needs one.

`AsyncEnforceClient.approval_status(saved)` returns an `ApprovalStatus` with
`state`, `requires_refresh` and `expires_at`. Use `refresh_approval_from` for an
explicit fresh decision, supplying current `fact_resolutions`/`trajectory` when
needed. If approval is still required, `EnforceBlockedError.approval_continuation`
contains the replacement to persist. Ordinary `resume_approval_from` and
`recover_approval_from` preserve the original checked call.

## Secure transport and workload boundary

The customer-hosted SDK keeps its sidecar on the same host. Literal loopback HTTP
is supported for local development; HTTPS loopback URLs use the runtime's normal
TLS certificate and hostname verification. HTTPS already supplies TLS: no extra
encryption layer is added. Configure trust for the sidecar certificate and keep
verification enabled. Redirects are not followed with the adapter credential.
API/provider network calls require verified HTTPS in production. Local HTTP or a
Unix socket is not evidence of production network TLS configuration.

OpenShell can optionally contain a workload the application operator controls.
It does not replace Rail checks or wrap the internals of hosted ChatGPT/Claude.
Build a real protected application with private credentials, an authenticated
caller/resource boundary, durable execution checkpoints and one protected callback.
Keep the reference demo optional; never give an agent an unrestricted alternate
path to the same business credentials.
