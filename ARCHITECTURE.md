# Python Runtime adapter

The application owns business functions, provider credentials, authenticated
caller/resource lookup and saved workflow state. The SDK signs checks and applies
the sidecar's decisions around those functions. The customer-side Go sidecar owns
rule evaluation and durable report delivery; the AuthRail server owns reviewed
configuration, approvals and retained records. Python does not contain another
policy engine.

## Observe and Enforce

The public API uses asyncio. A normal command-line application can call it through
`asyncio.run`; an async server keeps one client for its application lifetime.

Observe starts the call check independently of the callback. It preserves the
callback's result, exception and cancellation. Result evaluation follows the
call check and uses the original prepared context. Invalid context and delivery
failure are advisory errors, not permission decisions or callback replacements.

Enforce requires evaluated, retained, non-replayed permission and an acknowledged
fresh execution start before invoking the callback. A queued decision cannot
authorize an effect. The result is withheld until its own check passes for the
same Action. Application credentials and alternate tool routes must remain
outside the agent's reach; a local checker cannot close an unrelated bypass.

## Signing and snapshots

Arguments and result objects are bounded at64KiB; context and responses at128KiB.
Input snapshots detach mutable caller objects. Signatures use the same ordered
statements, sorted JSON maps, HTML escaping and number notation as the Go
sidecar. Non-finite values and unsafe Python integers are rejected rather than
silently changing signed values. Executor proofs bind deployment, phase, exact
input, caller attribution and request/business identity. Trace context only
correlates diagnostics.

## Approval and uncertain effects

Approval continuations retain the exact call and decision. The application must
encrypt and tenant-scope them in persistent storage, alongside its workflow state.
Resume claims a one-use permit. Recovery after a lost claim response reads only
an existing permit. Neither path replaces the original arguments or schedules an
agent session. The execution-start acknowledgement still gates the callback.

The callback receives a stable provider idempotency key and recovery identity.
It must persist these before making a provider request. Callback errors,
cancellation during execution and missing completion acknowledgements produce an
unknown outcome. Reconciliation records a provider-confirmed result with the
original identity and never invokes the business function again.

## Guard processing and facts

Guard processing is explicitly registered on Enforce clients. An exact sidecar
plan selects pure, versioned string handlers and exact targets. Unsupported
isolation, missing handlers, overlapping paths, oversized output or a changed
bundle stop the boundary. Processing evidence is signed with the resulting input.
Cancellation-resistant readers/handlers cannot turn a late answer into permission;
application callbacks must still cooperate with cancellation and avoid effects.

Provider and application fact readers perform bounded reads. They verify the
reviewed account/resource identity and report unavailable or untrusted values
without inventing zero balances or passing booleans. The sidecar applies the
reviewed source's freshness requirements. A lookup result alone is not permission.

Contextual extraction sends only application-selected bytes to the configured
model provider using the customer's credential. It does not redact automatically.
Typed answers, uncertainty and bounded provenance go into the signed fact; raw
source bytes and credentials do not. The first model client pins OpenAI Decisions
and GPT-6 Luna. Published Rails determine the outcome.

The Python settings fingerprint matches Go's JSON encoding. The extractor also
recognises existing Node JSON.stringify fingerprints for the exact same validated
question/settings. This handles HTML/line-separator escaping differences without
accepting a different question, model, threshold or output shape.

## Transport and verification

Local clients accept literal loopback HTTP origins only, ignore environment
proxies and do not follow redirects. Provider helpers use fixed reviewed HTTPS
destinations and bounded responses. Safe errors omit credentials, source text and
raw provider bodies. Discovery keys resolve setup identity only.

Conformance fixtures compare canonical input and an existing Go executor proof.
Transport tests verify execution/approval gates and failure behavior. The isolated
Go helper exercises the real sidecar handler with disposable signed rules and
state, including queued reporting. It does not stand in for tenant-backed
approval/payment E2E or independent provider verification. Package publication,
supported-version runtime checks and founder acceptance remain separate gates.
