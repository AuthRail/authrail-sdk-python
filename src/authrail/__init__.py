"""AuthRail's Python adapter for a customer-side decision runtime."""

from .contextual import (
    DECISIONS_MODEL,
    DecisionsQuestion,
    new_openai_decisions_extractor,
    openai_decisions_config_sha256,
)
from .discovery import discover
from .enforce import (
    ApprovalContinuation,
    AsyncEnforceClient,
    EnforceBlockedError,
    EnforceOutcomeUnknownError,
    EnforceResult,
    ExecutionContext,
    ExecutionReceipt,
)
from .facts import (
    CustomerReadResult,
    CustomerSource,
    ExtractionResult,
    ExtractionSource,
    extract_context_fact,
    lookup_customer_fact,
    lookup_quickbooks_invoice_balance,
    lookup_stripe_invoice_status,
    new_customer_api_reader,
)
from .guard import GuardHandler
from .observe import AsyncObserveClient
from .types import (
    AuthRailError,
    Decision,
    JSONObject,
    JSONValue,
    Observation,
    ObserveRun,
    Operation,
    PreparedCall,
)

__all__ = [
    "GuardHandler",
    "DECISIONS_MODEL",
    "DecisionsQuestion",
    "new_openai_decisions_extractor",
    "openai_decisions_config_sha256",
    "discover",
    "CustomerSource",
    "CustomerReadResult",
    "ExtractionSource",
    "ExtractionResult",
    "extract_context_fact",
    "lookup_customer_fact",
    "lookup_stripe_invoice_status",
    "lookup_quickbooks_invoice_balance",
    "new_customer_api_reader",
    "ApprovalContinuation",
    "AsyncEnforceClient",
    "EnforceBlockedError",
    "EnforceOutcomeUnknownError",
    "EnforceResult",
    "ExecutionContext",
    "ExecutionReceipt",
    "AsyncObserveClient",
    "AuthRailError",
    "Decision",
    "JSONObject",
    "JSONValue",
    "Observation",
    "ObserveRun",
    "Operation",
    "PreparedCall",
]
