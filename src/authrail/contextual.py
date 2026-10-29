"""OpenAI Decisions supplies contextual facts; published Rails retain decision authority."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Literal

import httpx

from ._http import provider_json, valid_secret
from ._protocol import canonical, snapshot
from .facts import ExtractionResult, ExtractionSource, Extractor
from .types import AuthRailError, JSONObject, JSONValue

DECISIONS_MODEL = "gpt-6-luna"
_ENDPOINT = "https://api.openai.com/v1/decisions"


@dataclass(frozen=True, kw_only=True)
class DecisionsQuestion:
    """One reviewed predicate, category choice or rubric score with an uncertainty boundary."""

    type: Literal["predicate", "choice", "score"]
    instructions: str
    min_confidence: float
    choices: tuple[str, ...] = ()
    levels: tuple[str, ...] = ()


def openai_decisions_config_sha256(question: DecisionsQuestion) -> str:
    """Pin exact model/question/settings bytes in the reviewed source, as in the Go SDK."""
    if (
        question.type not in ("predicate", "choice", "score")
        or type(question.instructions) is not str
        or not question.instructions.strip()
        or len(question.instructions.encode()) > 2048
        or type(question.min_confidence) not in (int, float)
        or not math.isfinite(question.min_confidence)
        or not 0.5 <= question.min_confidence <= 1
    ):
        raise AuthRailError("Invalid contextual question")
    entries = question.choices if question.type == "choice" else question.levels
    if question.type == "predicate":
        if question.choices or question.levels:
            raise AuthRailError("Predicate questions cannot specify choices or levels")
    elif (
        not 2 <= len(entries) <= 16
        or len(set(entries)) != len(entries)
        or any(
            type(entry) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,79}", entry)
            for entry in entries
        )
        or (question.type == "choice" and question.levels)
        or (question.type == "score" and question.choices)
    ):
        raise AuthRailError("Invalid contextual answer options")
    config: JSONObject = {
        "model": DECISIONS_MODEL,
        "type": question.type,
        "instructions": question.instructions,
    }
    if question.type != "predicate":
        config["entries"] = list(entries)
    config["minConfidence"] = question.min_confidence
    return hashlib.sha256(canonical(config, ordered=True).encode()).hexdigest()


def _node_config_sha256(question: DecisionsQuestion) -> str:
    # Existing Node sources hash JSON.stringify bytes; Go sources escape HTML.
    # Both encodings below represent exactly the same validated question/settings.
    config: JSONObject = {
        "model": DECISIONS_MODEL,
        "type": question.type,
        "instructions": question.instructions,
    }
    if question.type != "predicate":
        config["entries"] = list(question.choices if question.type == "choice" else question.levels)
    config["minConfidence"] = (
        int(question.min_confidence) if question.min_confidence == 1 else question.min_confidence
    )
    encoded = json.dumps(config, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def _probability(value: JSONValue) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
        and 0 <= value <= 1
    )


def new_openai_decisions_extractor(
    *,
    source: ExtractionSource,
    question: DecisionsQuestion,
    api_key: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> Extractor:
    """Send selected bytes using the customer's OpenAI key; no automatic redaction."""
    digest = openai_decisions_config_sha256(question)
    if (
        source.model_id != DECISIONS_MODEL
        or source.model_config_sha256 not in (digest, _node_config_sha256(question))
        or not source.prompt_version
        or not valid_secret(api_key)
        or not 1 <= source.max_input_bytes <= 65536
        or not 1 <= source.max_output_bytes <= 4096
        or not 100 <= source.timeout_ms <= 10_000
        or source.value_type
        != {"predicate": "boolean", "choice": "string", "score": "number"}[question.type]
    ):
        raise AuthRailError("Invalid OpenAI contextual configuration")
    api_question: JSONObject = {
        "type": question.type,
        "name": "fact",
        "instructions": question.instructions,
    }
    if question.type == "choice":
        api_question["choices"] = [{"value": entry} for entry in question.choices]
    if question.type == "score":
        api_question["levels"] = [{"label": entry} for entry in question.levels]

    async def extract(document: bytes) -> ExtractionResult:
        try:
            if type(document) is not bytes or not 1 <= len(document) <= source.max_input_bytes:
                raise AuthRailError("Invalid contextual source bytes")
            text = document.decode("utf-8", errors="strict")
            async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
                value = await provider_json(
                    client,
                    "POST",
                    _ENDPOINT,
                    {"Authorization": "Bearer " + api_key, "Content-Type": "application/json"},
                    body=snapshot(
                        {"model": DECISIONS_MODEL, "input": text, "questions": [api_question]}
                    ),
                    limit=16 * 1024,
                    seconds=source.timeout_ms / 1000,
                )
            result, uncertain = _answer(value, question)
            return ExtractionResult(
                value=result,
                uncertain=uncertain,
                model_id=DECISIONS_MODEL,
                model_config_sha256=source.model_config_sha256,
                prompt_version=source.prompt_version,
            )
        except Exception:
            raise AuthRailError("Contextual model unavailable or invalid") from None

    return extract


def _answer(value: JSONObject, question: DecisionsQuestion) -> tuple[JSONValue, bool]:
    answers = value.get("answers")
    if (
        value.get("model") != DECISIONS_MODEL
        or type(answers) is not list
        or len(answers) != 1
        or type(answers[0]) is not dict
        or answers[0].get("name") != "fact"
    ):
        raise AuthRailError("Invalid contextual answer")
    answer = answers[0]
    if answer.get("type") == "refusal":
        return None, True
    if answer.get("type") != question.type:
        raise AuthRailError("Contextual answer type mismatch")
    if question.type == "predicate":
        probability = answer.get("probability")
        if not _probability(probability):
            raise AuthRailError("Invalid contextual probability")
        if isinstance(probability, (int, float)) and probability >= question.min_confidence:
            return True, False
        if isinstance(probability, (int, float)) and probability <= 1 - question.min_confidence:
            return False, False
        return None, True
    confidence = answer.get("confidence")
    if not _probability(confidence):
        raise AuthRailError("Invalid contextual confidence")
    confident = isinstance(confidence, (int, float)) and confidence >= question.min_confidence
    if question.type == "choice":
        choice = answer.get("choice")
        if type(choice) is not str or choice not in question.choices:
            raise AuthRailError("Invalid contextual choice")
        return (choice, False) if confident else (None, True)
    score = answer.get("score")
    if (
        type(score) not in (int, float)
        or not isinstance(score, (int, float))
        or not math.isfinite(score)
        or not 0 <= score <= len(question.levels) - 1
    ):
        raise AuthRailError("Invalid contextual score")
    return (score, False) if confident else (None, True)
