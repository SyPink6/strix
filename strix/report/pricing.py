"""LiteLLM model-name resolution and price overrides for local cost estimates."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from functools import cache, lru_cache
from typing import Any, cast


logger = logging.getLogger(__name__)

# Per-token USD prices: (uncached input, output, cached input).
PriceOverride = tuple[float, float, float]


@lru_cache(maxsize=512)
def resolve_litellm_model(model: str) -> str | None:
    """Return a provider-qualified model name that LiteLLM can price."""
    try:
        import litellm

        normalized = model.strip()
        for prefix in ("litellm/", "any-llm/", "openai/"):
            if normalized.startswith(prefix):
                normalized = normalized.removeprefix(prefix)
                break
        if not normalized:
            return None

        model_cost = cast(
            "dict[str, dict[str, Any]]",
            getattr(litellm, "model_cost"),  # noqa: B009
        )
        bare_entry = model_cost.get(normalized)
        if "/" not in normalized and isinstance(bare_entry, dict):
            provider = bare_entry.get("litellm_provider")
            if isinstance(provider, str) and provider:
                return f"{provider}/{normalized}"
        if "/" in normalized and isinstance(bare_entry, dict):
            return normalized

        names = [normalized]
        if "/" in normalized:
            names.append(normalized.rsplit("/", 1)[-1])
        for name in names:
            matches = sorted(key for key in model_cost if key.endswith(f"/{name}"))
            if not matches:
                continue
            prices = {
                (
                    model_cost[key].get("input_cost_per_token"),
                    model_cost[key].get("output_cost_per_token"),
                )
                for key in matches
                if isinstance(model_cost.get(key), dict)
            }
            if len(matches) == 1 or len(prices) == 1:
                return matches[0]
        return None  # noqa: TRY300
    except Exception:  # noqa: BLE001
        return None


@cache
def _parse_price_overrides(raw: str | None) -> dict[str, PriceOverride]:
    """Parse ``"model=in,out[,cached];..."`` into a model-name → price table.

    ``cached`` prices cached-input reads and defaults to 0 (cached reads free),
    so a two-value entry matches uncached-token accounting. Malformed entries
    are logged and skipped rather than failing the whole table.
    """
    if not raw:
        return {}
    table: dict[str, PriceOverride] = {}
    for chunk in raw.split(";"):
        entry = chunk.strip()
        if not entry:
            continue
        name, sep, spec = entry.partition("=")
        name = name.strip()
        parts = [part.strip() for part in spec.split(",")] if sep else []
        values: list[float] = []
        for part in parts:
            try:
                price = float(part)
            except ValueError:
                values.clear()
                break
            if price < 0:
                values.clear()
                break
            values.append(price)
        if not name or len(values) not in (2, 3):
            logger.warning("Ignoring malformed price override %r", entry)
            continue
        table[name] = (values[0], values[1], values[2] if len(values) == 3 else 0.0)
    return table


def price_override_for(model: str) -> PriceOverride | None:
    """Configured per-token prices for ``model``, or ``None`` when unset.

    Explicit prices outrank the LiteLLM catalog: a bare model name sold by
    several providers at different prices makes ``resolve_litellm_model``
    refuse to guess, silently zeroing cost accounting — and every budget
    limit built on it. ``STRIX_PRICE_OVERRIDES`` is the escape hatch for
    those models. The full provider-qualified name is matched first, then
    the bare name.
    """
    from strix.config.loader import load_settings

    table = _parse_price_overrides(load_settings().pricing.price_overrides)
    if not table:
        return None
    normalized = model.strip()
    for prefix in ("litellm/", "any-llm/", "openai/"):
        if normalized.startswith(prefix):
            normalized = normalized.removeprefix(prefix)
            break
    if normalized in table:
        return table[normalized]
    bare = normalized.rsplit("/", 1)[-1]
    return table.get(bare)


def estimate_cost_with_override(payload: Mapping[str, Any], prices: PriceOverride) -> float:
    """Price one request's usage payload under a configured override.

    Cached input tokens are read from whichever details field the provider
    populated (OpenAI-style nested details or LiteLLM's flat key) and billed
    at the cached rate; the rest of the input at the uncached rate.
    """
    prompt = _token_count(payload.get("prompt_tokens"))
    completion = _token_count(payload.get("completion_tokens"))
    cached = min(_cached_input_tokens(payload), prompt)
    input_price, output_price, cached_price = prices
    return (prompt - cached) * input_price + completion * output_price + cached * cached_price


def _cached_input_tokens(payload: Mapping[str, Any]) -> int:
    for details_key in ("prompt_tokens_details", "input_tokens_details"):
        details = payload.get(details_key)
        if isinstance(details, Mapping):
            cached = _token_count(details.get("cached_tokens"))
            if cached:
                return cached
    for flat_key in ("cache_read_input_tokens", "cached_tokens"):
        cached = _token_count(payload.get(flat_key))
        if cached:
            return cached
    return 0


def _token_count(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0
