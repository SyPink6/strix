from __future__ import annotations

from unittest.mock import patch

import litellm
import pytest
from agents.usage import Usage
from openai.types.responses.response_usage import InputTokensDetails

from strix.config.settings import PricingSettings, Settings
from strix.report.pricing import price_override_for, resolve_litellm_model
from strix.report.usage import LLMUsageLedger


def _settings_with_overrides(raw: str | None) -> Settings:
    return Settings(pricing=PricingSettings(price_overrides=raw))


def test_resolves_common_bare_model_names() -> None:
    resolve_litellm_model.cache_clear()
    assert resolve_litellm_model("deepseek-v4-flash") == "deepseek/deepseek-v4-flash"
    assert resolve_litellm_model("openai/deepseek-v4-flash") == "deepseek/deepseek-v4-flash"
    # LiteLLM prices grok-4.5 identically under xai/, perplexity/xai/ and
    # openrouter/x-ai/, so the resolver may return any of them; the contract
    # is a provider-qualified name LiteLLM can price.
    grok = resolve_litellm_model("grok-4.5")
    assert grok is not None
    assert grok.endswith("/grok-4.5")
    assert grok in litellm.model_cost
    # MiniMax-M3 is sold by several LiteLLM providers at different prices, so
    # the resolver must not guess from its bare name. A provider-qualified
    # model remains deterministic.
    assert resolve_litellm_model("minimax/MiniMax-M3") == "minimax/MiniMax-M3"


def test_resolver_returns_none_for_unresolvable_model() -> None:
    resolve_litellm_model.cache_clear()
    assert resolve_litellm_model("provider/not-a-real-model") is None


def test_ledger_uses_estimate_when_routed_provider_reports_no_cost() -> None:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = 1000
    usage.output_tokens = 200
    usage.total_tokens = 1200
    ledger = LLMUsageLedger()

    with patch("litellm.completion_cost", return_value=0.42):
        ledger.record(agent_id="a", usage=usage, model="openai/deepseek-v4-flash")

    assert ledger.total_cost == 0.42


def test_ledger_prefers_observed_cost_over_estimate() -> None:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = 1000
    usage.output_tokens = 200
    usage.total_tokens = 1200
    ledger = LLMUsageLedger()

    with patch("litellm.completion_cost", return_value=0.42):
        ledger.record(agent_id="a", usage=usage, model="openai/deepseek-v4-flash")
    ledger.record_observed_cost(0.17)

    assert ledger.total_cost == 0.17


def test_hydrated_estimate_continues_accumulating_new_estimates() -> None:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = 1000
    usage.output_tokens = 200
    usage.total_tokens = 1200
    ledger = LLMUsageLedger()
    ledger.hydrate({"cost": 0.42})

    with patch("litellm.completion_cost", return_value=0.17):
        ledger.record(agent_id="a", usage=usage, model="openai/deepseek-v4-flash")

    assert ledger.total_cost == 0.59


def test_zero_cost_disables_both_observed_and_estimated_costs() -> None:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = 1000
    usage.output_tokens = 200
    usage.total_tokens = 1200
    ledger = LLMUsageLedger()
    ledger.zero_cost = True

    with patch("litellm.completion_cost", return_value=0.42) as estimate:
        ledger.record(agent_id="a", usage=usage, model="deepseek-v4-flash")
        ledger.record_observed_cost(1.0)

    estimate.assert_not_called()
    assert ledger.total_cost == 0.0


def test_resolver_uses_provider_when_bare_entry_has_one() -> None:
    original = litellm.model_cost
    litellm.model_cost = {
        "example": {
            "litellm_provider": "example-provider",
            "input_cost_per_token": 1.0,
            "output_cost_per_token": 2.0,
        }
    }
    try:
        resolve_litellm_model.cache_clear()
        assert resolve_litellm_model("example") == "example-provider/example"
    finally:
        litellm.model_cost = original
        resolve_litellm_model.cache_clear()


def test_resolver_does_not_guess_between_differently_priced_providers() -> None:
    original = litellm.model_cost
    litellm.model_cost = {
        "provider-a/example": {
            "input_cost_per_token": 1.0,
            "output_cost_per_token": 2.0,
        },
        "provider-b/example": {
            "input_cost_per_token": 3.0,
            "output_cost_per_token": 4.0,
        },
    }
    try:
        resolve_litellm_model.cache_clear()
        assert resolve_litellm_model("example") is None
    finally:
        litellm.model_cost = original
        resolve_litellm_model.cache_clear()


def test_price_override_matches_prefixed_full_and_bare_model_names() -> None:
    with patch(
        "strix.config.loader.load_settings",
        return_value=_settings_with_overrides("alibaba/glm-5.2=1.4e-6,4.4e-6"),
    ):
        assert price_override_for("openai/alibaba/glm-5.2") == (1.4e-6, 4.4e-6, 0.0)
        assert price_override_for("alibaba/glm-5.2") == (1.4e-6, 4.4e-6, 0.0)

    # A bare-name entry matches any provider-qualified form of the same model.
    with patch(
        "strix.config.loader.load_settings",
        return_value=_settings_with_overrides("glm-5.2=1e-6,2e-6,0.1e-6"),
    ):
        assert price_override_for("openai/alibaba/glm-5.2") == (1e-6, 2e-6, 0.1e-6)


def test_price_override_returns_none_when_unset_or_unmatched() -> None:
    with patch(
        "strix.config.loader.load_settings",
        return_value=_settings_with_overrides(None),
    ):
        assert price_override_for("alibaba/glm-5.2") is None
    with patch(
        "strix.config.loader.load_settings",
        return_value=_settings_with_overrides("alibaba/glm-5.2=1.4e-6,4.4e-6"),
    ):
        assert price_override_for("provider/other-model") is None


def test_price_override_skips_malformed_entries() -> None:
    raw = "not-an-override;glm-5.2=1e-6,2e-6;bad=1;neg=-1,2;toomany=1,2,3,4"
    with patch(
        "strix.config.loader.load_settings",
        return_value=_settings_with_overrides(raw),
    ):
        assert price_override_for("glm-5.2") == (1e-6, 2e-6, 0.0)
        assert price_override_for("bad") is None
        assert price_override_for("neg") is None
        assert price_override_for("toomany") is None


def test_ledger_prices_model_via_override_without_consulting_catalog() -> None:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = 1000
    usage.output_tokens = 200
    usage.total_tokens = 1200
    ledger = LLMUsageLedger()

    with (
        patch("litellm.completion_cost", return_value=0.42) as catalog,
        patch(
            "strix.config.loader.load_settings",
            return_value=_settings_with_overrides("alibaba/glm-5.2=1.4e-6,4.4e-6"),
        ),
    ):
        ledger.record(agent_id="a", usage=usage, model="openai/alibaba/glm-5.2")

    catalog.assert_not_called()
    assert ledger.total_cost == pytest.approx(1000 * 1.4e-6 + 200 * 4.4e-6)


def test_ledger_override_prices_cached_input_at_cached_rate() -> None:
    usage = Usage()
    usage.add(
        Usage(
            requests=1,
            input_tokens=1000,
            output_tokens=200,
            total_tokens=1200,
            input_tokens_details=InputTokensDetails(cached_tokens=800, cache_write_tokens=0),
        )
    )
    ledger = LLMUsageLedger()

    with patch(
        "strix.config.loader.load_settings",
        return_value=_settings_with_overrides("alibaba/glm-5.2=1.4e-6,4.4e-6,0.14e-6"),
    ):
        ledger.record(agent_id="a", usage=usage, model="openai/alibaba/glm-5.2")

    assert ledger.total_cost == pytest.approx(200 * 1.4e-6 + 800 * 0.14e-6 + 200 * 4.4e-6)


def test_ledger_stays_unpriced_for_ambiguous_model_without_override() -> None:
    original = litellm.model_cost
    litellm.model_cost = {
        "provider-a/example": {
            "input_cost_per_token": 1.0,
            "output_cost_per_token": 2.0,
        },
        "provider-b/example": {
            "input_cost_per_token": 3.0,
            "output_cost_per_token": 4.0,
        },
    }
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = 1000
    usage.output_tokens = 200
    usage.total_tokens = 1200
    ledger = LLMUsageLedger()
    try:
        resolve_litellm_model.cache_clear()
        with patch(
            "strix.config.loader.load_settings",
            return_value=_settings_with_overrides(None),
        ):
            ledger.record(agent_id="a", usage=usage, model="example")
    finally:
        litellm.model_cost = original
        resolve_litellm_model.cache_clear()

    assert ledger.total_cost == 0.0
