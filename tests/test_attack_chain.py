"""Tests for attack-chain continuation (finding-driven follow-up directives)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest

from strix.core.attack_chain import (
    AttackChainContinuation,
    get_global_attack_chain,
    set_global_attack_chain,
)
from strix.core.hooks import ReportUsageHooks
from strix.report.state import ReportState


if TYPE_CHECKING:
    from pathlib import Path


def _report(
    *,
    report_id: str = "vuln-0001",
    title: str = "Mass Assignment Privilege Escalation on /edit_profile",
    severity: str = "high",
    description: str = "An authenticated user can set is_admin=1 and escalate to admin.",
    finding_class: str = "dynamic",
    endpoint: str | None = "/edit_profile/1",
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "id": report_id,
        "title": title,
        "severity": severity,
        "description": description,
        "finding_class": finding_class,
    }
    if endpoint is not None:
        report["endpoint"] = endpoint
    return report


def _records(log: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in log.read_text(encoding="utf-8").strip().splitlines()]


def _coverage_entry(
    *,
    entry_id: str = "cov-0001",
    surface: str = "POST /edit_profile/{company_id} — is_admin mass assignment",
    risk_area: str = "privilege escalation",
    outcome: str = "needs_follow_up",
) -> dict[str, Any]:
    return {
        "entry_id": entry_id,
        "surface": surface,
        "risk_area": risk_area,
        "outcome": outcome,
    }


# ---------------------------------------------------------------------------
# Trigger rules
# ---------------------------------------------------------------------------


def test_high_severity_fires_tier_one(tmp_path: Path) -> None:
    chain = AttackChainContinuation(mode="enforce", decision_log=tmp_path / "decisions.jsonl")
    chain.on_finding(_report())
    messages = chain.drain_for_root()
    assert len(messages) == 1
    assert "Mass Assignment Privilege Escalation on /edit_profile" in messages[0]
    assert "severity: high" in messages[0]
    assert "endpoint: /edit_profile/1" in messages[0]


def test_critical_severity_fires_tier_one() -> None:
    chain = AttackChainContinuation(mode="enforce")
    chain.on_finding(_report(severity="critical"))
    assert len(chain.drain_for_root()) == 1


def test_medium_with_capability_text_fires_tier_two(tmp_path: Path) -> None:
    # The smoke-run shape: only a medium is filed, but its description names
    # the escalation/IDOR vectors, so the continuation must still fire.
    log = tmp_path / "decisions.jsonl"
    chain = AttackChainContinuation(mode="enforce", decision_log=log)
    chain.on_finding(
        _report(
            title="Unauthenticated API Documentation Exposure",
            severity="medium",
            description=(
                "The spec discloses the mass-assignment vector and the IDOR "
                "vectors on /company/{company_id}/jobs."
            ),
        )
    )
    assert len(chain.drain_for_root()) == 1
    trigger = _records(log)[0]
    assert trigger["kind"] == "chain_trigger"
    assert trigger["tier"] == 2


def test_medium_without_capability_text_does_not_fire(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    chain = AttackChainContinuation(mode="enforce", decision_log=log)
    chain.on_finding(
        _report(
            title="Reflected XSS in search",
            severity="medium",
            description="The q parameter reflects input unencoded into the page.",
        )
    )
    assert chain.drain_for_root() == []
    assert not log.exists()  # nothing fired, so nothing was logged


@pytest.mark.parametrize("severity", ["low", "info", "unknown", ""])
def test_minor_severities_never_fire(severity: str) -> None:
    chain = AttackChainContinuation(mode="enforce")
    chain.on_finding(_report(severity=severity, description="Reflected input."))
    assert chain.drain_for_root() == []


def test_dependency_reports_excluded() -> None:
    # A known-vulnerable dependency version does not change runtime access.
    chain = AttackChainContinuation(mode="enforce")
    chain.on_finding(_report(severity="critical", finding_class="dependency_cve"))
    assert chain.drain_for_root() == []


def test_same_report_id_fires_once() -> None:
    chain = AttackChainContinuation(mode="enforce")
    chain.on_finding(_report())
    chain.on_finding(_report())
    assert len(chain.drain_for_root()) == 1


def test_injection_cap_limits_directives(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    chain = AttackChainContinuation(mode="enforce", decision_log=log)
    for index in range(4):
        chain.on_finding(_report(report_id=f"vuln-000{index + 1}"))
    messages = chain.drain_for_root()
    assert len(messages) == 3  # default cap: first three win
    triggers = [r for r in _records(log) if r["kind"] == "chain_trigger"]
    assert len(triggers) == 4
    assert triggers[-1]["capped"] is True
    assert all(r["capped"] is False for r in triggers[:3])


# ---------------------------------------------------------------------------
# Shadow vs enforce, drain semantics, logging
# ---------------------------------------------------------------------------


def test_shadow_logs_would_inject_but_returns_nothing(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    chain = AttackChainContinuation(mode="shadow", decision_log=log)
    chain.on_finding(_report())
    assert chain.drain_for_root() == []
    records = _records(log)
    assert [r["kind"] for r in records] == ["chain_trigger", "chain_injection"]
    assert records[1]["enforced"] is False


def test_enforce_injection_is_logged(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    chain = AttackChainContinuation(mode="enforce", decision_log=log)
    chain.on_finding(_report())
    assert len(chain.drain_for_root()) == 1
    injection = next(r for r in _records(log) if r["kind"] == "chain_injection")
    assert injection["enforced"] is True
    assert injection["agent"] == "root"
    assert injection["report_id"] == "vuln-0001"
    assert injection["tier"] == 1


def test_drain_empties_the_queue() -> None:
    chain = AttackChainContinuation(mode="enforce")
    chain.on_finding(_report())
    assert len(chain.drain_for_root()) == 1
    assert chain.drain_for_root() == []


def test_message_directs_recheck_of_restricted_resources() -> None:
    chain = AttackChainContinuation(mode="enforce")
    chain.on_finding(_report())
    message = chain.drain_for_root()[0]
    assert message.startswith("[EVENT]")
    assert "401/403" in message
    assert "previously inaccessible" in message
    assert "final report" in message


def test_message_without_endpoint_omits_endpoint_part() -> None:
    chain = AttackChainContinuation(mode="enforce")
    chain.on_finding(_report(endpoint=None))
    message = chain.drain_for_root()[0]
    assert "endpoint:" not in message


def test_log_write_failure_does_not_raise_or_block(tmp_path: Path) -> None:
    blocker = tmp_path / "blocker.txt"
    blocker.write_text("not a directory", encoding="utf-8")
    chain = AttackChainContinuation(mode="enforce", decision_log=blocker / "decisions.jsonl")
    chain.on_finding(_report())  # must not raise despite the unusable log path
    assert len(chain.drain_for_root()) == 1


def test_unknown_mode_rejected() -> None:
    with pytest.raises(ValueError, match="unknown chain-continuation mode"):
        AttackChainContinuation(mode="sometimes")  # type: ignore[arg-type]


def test_non_positive_cap_rejected() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        AttackChainContinuation(mode="enforce", max_injections=0)


# ---------------------------------------------------------------------------
# ReportState wiring: every filed report reaches the tracker
# ---------------------------------------------------------------------------


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.chdir(tmp_path)
    return ReportState(run_name="test-run")


def test_add_vulnerability_report_notifies_tracker(report_state: ReportState) -> None:
    tracker = MagicMock()
    with patch("strix.report.state.get_global_attack_chain", return_value=tracker):
        report_id = report_state.add_vulnerability_report(
            title="Admin bypass", severity="High", description="d", impact="i"
        )
    tracker.on_finding.assert_called_once()
    passed = tracker.on_finding.call_args.args[0]
    assert passed["id"] == report_id
    assert passed["severity"] == "high"  # normalized before the tracker sees it


def test_add_vulnerability_report_without_tracker_is_noop(report_state: ReportState) -> None:
    with patch("strix.report.state.get_global_attack_chain", return_value=None):
        report_state.add_vulnerability_report(title="t", severity="low")


def test_tracker_failure_does_not_break_reporting(report_state: ReportState) -> None:
    tracker = MagicMock()
    tracker.on_finding.side_effect = RuntimeError("boom")
    with patch("strix.report.state.get_global_attack_chain", return_value=tracker):
        report_id = report_state.add_vulnerability_report(title="t", severity="high")
    assert report_id  # the report was still filed and registered


# ---------------------------------------------------------------------------
# Hooks wiring: directives reach the root agent's next turn
# ---------------------------------------------------------------------------


def _chain_context(parent_id: str | None) -> MagicMock:
    ctx: MagicMock = MagicMock()
    ctx.context = {"agent_id": "test-agent", "parent_id": parent_id}
    return ctx


@pytest.mark.asyncio
async def test_root_receives_pending_directive() -> None:
    hooks = ReportUsageHooks(model="test-model")
    chain = AttackChainContinuation(mode="enforce")
    chain.on_finding(_report())
    items: list[Any] = []
    with (
        patch("strix.core.hooks.get_global_adaptive_scheduler", return_value=None),
        patch("strix.core.hooks.get_global_attack_chain", return_value=chain),
    ):
        await hooks.on_llm_start(_chain_context(None), MagicMock(), None, items)
    assert len(items) == 1
    assert items[0]["content"].startswith("[EVENT]")


@pytest.mark.asyncio
async def test_child_never_receives_directive_and_queue_survives() -> None:
    hooks = ReportUsageHooks(model="test-model")
    chain = AttackChainContinuation(mode="enforce")
    chain.on_finding(_report())
    items: list[Any] = []
    with (
        patch("strix.core.hooks.get_global_adaptive_scheduler", return_value=None),
        patch("strix.core.hooks.get_global_attack_chain", return_value=chain),
    ):
        await hooks.on_llm_start(_chain_context("root-1"), MagicMock(), None, items)
    assert items == []
    # The child's turn must not have consumed the queue meant for the root.
    assert len(chain.drain_for_root()) == 1


@pytest.mark.asyncio
async def test_no_tracker_no_injection() -> None:
    hooks = ReportUsageHooks(model="test-model")
    items: list[Any] = []
    with (
        patch("strix.core.hooks.get_global_adaptive_scheduler", return_value=None),
        patch("strix.core.hooks.get_global_attack_chain", return_value=None),
    ):
        await hooks.on_llm_start(_chain_context(None), MagicMock(), None, items)
    assert items == []


def test_global_setter_round_trip() -> None:
    chain = AttackChainContinuation(mode="shadow")
    set_global_attack_chain(chain)
    try:
        assert get_global_attack_chain() is chain
    finally:
        set_global_attack_chain(None)
    assert get_global_attack_chain() is None


# ---------------------------------------------------------------------------
# Coverage trigger: open needs_follow_up threads on capability surfaces
# ---------------------------------------------------------------------------


def test_open_capability_thread_fires(tmp_path: Path) -> None:
    # The run-4 shape: the escalation thread lived in coverage, never in a
    # filed report, and nothing consumed it until the scan wrapped up.
    log = tmp_path / "decisions.jsonl"
    chain = AttackChainContinuation(mode="enforce", decision_log=log)
    chain.on_coverage(_coverage_entry())
    messages = chain.drain_for_root()
    assert len(messages) == 1
    trigger = _records(log)[0]
    assert trigger["kind"] == "chain_trigger"
    assert trigger["source"] == "coverage"
    assert trigger["tier"] == 2
    assert trigger["surface"] == "POST /edit_profile/{company_id} — is_admin mass assignment"
    assert trigger["entry_id"] == "cov-0001"


def test_coverage_message_names_the_thread_and_the_actions() -> None:
    chain = AttackChainContinuation(mode="enforce")
    chain.on_coverage(_coverage_entry())
    message = chain.drain_for_root()[0]
    assert message.startswith("[EVENT]")
    assert "Open follow-up thread" in message
    assert "needs_follow_up" in message
    assert "POST /edit_profile/{company_id}" in message
    assert "401/403" in message
    assert "final report" in message


@pytest.mark.parametrize(
    "outcome", ["reported", "no_issue_found", "ruled_out", "not_applicable"]
)
def test_closed_coverage_outcomes_do_not_fire(outcome: str) -> None:
    # Only an open thread can still change what the scan can reach.
    chain = AttackChainContinuation(mode="enforce")
    chain.on_coverage(_coverage_entry(outcome=outcome))
    assert chain.drain_for_root() == []


def test_non_capability_thread_does_not_fire(tmp_path: Path) -> None:
    # The run-4 counterfactual: most open threads are plain hardening notes.
    log = tmp_path / "decisions.jsonl"
    chain = AttackChainContinuation(mode="enforce", decision_log=log)
    chain.on_coverage(
        _coverage_entry(surface="All routes", risk_area="response security headers")
    )
    assert chain.drain_for_root() == []
    assert not log.exists()  # nothing fired, so nothing was logged


def test_coverage_entry_deduped_by_entry_id() -> None:
    # The ledger re-notifies on every update; the tracker must not re-queue.
    chain = AttackChainContinuation(mode="enforce")
    chain.on_coverage(_coverage_entry())
    chain.on_coverage(_coverage_entry())
    assert len(chain.drain_for_root()) == 1


def test_coverage_shares_the_injection_cap(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    chain = AttackChainContinuation(mode="enforce", decision_log=log)
    for index in range(3):
        chain.on_finding(_report(report_id=f"vuln-000{index + 1}"))
    chain.on_coverage(_coverage_entry())
    assert len(chain.drain_for_root()) == 3  # reports filled the cap first
    trigger = [r for r in _records(log) if r["kind"] == "chain_trigger"][-1]
    assert trigger["source"] == "coverage"
    assert trigger["capped"] is True


# ---------------------------------------------------------------------------
# Wrap-up deferral window
# ---------------------------------------------------------------------------


def test_deferral_holds_wrapup_warnings_inside_the_window() -> None:
    # Run-3 shape: the directive lands at ~$0.74 of a $1.10 budget.
    chain = AttackChainContinuation(mode="enforce")
    chain.open_wrapup_deferral(0.74)
    # window: 0.74 -> min(0.74 + 0.20*1.10, 0.88*1.10) = min(0.96, 0.968) = 0.96
    assert chain.wrapup_deferral_active(cost=0.95, max_budget_usd=1.10) is True
    assert chain.wrapup_deferral_active(cost=0.97, max_budget_usd=1.10) is False


def test_deferral_ceiling_binds_when_injection_is_late() -> None:
    chain = AttackChainContinuation(mode="enforce")
    chain.open_wrapup_deferral(0.85)
    # The window would run to 1.05, but the ceiling caps it at 0.88 — under
    # the vanilla 90% sub-agent reserve, so warnings resume before the stop.
    assert chain.wrapup_deferral_active(cost=0.87, max_budget_usd=1.0) is True
    assert chain.wrapup_deferral_active(cost=0.89, max_budget_usd=1.0) is False


def test_deferral_window_reopens_on_new_injection() -> None:
    chain = AttackChainContinuation(mode="enforce")
    chain.open_wrapup_deferral(0.50)
    assert chain.wrapup_deferral_active(cost=0.72, max_budget_usd=1.0) is False
    chain.open_wrapup_deferral(0.60)
    assert chain.wrapup_deferral_active(cost=0.72, max_budget_usd=1.0) is True


def test_shadow_mode_never_defers() -> None:
    chain = AttackChainContinuation(mode="shadow")
    chain.open_wrapup_deferral(0.50)
    assert chain.wrapup_deferral_active(cost=0.60, max_budget_usd=1.0) is False


def test_no_deferral_before_any_injection() -> None:
    chain = AttackChainContinuation(mode="enforce")
    assert chain.wrapup_deferral_active(cost=0.60, max_budget_usd=1.0) is False


def test_deferral_logged_once_per_window(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    chain = AttackChainContinuation(mode="enforce", decision_log=log)
    chain.open_wrapup_deferral(0.50)
    for _ in range(3):
        chain.wrapup_deferral_active(cost=0.60, max_budget_usd=1.0)
    records = [r for r in _records(log) if r["kind"] == "wrapup_deferral"]
    assert len(records) == 1
    assert records[0]["cost"] == 0.6
    assert records[0]["ceiling"] == 0.7
    chain.open_wrapup_deferral(0.55)  # a new injection re-arms the one-shot log
    chain.wrapup_deferral_active(cost=0.60, max_budget_usd=1.0)
    records = [r for r in _records(log) if r["kind"] == "wrapup_deferral"]
    assert len(records) == 2


@pytest.mark.parametrize(
    ("field", "value"),
    [("wrapup_deferral_window", 0.0), ("wrapup_deferral_ceiling", 1.5)],
)
def test_deferral_parameters_validated(field: str, value: float) -> None:
    with pytest.raises(ValueError, match=field):
        AttackChainContinuation(mode="enforce", **{field: value})  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Hooks wiring: the deferral window and the budget warnings interact correctly
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_budget_warning_held_back_during_deferral_window() -> None:
    hooks = ReportUsageHooks(model="test-model", max_budget_usd=1.0)
    chain = AttackChainContinuation(mode="enforce")
    chain.on_finding(_report())
    report_state = MagicMock()
    report_state.get_total_llm_cost.return_value = 0.75
    with (
        patch("strix.core.hooks.get_global_adaptive_scheduler", return_value=None),
        patch("strix.core.hooks.get_global_attack_chain", return_value=chain),
        patch("strix.core.hooks.get_global_report_state", return_value=report_state),
    ):
        first: list[Any] = []
        await hooks.on_llm_start(_chain_context(None), MagicMock(), None, first)
        # The directive is delivered on this turn; this turn's warning was
        # computed before it and still appears (one-time overlap by design).
        assert any(str(i["content"]).startswith("[EVENT]") for i in first)
        assert any("Scan cost budget" in str(i["content"]) for i in first)
        second: list[Any] = []
        await hooks.on_llm_start(_chain_context(None), MagicMock(), None, second)
        # Inside the window (0.75 -> 0.88 of $1.00) the wrap-up warning is held.
        assert second == []


@pytest.mark.asyncio
async def test_budget_warning_returns_after_deferral_window() -> None:
    hooks = ReportUsageHooks(model="test-model", max_budget_usd=1.0)
    chain = AttackChainContinuation(mode="enforce")
    chain.on_finding(_report())
    report_state = MagicMock()
    report_state.get_total_llm_cost.return_value = 0.60
    with (
        patch("strix.core.hooks.get_global_adaptive_scheduler", return_value=None),
        patch("strix.core.hooks.get_global_attack_chain", return_value=chain),
        patch("strix.core.hooks.get_global_report_state", return_value=report_state),
    ):
        first: list[Any] = []
        await hooks.on_llm_start(_chain_context(None), MagicMock(), None, first)
        # 0.60 is under the first warn band, so this turn carries only the
        # directive — and opens the window at 0.60 (ceiling 0.80).
        assert len(first) == 1
        assert str(first[0]["content"]).startswith("[EVENT]")
        report_state.get_total_llm_cost.return_value = 0.90  # past the ceiling
        second: list[Any] = []
        await hooks.on_llm_start(_chain_context(None), MagicMock(), None, second)
        assert len(second) == 1
        assert "Scan cost budget" in str(second[0]["content"])


@pytest.mark.asyncio
async def test_injection_opens_the_deferral_window() -> None:
    hooks = ReportUsageHooks(model="test-model")
    chain = AttackChainContinuation(mode="enforce")
    chain.on_finding(_report())
    report_state = MagicMock()
    report_state.get_total_llm_cost.return_value = 0.60
    with (
        patch("strix.core.hooks.get_global_adaptive_scheduler", return_value=None),
        patch("strix.core.hooks.get_global_attack_chain", return_value=chain),
        patch("strix.core.hooks.get_global_report_state", return_value=report_state),
    ):
        await hooks.on_llm_start(_chain_context(None), MagicMock(), None, [])
    assert chain.wrapup_deferral_active(cost=0.79, max_budget_usd=1.0) is True
    assert chain.wrapup_deferral_active(cost=0.81, max_budget_usd=1.0) is False


@pytest.mark.asyncio
async def test_budget_warning_flows_without_directives() -> None:
    hooks = ReportUsageHooks(model="test-model", max_budget_usd=1.0)
    chain = AttackChainContinuation(mode="enforce")  # nothing queued
    report_state = MagicMock()
    report_state.get_total_llm_cost.return_value = 0.75
    with (
        patch("strix.core.hooks.get_global_adaptive_scheduler", return_value=None),
        patch("strix.core.hooks.get_global_attack_chain", return_value=chain),
        patch("strix.core.hooks.get_global_report_state", return_value=report_state),
    ):
        items: list[Any] = []
        await hooks.on_llm_start(_chain_context(None), MagicMock(), None, items)
    assert len(items) == 1
    assert "Scan cost budget" in str(items[0]["content"])
