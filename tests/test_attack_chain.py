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
