"""Mock tests for the adaptive scheduler: spawn admission, agent share, decision log.

No LLM calls are made; every decision input is a literal. The baseline-task
regression test pins the reporting-intent patterns to the real sub-agent
task texts observed in the 2026-10-21 XBEN baseline.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from pathlib import Path

from strix.core.adaptive_scheduler import (
    ActiveChild,
    AdaptiveScheduler,
    running_children,
    task_similarity,
)


# Abridged openings of the 13 real sub-agent tasks observed in the
# 2026-10-21 XBEN baseline (docs/experiments/baseline-xben-2026-10-21.md).
# The reporting-intent rule must single out the one reporting spawn and let
# every specialist/recon task through.
_BASELINE_TASK_OPENINGS = (
    "Perform complete black-box reconnaissance and attack-surface mapping of the target",
    "You are a reporting agent. File a vulnerability report for a CONFIRMED "
    "mass assignment privilege escalation finding",
    "You are an injection testing agent for a black-box assessment of the target",
    "You are a JWT/authentication validation agent for a black-box assessment",
    "You are the infrastructure reconnaissance specialist for a black-box security assessment",
    "You are the web content and attack-surface reconnaissance specialist",
    "You are the SQL injection and auth bypass testing specialist",
    "You are the PHP type juggling and logic-based auth bypass specialist",
    "You are the information disclosure and source code exposure specialist",
    "You are the Cross-Site Scripting (XSS) testing specialist",
    "Black-box reconnaissance and attack-surface mapping of the web application",
    "You are testing the POST /page endpoint for injection vulnerabilities",
    "You are checking the technology stack for known CVEs and misconfigurations",
)
_BASELINE_REPORTING_INDEX = 1


class _FakeCoordinator:
    """Minimal structural stand-in for AgentCoordinator (see CoordinatorSnapshot)."""

    def __init__(
        self,
        statuses: dict[str, str],
        parent_of: dict[str, str | None],
        names: dict[str, str] | None = None,
        metadata: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self.statuses = statuses
        self.parent_of = parent_of
        self.names = names or {}
        self.metadata = metadata or {}


def _children(*specs: tuple[str, str]) -> list[ActiveChild]:
    return [ActiveChild(name=name, task=task) for name, task in specs]


# ---------------------------------------------------------------------------
# Spawn admission: allow path
# ---------------------------------------------------------------------------


def test_normal_spawn_allowed_in_enforce_mode() -> None:
    scheduler = AdaptiveScheduler(mode="enforce", max_budget_usd=1.0)
    decision = scheduler.decide_spawn(
        name="XSS Specialist",
        task="You are the XSS testing specialist for the target",
        active_children=_children(("Recon", "Map the attack surface")),
        task_cost=0.10,
    )
    assert decision.allowed
    assert decision.rule is None


def test_spawn_allowed_without_budget() -> None:
    scheduler = AdaptiveScheduler(mode="enforce")
    decision = scheduler.decide_spawn(
        name="Recon",
        task="Map the attack surface",
        active_children=[],
        task_cost=999.0,
    )
    assert decision.allowed


# ---------------------------------------------------------------------------
# Rule (a): budget floor
# ---------------------------------------------------------------------------


def test_budget_floor_denies_spawn_at_reserve() -> None:
    scheduler = AdaptiveScheduler(mode="enforce", max_budget_usd=1.0)
    decision = scheduler.decide_spawn(
        name="Recon",
        task="Map the attack surface",
        active_children=[],
        task_cost=0.90,
    )
    assert not decision.allowed
    assert decision.rule == "budget_floor"
    assert decision.reason is not None and "reserve" in decision.reason
    assert decision.suggestion is not None


def test_budget_floor_allows_just_below_reserve() -> None:
    scheduler = AdaptiveScheduler(mode="enforce", max_budget_usd=1.0)
    decision = scheduler.decide_spawn(
        name="Recon",
        task="Map the attack surface",
        active_children=[],
        task_cost=0.8999,
    )
    assert decision.allowed


# ---------------------------------------------------------------------------
# Rule (b): reporting-only spawn (baseline regression)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("opening", _BASELINE_TASK_OPENINGS)
def test_reporting_rule_against_baseline_task_openings(opening: str) -> None:
    scheduler = AdaptiveScheduler(mode="enforce", max_budget_usd=1.0)
    decision = scheduler.decide_spawn(
        name="Specialist",
        task=opening,
        active_children=[],
        task_cost=0.10,
    )
    index = _BASELINE_TASK_OPENINGS.index(opening)
    if index == _BASELINE_REPORTING_INDEX:
        assert not decision.allowed
        assert decision.rule == "reporting_spawn"
        assert decision.suggestion is not None and "reporting tool" in decision.suggestion
    else:
        assert decision.allowed, f"false positive on baseline opening #{index}: {opening}"


def test_reporting_rule_ignores_investigation_tasks_that_mention_reports() -> None:
    scheduler = AdaptiveScheduler(mode="enforce", max_budget_usd=1.0)
    decision = scheduler.decide_spawn(
        name="Endpoint Prober",
        task="Probe every endpoint and report any confirmed finding you discover with evidence.",
        active_children=[],
        task_cost=0.10,
    )
    assert decision.allowed


# ---------------------------------------------------------------------------
# Rule (c): near-duplicate task
# ---------------------------------------------------------------------------


def test_duplicate_task_denied() -> None:
    scheduler = AdaptiveScheduler(mode="enforce", max_budget_usd=1.0)
    running = _children(
        (
            "SQLi Specialist",
            (
                "You are the SQL injection testing specialist. Test all parameters on the "
                "target application for SQL injection."
            ),
        )
    )
    decision = scheduler.decide_spawn(
        name="SQLi Specialist 2",
        task=(
            "You are the SQL injection testing specialist. Test every parameter on the "
            "target application for SQL injection."
        ),
        active_children=running,
        task_cost=0.10,
    )
    assert not decision.allowed
    assert decision.rule == "duplicate_task"
    assert decision.reason is not None and "SQLi Specialist" in decision.reason


def test_distinct_task_allowed_alongside_running_children() -> None:
    scheduler = AdaptiveScheduler(mode="enforce", max_budget_usd=1.0)
    running = _children(
        (
            "SQLi Specialist",
            (
                "You are the SQL injection testing specialist. Test all parameters on the "
                "target application for SQL injection."
            ),
        )
    )
    decision = scheduler.decide_spawn(
        name="XSS Specialist",
        task=(
            "You are the Cross-Site Scripting specialist. Audit every reflected input "
            "on the application."
        ),
        active_children=running,
        task_cost=0.10,
    )
    assert decision.allowed


# ---------------------------------------------------------------------------
# Rule (d): concurrency cap
# ---------------------------------------------------------------------------


def test_max_children_denies_spawn_at_cap() -> None:
    scheduler = AdaptiveScheduler(mode="enforce", max_budget_usd=1.0)
    running = _children(
        ("Recon", "Map the network attack surface"),
        ("Web Recon", "Crawl the web application"),
        ("SQLi Specialist", "Test SQL injection"),
        ("XSS Specialist", "Test cross-site scripting"),
    )
    decision = scheduler.decide_spawn(
        name="Auth Specialist",
        task="Audit the authentication flow",
        active_children=running,
        task_cost=0.10,
    )
    assert not decision.allowed
    assert decision.rule == "max_children"
    assert decision.suggestion is not None and "Wait" in decision.suggestion


def test_max_children_custom_cap() -> None:
    scheduler = AdaptiveScheduler(mode="enforce", max_budget_usd=1.0, max_children=2)
    running = _children(("Recon", "Map the network attack surface"), ("Web", "Crawl the app"))
    decision = scheduler.decide_spawn(
        name="SQLi Specialist",
        task="Test SQL injection",
        active_children=running,
        task_cost=0.10,
    )
    assert not decision.allowed
    assert decision.rule == "max_children"


# ---------------------------------------------------------------------------
# Rule precedence and shadow mode
# ---------------------------------------------------------------------------


def test_budget_floor_takes_precedence_over_other_rules() -> None:
    scheduler = AdaptiveScheduler(mode="enforce", max_budget_usd=1.0)
    running = _children(
        ("SQLi Specialist", "You are the SQL injection testing specialist. Test all parameters."),
        ("Recon", "Map the network attack surface"),
        ("Web Recon", "Crawl the web application"),
        ("XSS Specialist", "Test cross-site scripting"),
    )
    decision = scheduler.decide_spawn(
        name="Reporter",
        task="You are a reporting agent. File a vulnerability report for a CONFIRMED finding.",
        active_children=running,
        task_cost=0.95,
    )
    assert not decision.allowed
    assert decision.rule == "budget_floor"


def test_shadow_mode_allows_everything_but_logs() -> None:
    scheduler = AdaptiveScheduler(mode="shadow", max_budget_usd=1.0)
    decision = scheduler.decide_spawn(
        name="Reporter",
        task="You are a reporting agent. File a vulnerability report for a CONFIRMED finding.",
        active_children=[],
        task_cost=0.95,
    )
    assert decision.allowed  # shadow never blocks


# ---------------------------------------------------------------------------
# Per-agent share ceiling
# ---------------------------------------------------------------------------


def test_agent_share_warns_once_per_agent() -> None:
    scheduler = AdaptiveScheduler(mode="enforce", max_budget_usd=1.0, per_agent_share=0.30)
    first = scheduler.check_agent_share(agent_id="child-1", agent_name="Validator", spend=0.30)
    assert first.should_warn
    assert first.message is not None and "budget share" in first.message
    second = scheduler.check_agent_share(agent_id="child-1", agent_name="Validator", spend=0.50)
    assert not second.should_warn  # one directive per agent, not per turn


def test_agent_share_silent_below_ceiling_and_without_budget() -> None:
    below = AdaptiveScheduler(mode="enforce", max_budget_usd=1.0)
    assert not below.check_agent_share(agent_id="a", agent_name=None, spend=0.29).should_warn
    unbudgeted = AdaptiveScheduler(mode="enforce")
    assert not unbudgeted.check_agent_share(agent_id="a", agent_name=None, spend=99.0).should_warn


def test_agent_share_shadow_never_warns() -> None:
    scheduler = AdaptiveScheduler(mode="shadow", max_budget_usd=1.0, per_agent_share=0.30)
    assert not scheduler.check_agent_share(agent_id="a", agent_name=None, spend=0.40).should_warn


def test_agent_share_independent_per_agent() -> None:
    scheduler = AdaptiveScheduler(mode="enforce", max_budget_usd=1.0, per_agent_share=0.30)
    assert scheduler.check_agent_share(agent_id="a", agent_name=None, spend=0.30).should_warn
    assert scheduler.check_agent_share(agent_id="b", agent_name=None, spend=0.30).should_warn


# ---------------------------------------------------------------------------
# Decision log
# ---------------------------------------------------------------------------


def test_decision_log_appends_valid_jsonl(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    scheduler = AdaptiveScheduler(mode="enforce", max_budget_usd=1.0, decision_log=log)
    scheduler.decide_spawn(
        name="Recon", task="Map the attack surface", active_children=[], task_cost=0.95
    )
    scheduler.check_agent_share(agent_id="child-1", agent_name="Validator", spend=0.30)

    lines = log.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    spawn_record, share_record = (json.loads(line) for line in lines)
    assert spawn_record["kind"] == "spawn"
    assert spawn_record["mode"] == "enforce"
    assert spawn_record["rule"] == "budget_floor"
    assert spawn_record["enforced"] is True
    assert "ts" in spawn_record
    assert share_record["kind"] == "agent_share"
    assert share_record["agent_id"] == "child-1"
    assert share_record["ceiling"] == pytest.approx(0.30)


def test_shadow_decision_log_records_would_deny(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    scheduler = AdaptiveScheduler(mode="shadow", max_budget_usd=1.0, decision_log=log)
    decision = scheduler.decide_spawn(
        name="Recon", task="Map the attack surface", active_children=[], task_cost=0.95
    )
    assert decision.allowed
    record = json.loads(log.read_text(encoding="utf-8").strip())
    assert record["rule"] == "budget_floor"
    assert record["enforced"] is False


def test_decision_log_failure_does_not_raise_or_block(tmp_path: Path) -> None:
    blocker = tmp_path / "blocker.txt"
    blocker.write_text("not a directory", encoding="utf-8")
    scheduler = AdaptiveScheduler(
        mode="enforce", max_budget_usd=1.0, decision_log=blocker / "decisions.jsonl"
    )
    decision = scheduler.decide_spawn(
        name="Recon", task="Map the attack surface", active_children=[], task_cost=0.95
    )
    assert not decision.allowed  # the denial still lands even though logging failed


# ---------------------------------------------------------------------------
# Similarity helper
# ---------------------------------------------------------------------------


def test_task_similarity_identical_case_and_whitespace_insensitive() -> None:
    assert task_similarity("Map the attack surface", "map  THE attack\nsurface") == pytest.approx(
        1.0
    )


def test_task_similarity_empty_is_zero() -> None:
    assert task_similarity("", "anything") == 0.0
    assert task_similarity("", "") == 0.0


def test_task_similarity_orders_similar_above_distinct() -> None:
    base = (
        "You are the SQL injection testing specialist. Test all parameters on the "
        "target application for SQL injection."
    )
    typo = (
        "You are the SQL injection testing specialist. Test every parameter on the "
        "target application for SQL injection."
    )
    distinct = "You are the XSS testing specialist. Audit all reflected inputs."
    assert task_similarity(base, typo) > task_similarity(base, distinct)
    assert task_similarity(base, typo) >= 0.80


# ---------------------------------------------------------------------------
# running_children coordinator snapshot
# ---------------------------------------------------------------------------


def test_running_children_filters_stopped_and_root() -> None:
    coordinator = _FakeCoordinator(
        statuses={"root": "running", "c1": "running", "c2": "completed", "c3": "running"},
        parent_of={"root": None, "c1": "root", "c2": "root", "c3": "root"},
        names={"c1": "SQLi Specialist", "c3": "XSS Specialist"},
        metadata={"c1": {"task": "Test SQL injection"}},
    )
    children = running_children(coordinator)
    assert [child.name for child in children] == ["SQLi Specialist", "XSS Specialist"]
    assert children[0].task == "Test SQL injection"
    assert children[1].task == ""  # missing task metadata degrades to empty


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"mode": "off"}, "unknown scheduler mode"),
        ({"mode": "enforce", "max_budget_usd": 0.0}, "positive"),
        ({"mode": "enforce", "max_budget_usd": -1.0}, "positive"),
        ({"mode": "enforce", "per_agent_share": 0.0}, "per_agent_share"),
        ({"mode": "enforce", "per_agent_share": 1.5}, "per_agent_share"),
        ({"mode": "enforce", "max_children": 0}, "max_children"),
        ({"mode": "enforce", "dedup_threshold": 0.0}, "dedup_threshold"),
    ],
)
def test_constructor_rejects_invalid_configuration(kwargs: dict[str, Any], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        AdaptiveScheduler(**kwargs)
