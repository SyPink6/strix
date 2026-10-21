"""Adaptive agent scheduling: spawn admission and per-agent cost ceilings.

Vanilla strix enforces budgets at the scan level — warning bands, a 90%
sub-agent reserve, hard stops — but has no per-agent accountability and no
admission control: every spawn runs unconditionally, and a single agent can
burn a large share of the budget before a turn cap stops it. This module
adds three rule-based layers on top: spawn admission (budget floor,
near-duplicate tasks, reporting-only spawns, a concurrency cap), a per-agent
cost-share ceiling that injects one wrap-up directive, and a JSONL decision
log. In ``shadow`` mode every decision is logged but never enforced; in
``enforce`` mode denials return a structured reason the parent agent can act
on.

Thresholds are calibrated on the measured XBEN baseline and every rule is
deliberately conservative; see docs/adaptive-scheduler-design.md for the
calibration evidence and the ablation experiment plan.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, Protocol


if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

logger = logging.getLogger(__name__)

SchedulerMode = Literal["shadow", "enforce"]

# Calibrated on the 2026-10-21 XBEN baseline (docs/experiments/): 0.30 = the
# share the Injection Validator that maxed out its turn cap consumed of its
# task's cost; 4 = the observed peak of productive parallel children.
DEFAULT_PER_AGENT_SHARE = 0.30
DEFAULT_MAX_CHILDREN = 4
DEFAULT_DEDUP_THRESHOLD = 0.80

# New sub-agents are refused once spend reaches this share of the budget:
# vanilla stops sub-agents there anyway (hooks._SUBAGENT_BUDGET_RESERVE) so
# the root agent can file its final report, so a spawn started past the
# floor would be cut down before finishing useful work.
_BUDGET_FLOOR_SHARE = 0.90

# Matches tasks that exist only to file a report for an already-confirmed
# finding — the parent can call the reporting tool itself instead of paying
# for a fresh (uncached) agent context. Calibrated on the real baseline task
# texts: every non-reporting task matched none of these.
_REPORTING_TASK_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\byou are (?:a |an |the )?(?:\w+ ){0,2}reporting agent\b",
        r"\bfile (?:a|the) (?:\w+ ){0,2}(?:vulnerability|security|finding) report\b",
        r"\breport (?:a|the|this) (?:confirmed|documented|above) finding\b",
    )
)


@dataclass(frozen=True)
class ActiveChild:
    """A currently-running child agent, as seen by the admission rules."""

    name: str
    task: str


class CoordinatorSnapshot(Protocol):
    """Structural subset of ``AgentCoordinator`` the scheduler reads.

    Members are declared as read-only properties so implementations with the
    concrete mutable types (``dict[str, Status]`` etc.) satisfy the protocol.
    """

    @property
    def statuses(self) -> Mapping[str, str]: ...

    @property
    def parent_of(self) -> Mapping[str, str | None]: ...

    @property
    def names(self) -> Mapping[str, str]: ...

    @property
    def metadata(self) -> Mapping[str, Mapping[str, Any]]: ...


@dataclass(frozen=True)
class SpawnDecision:
    """Admission verdict for one spawn request."""

    allowed: bool
    rule: str | None = None
    reason: str | None = None
    suggestion: str | None = None


@dataclass(frozen=True)
class AgentShareDecision:
    """Verdict of the per-agent cost-share ceiling."""

    should_warn: bool = False
    message: str | None = None


def running_children(coordinator: CoordinatorSnapshot) -> list[ActiveChild]:
    """Snapshot the child agents currently running under any parent."""
    children: list[ActiveChild] = []
    for agent_id, status in coordinator.statuses.items():
        if status != "running":
            continue
        if coordinator.parent_of.get(agent_id) is None:
            continue  # the root agent is not a child
        task = coordinator.metadata.get(agent_id, {}).get("task")
        children.append(
            ActiveChild(
                name=coordinator.names.get(agent_id, agent_id),
                task=task if isinstance(task, str) else "",
            )
        )
    return children


def task_similarity(a: str, b: str) -> float:
    """Trigram Jaccard similarity in [0, 1]; 0 when either text is empty."""
    trigrams_a = _trigrams(a)
    trigrams_b = _trigrams(b)
    if not trigrams_a or not trigrams_b:
        return 0.0
    return len(trigrams_a & trigrams_b) / len(trigrams_a | trigrams_b)


def _trigrams(text: str) -> set[str]:
    normalized = " ".join(text.lower().split())
    if len(normalized) < 3:
        return {normalized} if normalized else set()
    return {normalized[i : i + 3] for i in range(len(normalized) - 2)}


def _is_reporting_task(task: str) -> bool:
    return any(pattern.search(task) for pattern in _REPORTING_TASK_PATTERNS)


class AdaptiveScheduler:
    """Rule-based spawn admission and per-agent budget-share ceilings.

    ``max_budget_usd`` is the scan's ``--max-budget``; without it the budget
    floor and share rules are inert and only the dedup and concurrency rules
    can fire. Every decision — enforced or shadowed — appends to the JSONL
    decision log when one is configured.
    """

    def __init__(
        self,
        *,
        mode: SchedulerMode,
        max_budget_usd: float | None = None,
        per_agent_share: float = DEFAULT_PER_AGENT_SHARE,
        max_children: int = DEFAULT_MAX_CHILDREN,
        dedup_threshold: float = DEFAULT_DEDUP_THRESHOLD,
        decision_log: Path | None = None,
    ) -> None:
        if mode not in ("shadow", "enforce"):
            raise ValueError(f"unknown scheduler mode: {mode!r}")
        if max_budget_usd is not None and max_budget_usd <= 0:
            raise ValueError("max_budget_usd must be positive")
        if not 0 < per_agent_share <= 1:
            raise ValueError("per_agent_share must be in (0, 1]")
        if max_children < 1:
            raise ValueError("max_children must be at least 1")
        if not 0 < dedup_threshold <= 1:
            raise ValueError("dedup_threshold must be in (0, 1]")
        self._mode = mode
        self._max_budget_usd = max_budget_usd
        self._per_agent_share = per_agent_share
        self._max_children = max_children
        self._dedup_threshold = dedup_threshold
        self._decision_log = decision_log
        self._warned_agents: set[str] = set()

    @property
    def mode(self) -> SchedulerMode:
        return self._mode

    def decide_spawn(
        self,
        *,
        name: str,
        task: str,
        active_children: Sequence[ActiveChild],
        task_cost: float,
    ) -> SpawnDecision:
        """Admission decision for one spawn request.

        Rules are checked in order of decisiveness: budget floor,
        reporting-only task, near-duplicate of a running child, concurrency
        cap. In shadow mode the verdict is logged but the spawn is allowed.
        """
        denial = self._evaluate_spawn_rules(task, active_children, task_cost)
        if denial is None:
            return SpawnDecision(allowed=True)
        if self._mode == "shadow":
            self._log(
                "spawn",
                rule=denial.rule,
                name=name,
                spend=round(task_cost, 6),
                reason=denial.reason,
                enforced=False,
            )
            return SpawnDecision(allowed=True)
        self._log(
            "spawn",
            rule=denial.rule,
            name=name,
            spend=round(task_cost, 6),
            reason=denial.reason,
            enforced=True,
        )
        return denial

    def _evaluate_spawn_rules(
        self,
        task: str,
        active_children: Sequence[ActiveChild],
        task_cost: float,
    ) -> SpawnDecision | None:
        budget = self._max_budget_usd
        if budget is not None:
            floor = budget * _BUDGET_FLOOR_SHARE
            if task_cost >= floor:
                pct = round(_BUDGET_FLOOR_SHARE * 100)
                return SpawnDecision(
                    allowed=False,
                    rule="budget_floor",
                    reason=(
                        f"Scan cost ${task_cost:.4f} has reached the {pct}% sub-agent reserve "
                        f"of the ${budget:.2f} budget; a new sub-agent would be stopped "
                        "before finishing useful work."
                    ),
                    suggestion=(
                        "Finish the scan with the agents already running and file your "
                        "report; the remaining budget is reserved for the root agent's "
                        "wrap-up."
                    ),
                )
        if _is_reporting_task(task):
            return SpawnDecision(
                allowed=False,
                rule="reporting_spawn",
                reason=(
                    "This task only files a report for a finding that is already "
                    "confirmed, which does not need a fresh agent context."
                ),
                suggestion=(
                    "Call the vulnerability reporting tool directly from your current "
                    "context instead of spawning a dedicated reporting agent."
                ),
            )
        for child in active_children:
            similarity = task_similarity(task, child.task)
            if similarity >= self._dedup_threshold:
                return SpawnDecision(
                    allowed=False,
                    rule="duplicate_task",
                    reason=(
                        f"This task near-duplicates the running sub-agent '{child.name}' "
                        f"(similarity {similarity:.2f} >= {self._dedup_threshold:.2f})."
                    ),
                    suggestion=(
                        "Assign a different objective, or wait for that sub-agent's "
                        "result instead of duplicating its work."
                    ),
                )
        if len(active_children) >= self._max_children:
            return SpawnDecision(
                allowed=False,
                rule="max_children",
                reason=(
                    f"{len(active_children)} sub-agents are already running "
                    f"(concurrency cap {self._max_children})."
                ),
                suggestion="Wait for a running sub-agent to finish before spawning another.",
            )
        return None

    def check_agent_share(
        self,
        *,
        agent_id: str,
        agent_name: str | None,
        spend: float,
    ) -> AgentShareDecision:
        """One-time wrap-up directive once an agent passes its cost ceiling."""
        budget = self._max_budget_usd
        if budget is None:
            return AgentShareDecision()
        ceiling = budget * self._per_agent_share
        if spend < ceiling or agent_id in self._warned_agents:
            return AgentShareDecision()
        self._warned_agents.add(agent_id)
        self._log(
            "agent_share",
            agent_id=agent_id,
            agent_name=agent_name,
            spend=round(spend, 6),
            ceiling=round(ceiling, 6),
            enforced=self._mode == "enforce",
        )
        if self._mode == "shadow":
            return AgentShareDecision()
        pct = round(self._per_agent_share * 100)
        message = (
            f"[NOTICE] Agent budget share: this agent has spent ${spend:.4f}, reaching "
            f"its {pct}% share of the ${budget:.2f} scan budget. Wrap up the current line "
            "of investigation, report what you have found, and finish: the remaining "
            "budget is needed by the rest of the scan."
        )
        return AgentShareDecision(should_warn=True, message=message)

    def _log(self, kind: str, **fields: Any) -> None:
        if self._decision_log is None:
            return
        record = {
            "ts": datetime.now(UTC).isoformat(),
            "kind": kind,
            "mode": self._mode,
            **fields,
        }
        try:
            with self._decision_log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            logger.warning("failed to append scheduler decision log", exc_info=True)


_global_scheduler: AdaptiveScheduler | None = None


def get_global_adaptive_scheduler() -> AdaptiveScheduler | None:
    return _global_scheduler


def set_global_adaptive_scheduler(scheduler: AdaptiveScheduler | None) -> None:
    global _global_scheduler  # noqa: PLW0603
    _global_scheduler = scheduler
