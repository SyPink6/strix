"""Attack-chain continuation: finding-driven follow-up directives to the root.

Vanilla strix treats a filed vulnerability report as an output, not a state
change: nothing ever tells the root agent that a confirmed finding may have
changed what the scan can now access (privilege level, authentication state,
data exposure), so chains like "escalate privileges, then use them to reach
previously denied resources" stall at the report step. The measured XBEN-005
baseline is exactly this failure: it confirmed an admin escalation and never
revisited the admin-only surface before wrapping up.

This module watches the single choke point every filed report passes through
(``ReportState.add_vulnerability_report``), flags capability-changing findings
with cheap rules, and queues a one-time continuation directive that the usage
hooks append to the root agent's next LLM turn — the same cache-safe append
channel the budget warnings use, so prompt-prefix caching is preserved. In
``shadow`` mode every trigger and would-be injection is logged without
acting; ``enforce`` injects for real. Rules are deliberately generic (no
task-specific strings); see docs/attack-chain-continuation-design.md for the
calibration evidence and the experiment plan.
"""

from __future__ import annotations

import json
import logging
import re
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal


if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

logger = logging.getLogger(__name__)

ChainMode = Literal["shadow", "enforce"]

# Total directives per scan, first come first served: enough to cover a
# multi-finding run, low enough that a finding storm cannot turn into noise.
DEFAULT_MAX_INJECTIONS = 3

_HIGH_SEVERITIES = frozenset({"critical", "high"})

# Tier-2 gate: a medium finding whose own text says it changes what someone
# can access. Narrow on purpose — the measured false-fire cost is a wasted
# directive, but noise erodes the root agent's trust in [EVENT] messages.
_CAPABILITY_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"privileg",
        r"escalat",
        r"mass.?assign",
        r"\bidors?\b",
        r"insecure direct",
        r"authorization bypass",
        r"authentication bypass",
    )
)


@dataclass(frozen=True)
class _PendingDirective:
    """One queued continuation directive, with the fields needed to log it."""

    message: str
    tier: int
    report_id: str
    severity: str
    title: str
    endpoint: str | None


def _describes_capability_change(report: Mapping[str, Any]) -> bool:
    text = " ".join(
        part
        for part in (report.get("title"), report.get("description"))
        if isinstance(part, str)
    )
    return any(pattern.search(text) for pattern in _CAPABILITY_PATTERNS)


def _trigger_tier(severity: str, report: Mapping[str, Any]) -> int | None:
    """Which rule tier a filed report fires, or ``None`` when it should not."""
    if severity in _HIGH_SEVERITIES:
        return 1
    if severity == "medium" and _describes_capability_change(report):
        return 2
    return None


def _continuation_message(report: Mapping[str, Any]) -> str:
    title = str(report.get("title") or "untitled finding").strip()
    severity = str(report.get("severity") or "unknown").strip()
    endpoint = report.get("endpoint")
    where = f", endpoint: {endpoint}" if isinstance(endpoint, str) and endpoint else ""
    return (
        f'[EVENT] High-impact finding filed: "{title}" (severity: {severity}{where}). '
        "A finding of this kind can change what you can now access, e.g. privilege "
        "level, authentication state, or other users' data. Before this scan wraps "
        "up: (1) work out what new capability the PoC gives you; (2) use it to "
        "re-check resources that were previously inaccessible (401/403 responses, "
        "admin-only or other-user/private areas), including endpoints already "
        "mapped during reconnaissance; (3) chain it into follow-up verification or "
        "exploitation, either yourself or via a focused sub-agent. If nothing new "
        "becomes reachable, record that conclusion in the final report."
    )


class AttackChainContinuation:
    """Queue continuation directives for the root agent when findings land.

    ``on_finding`` is called from ``ReportState.add_vulnerability_report`` for
    every report that is actually filed (updates and deletions do not pass
    through it); qualifying reports enqueue one directive each. The usage
    hooks drain the queue into the root agent's next turn.
    """

    def __init__(
        self,
        *,
        mode: ChainMode,
        decision_log: Path | None = None,
        max_injections: int = DEFAULT_MAX_INJECTIONS,
    ) -> None:
        if mode not in ("shadow", "enforce"):
            raise ValueError(f"unknown chain-continuation mode: {mode!r}")
        if max_injections < 1:
            raise ValueError("max_injections must be at least 1")
        self._mode = mode
        self._decision_log = decision_log
        self._max_injections = max_injections
        self._pending: deque[_PendingDirective] = deque()
        self._seen_report_ids: set[str] = set()
        self._queued = 0

    @property
    def mode(self) -> ChainMode:
        return self._mode

    def on_finding(self, report: Mapping[str, Any]) -> None:
        """Record one filed report; queue a directive when it changes capabilities."""
        if str(report.get("finding_class") or "").lower() == "dependency_cve":
            return  # a known-vulnerable dependency does not change runtime access
        report_id = str(report.get("id") or "")
        if report_id and report_id in self._seen_report_ids:
            return
        severity = str(report.get("severity") or "").lower()
        tier = _trigger_tier(severity, report)
        if tier is None:
            return
        if report_id:
            self._seen_report_ids.add(report_id)
        title = str(report.get("title") or "")
        endpoint = report.get("endpoint")
        endpoint_text = endpoint if isinstance(endpoint, str) and endpoint else None
        record = {
            "tier": tier,
            "report_id": report_id,
            "severity": severity,
            "title": title,
            "endpoint": endpoint_text,
        }
        if self._queued >= self._max_injections:
            self._log("chain_trigger", capped=True, **record)
            return
        self._queued += 1
        self._pending.append(
            _PendingDirective(
                message=_continuation_message(report),
                tier=tier,
                report_id=report_id,
                severity=severity,
                title=title,
                endpoint=endpoint_text,
            )
        )
        self._log("chain_trigger", capped=False, **record)

    def drain_for_root(self) -> list[str]:
        """Pop the queued directives for the root agent's next LLM turn.

        Shadow mode logs every pending directive as a would-be injection and
        returns nothing; enforce returns the messages for real delivery.
        """
        if not self._pending:
            return []
        messages: list[str] = []
        while self._pending:
            directive = self._pending.popleft()
            self._log(
                "chain_injection",
                enforced=self._mode == "enforce",
                agent="root",
                tier=directive.tier,
                report_id=directive.report_id,
                severity=directive.severity,
                title=directive.title,
                endpoint=directive.endpoint,
            )
            if self._mode == "enforce":
                messages.append(directive.message)
        return messages

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
            logger.warning("failed to append attack-chain decision log", exc_info=True)


_global_attack_chain: AttackChainContinuation | None = None


def get_global_attack_chain() -> AttackChainContinuation | None:
    return _global_attack_chain


def set_global_attack_chain(chain: AttackChainContinuation | None) -> None:
    global _global_attack_chain  # noqa: PLW0603
    _global_attack_chain = chain
