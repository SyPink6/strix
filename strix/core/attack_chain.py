"""Attack-chain continuation: capability-signal-driven directives to the root.

Vanilla strix treats a filed vulnerability report as an output, not a state
change: nothing ever tells the root agent that a confirmed finding may have
changed what the scan can now access (privilege level, authentication state,
data exposure), so chains like "escalate privileges, then use them to reach
previously denied resources" stall at the report step. The measured XBEN-005
baseline is exactly this failure: it confirmed an admin escalation and never
revisited the admin-only surface before wrapping up.

This module watches two choke points for capability-relevant signals:

* ``ReportState.add_vulnerability_report`` — every filed report passes
  through it (:meth:`AttackChainContinuation.on_finding`);
* the coverage ledger's record/update paths — an open ``needs_follow_up``
  thread on a capability-relevant surface is the same signal one step
  earlier (:meth:`AttackChainContinuation.on_coverage`). The no-budget
  XBEN-005 run showed the whole intended chain living and dying in coverage
  records that nothing consumed: the escalation thread was recorded at
  minute 33 and the scan wrapped up 38 minutes later calling the target
  low-to-moderate risk.

Qualifying signals queue a one-time continuation directive that the usage
hooks append to the root agent's next LLM turn — the same cache-safe append
channel the budget warnings use, so prompt-prefix caching is preserved. The
hooks also open a bounded **wrap-up deferral window** after each injection:
while it is open, budget wrap-up warnings are held back (enforced stops are
not), because the measured failure mode is the wrap-up notice outcompeting
the continuation directive for the root's attention on exactly the budget
band where chain work happens. In ``shadow`` mode every trigger and
would-be injection is logged without acting; ``enforce`` injects for real.
Rules are deliberately generic (no task-specific strings); see
docs/attack-chain-continuation-design.md for the calibration evidence and
the experiment record.
"""

from __future__ import annotations

import json
import logging
import re
import threading
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

# Wrap-up deferral: after a directive is delivered, budget wrap-up warnings
# are held back for this fraction of the scan budget, or until the ceiling
# share of the budget is reached, whichever comes first — so chain work has
# a bounded runway. The default ceiling sits deliberately under the vanilla
# 90% sub-agent reserve: warnings resume before the enforced stop, so the
# deferral only reorders pressure, it never removes a safety net.
DEFAULT_WRAPUP_DEFERRAL_WINDOW = 0.20
DEFAULT_WRAPUP_DEFERRAL_CEILING = 0.88

_HIGH_SEVERITIES = frozenset({"critical", "high"})

# Capability gate: text that says a signal changes what someone can access.
# Used for both filed reports (title + description) and coverage threads
# (surface + risk area). Narrow on purpose — the measured false-fire cost is
# a wasted directive, but noise erodes the root agent's trust in [EVENT]
# messages.
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

# The coverage outcome that marks an open thread; every other outcome
# (reported / no_issue_found / ruled_out / not_applicable) is a closed
# surface and cannot change what the scan can reach.
_OPEN_THREAD_OUTCOME = "needs_follow_up"


@dataclass(frozen=True)
class _PendingDirective:
    """One queued continuation directive, with the fields needed to log it."""

    message: str
    source: str  # "report" or "coverage"
    tier: int
    report_id: str
    severity: str
    title: str
    endpoint: str | None


def _text_describes_capability(text: str) -> bool:
    return any(pattern.search(text) for pattern in _CAPABILITY_PATTERNS)


def _describes_capability_change(report: Mapping[str, Any]) -> bool:
    text = " ".join(
        part
        for part in (report.get("title"), report.get("description"))
        if isinstance(part, str)
    )
    return _text_describes_capability(text)


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


def _coverage_message(surface: str, risk_area: str) -> str:
    return (
        f'[EVENT] Open follow-up thread: "{surface}" (risk area: {risk_area}) was '
        f"recorded as {_OPEN_THREAD_OUTCOME} and is still unresolved. Threads like "
        "this often mark exactly the capability change that unlocks previously "
        "inaccessible resources — privilege level, authentication state, or other "
        "users' data. Before this scan wraps up: (1) pick this thread up yourself "
        "or via a focused sub-agent; (2) if it confirms a new capability, use it to "
        "re-check resources that previously returned 401/403, including endpoints "
        "already mapped during reconnaissance; (3) file what you confirm. If it "
        "leads nowhere, resolve the coverage entry and say why in the final report."
    )


class AttackChainContinuation:
    """Queue continuation directives for the root agent when signals land.

    ``on_finding`` is called from ``ReportState.add_vulnerability_report`` for
    every report that is actually filed (updates and deletions do not pass
    through it); ``on_coverage`` is called from the coverage ledger for every
    recorded or updated entry. Qualifying signals enqueue one directive each.
    The usage hooks drain the queue into the root agent's next turn and open
    the wrap-up deferral window.
    """

    def __init__(
        self,
        *,
        mode: ChainMode,
        decision_log: Path | None = None,
        max_injections: int = DEFAULT_MAX_INJECTIONS,
        wrapup_deferral_window: float = DEFAULT_WRAPUP_DEFERRAL_WINDOW,
        wrapup_deferral_ceiling: float = DEFAULT_WRAPUP_DEFERRAL_CEILING,
    ) -> None:
        if mode not in ("shadow", "enforce"):
            raise ValueError(f"unknown chain-continuation mode: {mode!r}")
        if max_injections < 1:
            raise ValueError("max_injections must be at least 1")
        for name, value in (
            ("wrapup_deferral_window", wrapup_deferral_window),
            ("wrapup_deferral_ceiling", wrapup_deferral_ceiling),
        ):
            if not 0 < value <= 1:
                raise ValueError(f"{name} must be in (0, 1]")
        self._mode = mode
        self._decision_log = decision_log
        self._max_injections = max_injections
        self._deferral_window = wrapup_deferral_window
        self._deferral_ceiling = wrapup_deferral_ceiling
        self._pending: deque[_PendingDirective] = deque()
        self._seen_report_ids: set[str] = set()
        self._queued = 0
        # The report path runs on the event loop, the coverage path in worker
        # threads (asyncio.to_thread), and the hooks path on the loop again;
        # one lock keeps the enqueue/cap/drain sequences atomic everywhere.
        self._lock = threading.Lock()
        self._deferral_open_cost: float | None = None
        self._deferral_logged = False

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
        title = str(report.get("title") or "")
        endpoint = report.get("endpoint")
        endpoint_text = endpoint if isinstance(endpoint, str) and endpoint else None
        with self._lock:
            if report_id:
                self._seen_report_ids.add(report_id)
            self._enqueue(
                _PendingDirective(
                    message=_continuation_message(report),
                    source="report",
                    tier=tier,
                    report_id=report_id,
                    severity=severity,
                    title=title,
                    endpoint=endpoint_text,
                ),
                source="report",
                tier=tier,
                report_id=report_id,
                severity=severity,
                title=title,
                endpoint=endpoint_text,
            )

    def on_coverage(self, entry: Mapping[str, Any]) -> None:
        """Record a coverage event; queue a directive for an open capability thread.

        Called from the coverage ledger for both fresh records and outcome
        updates; only ``needs_follow_up`` entries on a capability-relevant
        surface qualify. Threads are a weaker signal than a filed report, so
        they always log as tier 2.
        """
        if str(entry.get("outcome") or "").strip().lower() != _OPEN_THREAD_OUTCOME:
            return
        surface = str(entry.get("surface") or "").strip()
        risk_area = str(entry.get("risk_area") or "").strip()
        if not surface or not _text_describes_capability(f"{surface} {risk_area}"):
            return
        entry_id = str(entry.get("entry_id") or "")
        if entry_id and entry_id in self._seen_report_ids:
            return
        with self._lock:
            if entry_id:
                self._seen_report_ids.add(entry_id)
            self._enqueue(
                _PendingDirective(
                    message=_coverage_message(surface, risk_area),
                    source="coverage",
                    tier=2,
                    report_id=entry_id or f"coverage:{surface}",
                    severity=_OPEN_THREAD_OUTCOME,
                    title=surface,
                    endpoint=None,
                ),
                source="coverage",
                tier=2,
                surface=surface,
                risk_area=risk_area,
                entry_id=entry_id,
            )

    def _enqueue(self, directive: _PendingDirective, **record: Any) -> None:
        """Append one directive, or log it as capped. Callers hold ``_lock``."""
        if self._queued >= self._max_injections:
            self._log("chain_trigger", capped=True, **record)
            return
        self._queued += 1
        self._pending.append(directive)
        self._log("chain_trigger", capped=False, **record)

    def drain_for_root(self) -> list[str]:
        """Pop the queued directives for the root agent's next LLM turn.

        Shadow mode logs every pending directive as a would-be injection and
        returns nothing; enforce returns the messages for real delivery.
        """
        with self._lock:
            if not self._pending:
                return []
            messages: list[str] = []
            while self._pending:
                directive = self._pending.popleft()
                self._log(
                    "chain_injection",
                    enforced=self._mode == "enforce",
                    agent="root",
                    source=directive.source,
                    tier=directive.tier,
                    report_id=directive.report_id,
                    severity=directive.severity,
                    title=directive.title,
                    endpoint=directive.endpoint,
                )
                if self._mode == "enforce":
                    messages.append(directive.message)
            return messages

    # -- wrap-up deferral ---------------------------------------------------

    def open_wrapup_deferral(self, cost: float) -> None:
        """Open (or re-open) the window in which wrap-up warnings are held back.

        Called by the usage hooks right after directives are delivered to the
        root; ``cost`` is the scan's total LLM spend at that moment.
        """
        with self._lock:
            self._deferral_open_cost = cost
            self._deferral_logged = False

    def wrapup_deferral_active(self, *, cost: float, max_budget_usd: float) -> bool:
        """Whether budget wrap-up warnings should be held back at this spend.

        The window runs from the injection cost for ``wrapup_deferral_window``
        of the budget, but never past ``wrapup_deferral_ceiling`` of it — by
        default below the vanilla 90% sub-agent reserve, so warnings resume
        before the enforced stop. The first active evaluation per window is
        logged once so experiments can verify the mechanism fired.
        """
        with self._lock:
            if self._mode != "enforce" or self._deferral_open_cost is None:
                return False
            ceiling = min(
                self._deferral_open_cost + self._deferral_window * max_budget_usd,
                self._deferral_ceiling * max_budget_usd,
            )
            active = cost < ceiling
            if active and not self._deferral_logged:
                self._deferral_logged = True
                self._log(
                    "wrapup_deferral",
                    cost=round(cost, 4),
                    ceiling=round(ceiling, 4),
                    max_budget_usd=max_budget_usd,
                )
            return active

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
