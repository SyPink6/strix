"""Tests for the --scheduler / --per-agent-share CLI surface."""

from __future__ import annotations

import importlib
import sys
from types import SimpleNamespace
from typing import Any

import pytest


cli_main: Any = importlib.import_module("strix.interface.main")


def _stub_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(max_local_copy_mb=1024)),
    )


def _parse(argv: list[str], monkeypatch: pytest.MonkeyPatch) -> Any:
    _stub_settings(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["strix", "-t", "https://example.com/", *argv])
    return cli_main.parse_arguments()


def test_scheduler_defaults_to_off(monkeypatch: pytest.MonkeyPatch) -> None:
    args = _parse([], monkeypatch)
    assert args.scheduler == "off"
    assert args.per_agent_share == pytest.approx(0.30)


def test_scheduler_and_share_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    args = _parse(["--scheduler", "shadow", "--per-agent-share", "0.45"], monkeypatch)
    assert args.scheduler == "shadow"
    assert args.per_agent_share == pytest.approx(0.45)


def test_scheduler_enforce_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    args = _parse(["--scheduler", "enforce"], monkeypatch)
    assert args.scheduler == "enforce"


def test_unknown_scheduler_mode_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(SystemExit):
        _parse(["--scheduler", "sometimes"], monkeypatch)


@pytest.mark.parametrize("bad", ["0", "1.5", "-0.1", "abc"])
def test_invalid_share_rejected(bad: str, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(SystemExit):
        _parse(["--per-agent-share", bad], monkeypatch)


def test_share_bounds_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _parse(["--per-agent-share", "1"], monkeypatch).per_agent_share == pytest.approx(1.0)
    assert _parse(["--per-agent-share", "0.01"], monkeypatch).per_agent_share == pytest.approx(0.01)
