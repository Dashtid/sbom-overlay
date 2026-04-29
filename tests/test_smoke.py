from pathlib import Path

import pytest
from click.testing import CliRunner

from sbom_overlay import __version__
from sbom_overlay.cli import cli
from sbom_overlay.parsers import cyclonedx
from sbom_overlay.parsers.model import Component
from sbom_overlay.reconcile.diff import Reconciliation, reconcile
from sbom_overlay.support.log import get_logger, setup_logging, strip_ansi


def test_version_flag() -> None:
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_reconcile_not_implemented(tmp_path: Path) -> None:
    manual = tmp_path / "manual.spdx.json"
    syft = tmp_path / "syft.cdx.json"
    manual.write_text("{}", encoding="utf-8")
    syft.write_text("{}", encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        ["-v", "reconcile", "--manual", str(manual), "--syft", str(syft), "--name", "demo-1.0.0"],
    )
    assert result.exit_code == 1
    assert "not implemented" in result.output


def test_component_dataclass_defaults() -> None:
    c = Component(name="openssl", version="3.0.0", source="manual")
    assert c.purl is None
    assert c.license is None


def test_cyclonedx_parser_stub(tmp_path: Path) -> None:
    with pytest.raises(NotImplementedError):
        cyclonedx.load(tmp_path / "x.cdx.json")


def test_reconcile_stub() -> None:
    with pytest.raises(NotImplementedError):
        reconcile([], [])


def test_reconciliation_dataclass() -> None:
    r = Reconciliation(only_in_manual=[], only_in_syft=[], in_both=[])
    assert r.only_in_manual == []


def test_strip_ansi() -> None:
    assert strip_ansi("\x1b[31mred\x1b[0m") == "red"


def test_setup_logging_with_file_sink(tmp_path: Path) -> None:
    setup_logging(verbose=True, log_dir=tmp_path / "logs")
    log = get_logger("sbom_overlay.test")
    log.info("hello")
    log_file = tmp_path / "logs" / "sbom-overlay.log"
    assert log_file.exists()


def test_setup_logging_console_only() -> None:
    setup_logging(verbose=False, log_dir=None)
    log = get_logger("sbom_overlay.test2")
    log.info("hello")
