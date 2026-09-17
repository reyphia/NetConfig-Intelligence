import argparse
from pathlib import Path

from app.cli.main import build_parser, cmd_diff, cmd_topology

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "examples/cisco_ios/branch-router.cfg"


def _ns(**kwargs) -> argparse.Namespace:
    defaults = {"vendor": "auto", "output": None}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def test_build_parser_registers_topology_subcommand() -> None:
    parser = build_parser()
    args = parser.parse_args(["topology", str(FIXTURE)])
    assert args.command == "topology"
    assert args.file == FIXTURE


def test_cmd_topology_prints_svg_to_stdout(capsys) -> None:
    rc = cmd_topology(_ns(file=FIXTURE))
    assert rc == 0
    out = capsys.readouterr().out
    assert out.strip().startswith("<svg")
    assert "</svg>" in out


def test_cmd_topology_writes_to_file(tmp_path, capsys) -> None:
    out_file = tmp_path / "diagram.svg"
    rc = cmd_topology(_ns(file=FIXTURE, output=out_file))
    assert rc == 0
    assert out_file.exists()
    assert out_file.read_text().startswith("<svg")
    assert "Wrote" in capsys.readouterr().out


def test_cmd_diff_reports_no_differences_for_identical_files(capsys) -> None:
    rc = cmd_diff(_ns(old=FIXTURE, new=FIXTURE))
    assert rc == 0
    assert "No differences" in capsys.readouterr().out
