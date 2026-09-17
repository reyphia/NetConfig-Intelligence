"""Local CLI using the exact same analysis service as the web application.

No business logic lives here - every subcommand is a thin wrapper around
`app.services`, so the web UI and the CLI can never drift apart on what
counts as a finding, a valid edit, or a safe export.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.analyzers.topology import render_topology_svg
from app.services import analyze, render_device, update_interface
from app.services.diff import configuration_diff
from app.services.replay import build_replay_plan
from app.services.validation import validate_device


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def cmd_analyze(args: argparse.Namespace) -> int:
    session = analyze(_read(args.file), args.vendor)
    print(f"{session.device.hostname or 'Unknown device'} - {session.vendor.value}")
    print(f"Health: {session.health.overall}/100 ; findings: {len(session.findings)}")
    for category in session.health.categories:
        if category.finding_count:
            print(f"  {category.category}: {category.score}/100 ({category.finding_count} finding(s))")
    if not session.findings:
        print("No implemented rules fired for this configuration.")
    for finding in session.findings:
        subject = f" [{finding.subject}]" if finding.subject else ""
        print(f"{finding.severity.value:<8} {finding.title}{subject}")
        print(f"         {finding.recommendation}")
    return 0


def cmd_sanitize(args: argparse.Namespace) -> int:
    session = analyze(_read(args.file), args.vendor)
    mode = args.mode
    if mode == "sanitized":
        print(session.sanitization.sanitized_text)
    elif mode == "anonymized":
        print(session.sanitization.anonymized_text)
    else:  # reveal - local-only, explicit flag required, never the default
        print(session.sanitization.revealed_text())
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    session = analyze(_read(args.file), args.vendor)
    checks = validate_device(session.device)
    blocking = False
    for check in checks:
        marker = {"pass": "OK ", "warning": "WARN", "blocking": "FAIL"}.get(check["status"], "?")
        print(f"[{marker}] {check['name']}: {check['detail']}")
        blocking = blocking or check["status"] == "blocking"
    if blocking:
        print("\nEXPORT BLOCKED: resolve the FAIL item(s) above before exporting.")
        return 1
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    session = analyze(_read(args.file), args.vendor)
    print(
        "NOTE: a running configuration does not contain CLI command history. "
        "This is a dependency-aware reconstruction order, not recovered history.\n"
    )
    for step in build_replay_plan(session.device):
        dependencies = step["dependencies"]
        dep_list = dependencies if isinstance(dependencies, list) else []
        deps = f" (depends on: {', '.join(str(d) for d in dep_list)})" if dep_list else ""
        print(f"{step['step']:>3}. [{step['risk']:<6}] {step['command']}{deps}")
        print(f"      {step['explanation']}")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    old_session = analyze(_read(args.old), args.vendor)
    new_session = analyze(_read(args.new), args.vendor)
    result = configuration_diff(old_session.original_rendered_text, new_session.original_rendered_text)
    print(result["unified"] or "No differences.")
    print(f"\n{result['added']} line(s) added, {result['removed']} line(s) removed.")
    return 0


def cmd_topology(args: argparse.Namespace) -> int:
    session = analyze(_read(args.file), args.vendor)
    svg = render_topology_svg(session.device)
    if args.output:
        args.output.write_text(svg, encoding="utf-8")
        print(f"Wrote {args.output}")
    else:
        print(svg)
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    session = analyze(_read(args.file), args.vendor)
    checks = validate_device(session.device)
    if any(c["status"] == "blocking" for c in checks):
        print("EXPORT BLOCKED - run `netconfig validate` for details.", file=sys.stderr)
        return 1
    if args.interface and args.address and args.prefix_length is not None:
        update_interface(session, args.interface, args.address, args.prefix_length)
    output = render_device(session.device)
    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"Wrote {args.output}")
    else:
        print(output)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netconfig",
        description="NetConfig Intelligence - local-only Cisco/MikroTik configuration analysis CLI.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--vendor", default="auto", help="cisco_ios | cisco_iosxe | mikrotik_routeros | auto")

    p_analyze = sub.add_parser("analyze", help="Parse, sanitize, and run security/config rules.")
    p_analyze.add_argument("file", type=Path)
    add_common(p_analyze)
    p_analyze.set_defaults(func=cmd_analyze)

    p_sanitize = sub.add_parser("sanitize", help="Print a masked version of the configuration.")
    p_sanitize.add_argument("file", type=Path)
    p_sanitize.add_argument(
        "--mode", choices=["sanitized", "anonymized", "reveal"], default="sanitized",
        help="sanitized: mask credentials+device IDs (default). anonymized: also mask hostname/public IPs. "
        "reveal: show locally-recoverable credentials (plaintext/type 7 only) - local use only.",
    )
    add_common(p_sanitize)
    p_sanitize.set_defaults(func=cmd_sanitize)

    p_validate = sub.add_parser("validate", help="Run pre-export validation checks.")
    p_validate.add_argument("file", type=Path)
    add_common(p_validate)
    p_validate.set_defaults(func=cmd_validate)

    p_replay = sub.add_parser("replay", help="Print the dependency-aware configuration replay plan.")
    p_replay.add_argument("file", type=Path)
    add_common(p_replay)
    p_replay.set_defaults(func=cmd_replay)

    p_diff = sub.add_parser("diff", help="Diff two configurations (rendered through the same renderer).")
    p_diff.add_argument("old", type=Path)
    p_diff.add_argument("new", type=Path)
    add_common(p_diff)
    p_diff.set_defaults(func=cmd_diff)

    p_topology = sub.add_parser("topology", help="Render an interface/routing diagram as SVG.")
    p_topology.add_argument("file", type=Path)
    p_topology.add_argument("-o", "--output", type=Path, help="Write to this file instead of stdout")
    add_common(p_topology)
    p_topology.set_defaults(func=cmd_topology)

    p_export = sub.add_parser("export", help="Validate, optionally apply one interface edit, and render the config.")
    p_export.add_argument("file", type=Path)
    p_export.add_argument("--interface", help="Interface name to edit, e.g. GigabitEthernet0/1")
    p_export.add_argument("--address", help="New IPv4 address for --interface")
    p_export.add_argument("--prefix-length", dest="prefix_length", type=int, help="New IPv4 prefix length")
    p_export.add_argument("-o", "--output", type=Path, help="Write to this file instead of stdout")
    add_common(p_export)
    p_export.set_defaults(func=cmd_export)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        raise SystemExit(args.func(args))
    except BrokenPipeError:
        # e.g. `netconfig replay file.cfg | head` - not an error.
        sys.stderr.close()
        raise SystemExit(0) from None


if __name__ == "__main__":
    main()
