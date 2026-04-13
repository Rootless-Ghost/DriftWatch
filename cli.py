#!/usr/bin/env python3
"""
DriftWatch CLI
Analyze Sigma rule drift from the command line.

Usage:
    python cli.py --rules rules.yml --events events.json
    python cli.py --rules rules/ --events events.json --window 72 --output report.md
    python cli.py --validate --rule rule.yml --events events.json
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))


def load_rules_from_path(path: str) -> list[dict]:
    """Load rules from a file or directory of YAML files."""
    import yaml
    from app import _split_sigma_yaml

    rules: list[dict] = []

    if os.path.isdir(path):
        for fname in sorted(os.listdir(path)):
            if fname.lower().endswith((".yml", ".yaml")):
                fpath = os.path.join(path, fname)
                try:
                    with open(fpath, encoding="utf-8") as fh:
                        content = fh.read()
                    rules.extend(_split_sigma_yaml(content))
                except Exception as exc:
                    print(f"[!] Error reading {fname}: {exc}", file=sys.stderr)
    else:
        with open(path, encoding="utf-8") as fh:
            content = fh.read()
        rules = _split_sigma_yaml(content)

    return rules


def load_events_from_path(path: str) -> list[dict]:
    """Load ECS-lite events from a JSON file."""
    with open(path, encoding="utf-8") as fh:
        raw = fh.read()
    from app import _parse_events_json
    return _parse_events_json(raw)


def _print_summary(report: dict) -> None:
    s = report.get("summary", {})
    gap = s.get("gap_analysis", {})
    print(f"\n{'='*60}")
    print(f"  DriftWatch Report: {report.get('label', '')}")
    print(f"{'='*60}")
    print(f"  Time window:    {report.get('time_window_hours', 168)}h")
    print(f"  Events:         {report.get('event_count', 0):,}")
    print(f"  Total rules:    {s.get('total_rules', 0)}")
    print(f"  Never fired:    {s.get('never_fired_count', 0)}")
    print(f"  Overfiring:     {s.get('overfiring_count', 0)}")
    print(f"  Healthy:        {s.get('healthy_count', 0)}")
    print(f"  Coverage:       {s.get('coverage_pct', 0):.1f}%")
    print(f"  Noise score:    {s.get('noise_score', 0):.3f}")
    print(f"  Total hits:     {s.get('total_matches', 0):,}")
    if gap.get("uncovered_tactics"):
        print(f"\n  Uncovered tactics: {', '.join(gap['uncovered_tactics'])}")
    print()


def cmd_analyze(args: argparse.Namespace, engine) -> None:
    rules  = load_rules_from_path(args.rules)
    events = load_events_from_path(args.events) if args.events else []

    if not rules:
        print("[!] No rules found", file=sys.stderr)
        sys.exit(1)

    window = args.window
    label  = args.label or f"CLI analysis — {len(rules)} rules"
    save   = not args.no_save

    print(f"[+] Loaded {len(rules)} rule(s), {len(events)} event(s)")
    print(f"[+] Running drift analysis (window={window}h)…")

    report = engine.analyze(
        rules=rules,
        events=events,
        time_window_hours=window,
        label=label,
        save=save,
    )

    _print_summary(report)

    # Print per-rule breakdown
    for status, label_str, symbol in [
        ("never_fired", "NEVER FIRED", "✗"),
        ("overfiring",  "OVERFIRING",  "!"),
        ("healthy",     "HEALTHY",     "✓"),
    ]:
        rule_list = report.get(status, [])
        if not rule_list:
            continue
        print(f"\n  [{symbol}] {label_str} ({len(rule_list)}):")
        for r in rule_list:
            fp_str  = f"FP~{r['false_positive_estimate']:.0%}"
            rate_str = f"{r['rate_per_hour']:.3f}/hr"
            print(f"      {r['title'][:45]:<45}  hits={r['hit_count']:<5} {rate_str:<12} {fp_str}")

    # Output file
    if args.output:
        fmt = "markdown" if args.output.endswith(".md") else "json"
        if fmt == "markdown":
            content = engine.to_markdown(report)
        else:
            content = json.dumps(report, indent=2, ensure_ascii=False)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"\n[+] Report saved to: {args.output}")
    elif args.format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))


def cmd_validate(args: argparse.Namespace, engine) -> None:
    with open(args.rule, encoding="utf-8") as fh:
        sigma_yaml = fh.read()

    events = load_events_from_path(args.events) if args.events else []

    print(f"[+] Validating rule against {len(events)} event(s)…")

    result = engine.validate_rule(
        rule={"sigma_yaml": sigma_yaml},
        events=events,
    )

    print(f"\n  Fired:       {result['fired']}")
    print(f"  Matches:     {result['match_count']}")
    print(f"  FP estimate: {result['false_positive_estimate']:.0%}")
    if result.get("parse_error"):
        print(f"  Parse error: {result['parse_error']}", file=sys.stderr)

    if result["matched_events"]:
        print(f"\n  Sample matched event:")
        print(f"  {json.dumps(result['matched_events'][0], indent=4)[:500]}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"\n[+] Result saved to: {args.output}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="driftwatch",
        description="DriftWatch — Detection Drift Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --rules rules.yml --events events.json
  %(prog)s --rules ./rules/ --events events.json --window 72 --output report.md
  %(prog)s --rules rules.yml --events events.json --format json
  %(prog)s --validate --rule rule.yml --events events.json
        """,
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--analyze",  action="store_true", default=True,
                      help="Run drift analysis (default)")
    mode.add_argument("--validate", action="store_true",
                      help="Validate a single rule against events")

    parser.add_argument("--rules",  "-r", metavar="PATH",
                        help="Sigma YAML file or directory of .yml files")
    parser.add_argument("--rule",         metavar="FILE",
                        help="Single Sigma YAML file (for --validate)")
    parser.add_argument("--events", "-e", metavar="FILE",
                        help="ECS-lite events JSON file")
    parser.add_argument("--window", "-w", type=int, default=168,
                        help="Analysis time window in hours (default: 168)")
    parser.add_argument("--label",  "-l", metavar="LABEL",
                        help="Human-readable report label")
    parser.add_argument("--format", "-f", default="summary",
                        choices=["summary", "json", "markdown"],
                        help="Output format (default: summary)")
    parser.add_argument("--output", "-o", metavar="FILE",
                        help="Save report to file")
    parser.add_argument("--no-save", action="store_true",
                        help="Do not save report to database")
    parser.add_argument("--config", default="config.yaml",
                        help="Path to config.yaml")

    args = parser.parse_args()

    # Build minimal config
    config = {"db_path": "./driftwatch.db", "analysis": {"overfire_threshold": 100.0}}
    if os.path.exists(args.config):
        try:
            import yaml
            with open(args.config, encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh) or {}
            config.update(loaded)
        except Exception:
            pass

    from core.engine import DriftEngine
    engine = DriftEngine(config)

    if args.validate:
        if not args.rule:
            parser.error("--rule FILE is required with --validate")
        cmd_validate(args, engine)
    else:
        if not args.rules:
            parser.error("--rules PATH is required")
        cmd_analyze(args, engine)


if __name__ == "__main__":
    main()
