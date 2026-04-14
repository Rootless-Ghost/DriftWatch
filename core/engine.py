"""
DriftWatch — Detection Drift Analysis Engine.

Orchestrates:
  1. Sigma rule parsing
  2. Rule matching against ECS-lite events
  3. Drift classification (never_fired / overfiring / healthy)
  4. Tuning suggestion generation
  5. Summary and gap analysis
  6. Markdown report export
"""

import json
import logging
from datetime import datetime, timezone

from .sigma_parser  import parse_sigma_rule, extract_mitre_tactics
from .sigma_matcher import match_rule_against_events, _flatten_event
from .tuning        import (
    classify_rule, estimate_fp, build_suggestions,
    build_gap_analysis,
    DEFAULT_OVERFIRE_RATE,
)
from .storage import ReportStorage

logger = logging.getLogger("driftwatch.engine")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _last_seen(matched_events: list[dict]) -> str | None:
    """Return the most recent timestamp string from a list of matched events."""
    ts_fields = ("@timestamp", "timestamp", "event.created", "created_at")
    latest = None
    for ev in matched_events:
        flat = _flatten_event(ev)
        for f in ts_fields:
            if f in flat:
                try:
                    ts = str(flat[f])
                    if latest is None or ts > latest:
                        latest = ts
                except Exception:
                    pass
    return latest


def _build_hit_timeline(matched_events: list[dict], time_window_hours: int) -> list[dict]:
    """Group match hits into hourly buckets for the hit timeline."""
    from collections import Counter

    buckets: Counter = Counter()
    for ev in matched_events:
        flat = _flatten_event(ev)
        for f in ("@timestamp", "timestamp", "event.created"):
            if f in flat:
                try:
                    ts_str = str(flat[f]).replace("Z", "+00:00")
                    dt     = datetime.fromisoformat(ts_str)
                    hour   = dt.strftime("%Y-%m-%dT%H:00:00Z")
                    buckets[hour] += 1
                    break
                except Exception:
                    pass

    return [{"hour": h, "count": c} for h, c in sorted(buckets.items())]


def _noise_score(rule_results: list[dict]) -> float:
    """Noise score: fraction of all hits that come from overfiring rules."""
    total_hits = sum(r["hit_count"] for r in rule_results)
    noisy_hits = sum(r["hit_count"] for r in rule_results if r["status"] == "overfiring")
    if total_hits == 0:
        return 0.0
    return round(noisy_hits / total_hits, 3)


# ── DriftEngine ───────────────────────────────────────────────────────────────

class DriftEngine:
    """Main engine: parses rules, matches events, produces drift reports."""

    def __init__(self, config: dict):
        self.config  = config
        self.storage = ReportStorage(config.get("db_path", "./driftwatch.db"))
        self.overfire_threshold = float(
            config.get("analysis", {}).get("overfire_threshold", DEFAULT_OVERFIRE_RATE)
        )
        logger.info("DriftEngine initialised (overfire_threshold=%.1f/hr)", self.overfire_threshold)

    # ── Core analysis ──────────────────────────────────────────────────────────

    def analyze(
        self,
        rules:             list[dict],
        events:            list[dict],
        time_window_hours: int  = 168,
        label:             str  = "",
        save:              bool = True,
    ) -> dict:
        """
        Run drift analysis.

        Args:
            rules:             list of {"rule_id": str, "sigma_yaml": str}
            events:            list of ECS-lite event dicts
            time_window_hours: analysis window in hours
            label:             human-readable report label
            save:              persist to database

        Returns:
            Full drift report dict.
        """
        started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        errors:     list[str] = []
        rule_results: list[dict] = []

        logger.info(
            "Analyzing %d rules against %d events (window=%dh)",
            len(rules), len(events), time_window_hours,
        )

        for rule_input in rules:
            rr = self._analyze_single_rule(rule_input, events, time_window_hours)
            rule_results.append(rr)
            if rr.get("parse_error"):
                errors.append(f"[{rr['rule_id']}] {rr['parse_error']}")

        # Classify
        never_fired = [r for r in rule_results if r["status"] == "never_fired"]
        overfiring  = [r for r in rule_results if r["status"] == "overfiring"]
        healthy     = [r for r in rule_results if r["status"] == "healthy"]

        total = len(rule_results)
        coverage_pct = round(((total - len(never_fired)) / max(total, 1)) * 100, 1)

        gap_analysis = build_gap_analysis(rule_results)

        summary = {
            "total_rules":      total,
            "never_fired_count": len(never_fired),
            "overfiring_count": len(overfiring),
            "healthy_count":    len(healthy),
            "coverage_pct":     coverage_pct,
            "noise_score":      _noise_score(rule_results),
            "total_matches":    sum(r["hit_count"] for r in rule_results),
            "time_window_hours": time_window_hours,
            "event_count":      len(events),
            "gap_analysis":     gap_analysis,
        }

        report = {
            "success":           True,
            "label":             label or f"Drift analysis — {len(rules)} rules",
            "summary":           summary,
            "never_fired":       never_fired,
            "overfiring":        overfiring,
            "healthy":           healthy,
            "all_rules":         rule_results,
            "time_window_hours": time_window_hours,
            "event_count":       len(events),
            "errors":            errors,
            "analyzed_at":       started_at,
            "generator":         "DriftWatch v1.0.0",
        }

        if save and total > 0:
            report = self.storage.save_report(report)

        logger.info(
            "Analysis complete — never_fired=%d, overfiring=%d, healthy=%d",
            len(never_fired), len(overfiring), len(healthy),
        )
        return report

    def _analyze_single_rule(
        self,
        rule_input: dict,
        events: list[dict],
        time_window_hours: int,
    ) -> dict:
        """Analyze one rule. Returns a rule result dict."""
        rule_id   = rule_input.get("rule_id", "unknown")
        yaml_text = rule_input.get("sigma_yaml", "")

        parsed   = parse_sigma_rule(yaml_text)
        tactics  = extract_mitre_tactics(parsed)
        title    = parsed.get("title", rule_id)
        level    = parsed.get("level", "medium")
        ls       = parsed.get("logsource", {})

        match_result = match_rule_against_events(parsed, events, time_window_hours)

        hit_count     = match_result["match_count"]
        rate_per_hour = round(hit_count / max(time_window_hours, 1), 4)
        status        = classify_rule(hit_count, rate_per_hour, self.overfire_threshold)
        fp_est        = estimate_fp(hit_count, rate_per_hour, level)
        suggestions   = build_suggestions(
            status, parsed, match_result, rate_per_hour, fp_est
        )
        timeline      = _build_hit_timeline(match_result["matched_events"], time_window_hours)
        last_seen_ts  = _last_seen(match_result["matched_events"])

        return {
            "rule_id":               rule_id,
            "title":                 title,
            "level":                 level,
            "status":                status,
            "hit_count":             hit_count,
            "rate_per_hour":         rate_per_hour,
            "last_seen":             last_seen_ts,
            "false_positive_estimate": round(fp_est, 2),
            "tuning_suggestions":    suggestions,
            "matched_events":        match_result["matched_events"][:10],
            "hit_timeline":          timeline,
            "parse_error":           parsed.get("_parse_error"),
            "match_error":           match_result.get("error"),
            "logsource":             ls,
            "tactics":               tactics,
            "tags":                  parsed.get("tags", []),
            "description":           parsed.get("description", ""),
            "falsepositives":        parsed.get("falsepositives", []),
        }

    # ── Single rule validation ─────────────────────────────────────────────────

    def validate_rule(self, rule_input: dict, events: list[dict]) -> dict:
        """
        Validate a single rule against events without persisting.

        Returns:
          {
            "success": bool, "fired": bool, "match_count": int,
            "matched_events": [...], "false_positive_estimate": float,
            "parse_error": str|None
          }
        """
        parsed = parse_sigma_rule(rule_input.get("sigma_yaml", ""))
        match  = match_rule_against_events(parsed, events, time_window_hours=0)
        fp_est = estimate_fp(
            match["match_count"],
            match["match_count"] / max(1, 1),
            parsed.get("level", "medium"),
        )
        return {
            "success":                True,
            "fired":                  match["matched"],
            "match_count":            match["match_count"],
            "matched_events":         match["matched_events"],
            "false_positive_estimate": round(fp_est, 2),
            "parse_error":            parsed.get("_parse_error"),
        }

    # ── Storage proxies ────────────────────────────────────────────────────────

    def get_reports(self, **kwargs) -> dict:
        return self.storage.list_reports(**kwargs)

    def get_report(self, report_id: str) -> dict | None:
        return self.storage.get_report(report_id)

    def delete_report(self, report_id: str) -> bool:
        return self.storage.delete_report(report_id)

    # ── Markdown export ────────────────────────────────────────────────────────

    def to_markdown(self, report: dict) -> str:
        """Convert a drift report to Markdown."""
        s   = report.get("summary", {})
        gap = s.get("gap_analysis", {})
        ts  = report.get("analyzed_at", "")[:10]

        lines = [
            f"# DriftWatch Report — {report.get('label', 'Drift Analysis')}",
            "",
            f"> **Generated:** {ts}  ",
            f"> **Time window:** {report.get('time_window_hours', 168)}h  ",
            f"> **Events analyzed:** {report.get('event_count', 0):,}  ",
            f"> **Generator:** DriftWatch v1.0.0",
            "",
            "---",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Rules | {s.get('total_rules', 0)} |",
            f"| Never Fired | {s.get('never_fired_count', 0)} |",
            f"| Overfiring  | {s.get('overfiring_count', 0)} |",
            f"| Healthy     | {s.get('healthy_count', 0)} |",
            f"| Coverage    | {s.get('coverage_pct', 0):.1f}% |",
            f"| Noise Score | {s.get('noise_score', 0):.3f} |",
            f"| Total Hits  | {s.get('total_matches', 0):,} |",
            "",
        ]

        if gap:
            lines += [
                "## Gap Analysis",
                "",
                f"- **Coverage breadth:** {gap.get('coverage_breadth', 0):.1f}% of MITRE tactics",
                f"- **Uncovered tactics:** {', '.join(gap.get('uncovered_tactics', [])) or 'None'}",
                f"- **Never-fired rules:** {gap.get('never_fired_pct', 0):.1f}%",
                f"- **Overfiring rules:** {gap.get('overfiring_pct', 0):.1f}%",
                "",
            ]

        for status, heading, emoji in [
            ("never_fired", "Never Fired", "🔴"),
            ("overfiring",  "Overfiring",  "🟠"),
            ("healthy",     "Healthy",     "🟢"),
        ]:
            rules = report.get(status, [])
            lines += [
                f"---",
                "",
                f"## {emoji} {heading} ({len(rules)} rules)",
                "",
            ]
            if not rules:
                lines.append("*No rules in this category.*")
                lines.append("")
                continue
            for r in rules:
                lines += [
                    f"### {r['title']} (`{r['rule_id']}`)",
                    "",
                    f"- **Level:** {r['level']}",
                    f"- **Hit count:** {r['hit_count']}",
                    f"- **Rate/hour:** {r['rate_per_hour']:.4f}",
                    f"- **Last seen:** {r.get('last_seen') or 'N/A'}",
                    f"- **FP estimate:** {r['false_positive_estimate']:.0%}",
                    "",
                ]
                if r.get("description"):
                    lines += [f"> {r['description'][:200]}", ""]
                if r.get("tuning_suggestions"):
                    lines += ["**Tuning Suggestions:**", ""]
                    for sug in r["tuning_suggestions"]:
                        lines.append(f"- {sug}")
                    lines.append("")

        lines += [
            "---",
            "",
            "*Generated by DriftWatch v1.0.0 — Rootless-Ghost / Nebula Forge Suite*",
        ]

        return "\n".join(lines)
