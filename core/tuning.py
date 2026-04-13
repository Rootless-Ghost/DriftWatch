"""
DriftWatch — Tuning suggestion logic.

Generates actionable tuning recommendations based on rule status,
hit rates, matched event characteristics, and rule metadata.
"""

from __future__ import annotations


# ── Status thresholds (defaults, overridden by config) ────────────────────────

DEFAULT_OVERFIRE_RATE  = 100.0   # hits/hour above this → overfiring
DEFAULT_HEALTHY_MIN    = 0.01    # hits/hour below this (but > 0) → borderline


# ── Rule status classification ────────────────────────────────────────────────

def classify_rule(
    hit_count: int,
    rate_per_hour: float,
    overfire_threshold: float = DEFAULT_OVERFIRE_RATE,
) -> str:
    """Return 'never_fired' | 'overfiring' | 'healthy'."""
    if hit_count == 0:
        return "never_fired"
    if rate_per_hour > overfire_threshold:
        return "overfiring"
    return "healthy"


# ── False positive estimate ───────────────────────────────────────────────────

def estimate_fp(
    hit_count: int,
    rate_per_hour: float,
    rule_level: str,
) -> float:
    """
    Heuristic false-positive probability estimate [0.0, 0.97].

    Higher severity rules are assumed to be more precisely written, so the
    FP multiplier is lower for critical/high.
    """
    if hit_count == 0:
        return 0.0

    # Base FP from hit rate
    if rate_per_hour > 1000:
        base = 0.92
    elif rate_per_hour > 100:
        base = 0.72
    elif rate_per_hour > 10:
        base = 0.38
    elif rate_per_hour > 1:
        base = 0.18
    elif rate_per_hour > 0.1:
        base = 0.08
    else:
        base = 0.04

    # Severity multiplier
    multiplier = {
        "critical":      0.45,
        "high":          0.65,
        "medium":        1.00,
        "low":           1.35,
        "informational": 1.60,
    }.get(rule_level.lower(), 1.0)

    return min(0.97, base * multiplier)


# ── Tuning suggestions ────────────────────────────────────────────────────────

def build_suggestions(
    status: str,
    parsed_rule: dict,
    match_result: dict,
    rate_per_hour: float,
    fp_estimate: float,
) -> list[str]:
    """Return a list of actionable tuning suggestion strings."""
    suggestions: list[str] = []
    level      = parsed_rule.get("level", "medium").lower()
    detection  = parsed_rule.get("detection", {})
    logsource  = parsed_rule.get("logsource", {})

    if status == "never_fired":
        suggestions += _suggestions_never_fired(parsed_rule, detection, logsource)

    elif status == "overfiring":
        suggestions += _suggestions_overfiring(parsed_rule, match_result, rate_per_hour, fp_estimate)

    else:  # healthy
        suggestions += _suggestions_healthy(rate_per_hour, fp_estimate)

    return suggestions[:8]  # cap at 8 suggestions


def _suggestions_never_fired(
    rule: dict, detection: dict, logsource: dict
) -> list[str]:
    suggestions = []

    product  = logsource.get("product", "")
    category = logsource.get("category", "")
    service  = logsource.get("service", "")
    tags     = rule.get("tags", [])

    # Log source availability
    if product or category or service:
        src_desc = " / ".join(filter(None, [product, category, service]))
        suggestions.append(
            f"Verify the log source is enabled: {src_desc}. "
            "Events may not be reaching the analysis pipeline."
        )
    else:
        suggestions.append(
            "No logsource defined in rule — verify events from the intended "
            "data source are included in your event set."
        )

    # Field mapping check
    specs = []
    for name, block in detection.items():
        if name in ("condition", "_timeframe") or name.startswith("_"):
            continue
        if block.get("_type") == "fields":
            for sp in block.get("_specs", []):
                specs.append(sp["field"])

    if specs:
        field_list = ", ".join(specs[:4])
        suggestions.append(
            f"Check field mappings: rule uses {field_list}. "
            "Confirm these fields exist in your ECS-lite events "
            "(check LogNorm schema output)."
        )

    # Condition complexity
    condition = detection.get("condition", "")
    if "and" in condition.lower():
        suggestions.append(
            "Detection uses AND logic — all conditions must match simultaneously. "
            "Consider testing each selection block individually to isolate the gap."
        )

    # ATT&CK tags suggest coverage gaps
    if any("attack." in t for t in tags):
        technique_tags = [t for t in tags if re.search(r"t\d{4}", t, re.I)]
        if technique_tags:
            suggestions.append(
                f"This rule covers MITRE techniques ({', '.join(technique_tags[:2])}). "
                "Ensure your event set includes telemetry relevant to these techniques."
            )

    # Time window
    suggestions.append(
        "Broaden the analysis time window — adversary activity for this technique "
        "may be infrequent or seasonal."
    )

    # Keyword broadening
    if any(b.get("_type") == "keywords" for b in detection.values() if isinstance(b, dict)):
        suggestions.append(
            "Keywords-only rules require the exact string to appear in event fields. "
            "Consider adding field-specific conditions for higher precision."
        )

    return suggestions


def _suggestions_overfiring(
    rule: dict,
    match_result: dict,
    rate_per_hour: float,
    fp_estimate: float,
) -> list[str]:
    suggestions = []
    level = rule.get("level", "medium").lower()

    suggestions.append(
        f"Rule firing at {rate_per_hour:.1f} hits/hour — add exclusions for "
        "known-good processes, users, or asset groups to reduce noise."
    )

    if rate_per_hour > 500:
        suggestions.append(
            "Extremely high hit rate: consider making the detection more specific "
            "by adding AND conditions (e.g., parent process, privilege level, host role)."
        )

    if fp_estimate > 0.7:
        suggestions.append(
            f"High false-positive estimate ({fp_estimate:.0%}): "
            "review matched events to identify common benign patterns and build exclusion filters."
        )

    # Suggest scoping by asset group
    suggestions.append(
        "Scope detection to specific asset groups or subnets relevant to the threat "
        "rather than applying organisation-wide."
    )

    # Suggest time-of-day gating if available
    suggestions.append(
        "Consider a time-of-day filter — if legitimate activity only occurs "
        "during business hours, restrict the rule to off-hours alerts."
    )

    # Suggest threshold alerting
    suggestions.append(
        "Use threshold-based alerting (e.g., alert only when > N events occur "
        "from the same host within X minutes) to suppress individual noisy hits."
    )

    if level in ("low", "informational"):
        suggestions.append(
            f"Rule is classified '{level}' — overfiring low-severity rules "
            "contributes to alert fatigue. Consider suppressing or tuning aggressively."
        )

    return suggestions


def _suggestions_healthy(rate_per_hour: float, fp_estimate: float) -> list[str]:
    suggestions = []

    suggestions.append(
        "Rule is firing within the expected range — monitor for trend changes over time."
    )

    if rate_per_hour < 0.01:
        suggestions.append(
            "Very low hit rate (< 1 hit/day): validate that events are still flowing "
            "and the rule is not borderline never-fired."
        )

    if fp_estimate > 0.3:
        suggestions.append(
            f"Moderate false-positive estimate ({fp_estimate:.0%}): "
            "periodically review matched events to validate alert quality."
        )

    suggestions.append(
        "Schedule a quarterly review of matched events to ensure detection remains "
        "accurate as the environment evolves."
    )

    return suggestions


# ── Gap analysis ──────────────────────────────────────────────────────────────

def build_gap_analysis(rule_results: list[dict]) -> dict:
    """
    Analyse coverage gaps across all rules.

    Returns:
      {
        "uncovered_tactics":      [str, ...],
        "low_confidence_rules":   [{"rule_id", "title", "fp_estimate"}, ...],
        "no_logsource_rules":     [str, ...],   # rule IDs / titles
        "never_fired_pct":        float,
        "overfiring_pct":         float,
        "coverage_breadth":       float,   # % of tactics covered by ≥1 healthy rule
      }
    """
    all_tactics = {
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact",
    }

    covered_tactics:   set[str]  = set()
    low_conf:          list[dict] = []
    no_logsource:      list[str] = []
    total             = len(rule_results)
    never_fired_count = 0
    overfiring_count  = 0

    for rr in rule_results:
        status = rr.get("status", "")
        if status == "never_fired":
            never_fired_count += 1
        elif status == "overfiring":
            overfiring_count += 1
        else:
            # Healthy rule — mark its tactics as covered
            for tactic in rr.get("tactics", []):
                covered_tactics.add(tactic)

        fp = rr.get("false_positive_estimate", 0.0)
        if fp > 0.5 and rr.get("hit_count", 0) > 0:
            low_conf.append({
                "rule_id":       rr.get("rule_id", ""),
                "title":         rr.get("title", ""),
                "fp_estimate":   round(fp, 2),
            })

        ls = rr.get("logsource", {})
        if not ls.get("product") and not ls.get("category") and not ls.get("service"):
            no_logsource.append(rr.get("title", rr.get("rule_id", "unknown")))

    uncovered = sorted(all_tactics - covered_tactics)
    nf_pct    = (never_fired_count / total * 100) if total else 0.0
    of_pct    = (overfiring_count  / total * 100) if total else 0.0
    breadth   = (len(covered_tactics) / len(all_tactics) * 100)

    return {
        "uncovered_tactics":    uncovered,
        "low_confidence_rules": low_conf[:10],
        "no_logsource_rules":   no_logsource[:10],
        "never_fired_pct":      round(nf_pct, 1),
        "overfiring_pct":       round(of_pct, 1),
        "coverage_breadth":     round(breadth, 1),
    }


import re  # used above — keep at bottom to avoid circular issues
