"""
DriftWatch — Sigma rule matching engine.

Evaluates a parsed Sigma rule detection against a list of ECS-lite events.
Supports:
  - Field match blocks (contains, startswith, endswith, re, exact, gt, lt, gte, lte)
  - |all modifier (all values must match, not any)
  - |windash modifier (normalise Windows dash variants)
  - Keywords blocks (substring search across all event values)
  - Condition expressions: and / or / not / all of / 1 of / N of / them
  - Wildcards: * and ? in field values (non-regex)
"""

import re
import logging
from datetime import datetime, timezone

from .field_mappings import get_ecs_paths

logger = logging.getLogger("driftwatch.matcher")

# ── Public API ────────────────────────────────────────────────────────────────

def match_rule_against_events(
    parsed_rule: dict,
    events: list[dict],
    time_window_hours: int = 168,
) -> dict:
    """
    Run a parsed Sigma rule against a list of ECS-lite events.

    Returns:
      {
        "matched":        bool,         # any match at all
        "match_count":    int,
        "matched_events": [event, ...], # up to 50 matches
        "error":          str | None,
      }
    """
    if parsed_rule.get("_parse_error"):
        return {
            "matched":        False,
            "match_count":    0,
            "matched_events": [],
            "error":          parsed_rule["_parse_error"],
        }

    detection  = parsed_rule.get("detection", {})
    if not detection:
        return {
            "matched":        False,
            "match_count":    0,
            "matched_events": [],
            "error":          "No detection block in rule",
        }

    matched_events = []
    error          = None

    # Filter events to time window if timestamps present
    windowed = _filter_by_time_window(events, time_window_hours)

    try:
        for event in windowed:
            flat = _flatten_event(event)
            if _evaluate_detection(detection, event, flat):
                matched_events.append(event)
                if len(matched_events) >= 500:
                    break
    except Exception:
        error = "Rule evaluation failed"
        logger.exception("Match error in rule %r", parsed_rule.get("title"))

    return {
        "matched":        len(matched_events) > 0,
        "match_count":    len(matched_events),
        "matched_events": matched_events[:50],
        "error":          error,
    }


# ── Time window ───────────────────────────────────────────────────────────────

def _filter_by_time_window(events: list[dict], hours: int) -> list[dict]:
    """Return events within the last `hours` hours. If no timestamps found, return all."""
    if not hours or hours <= 0:
        return events

    ts_fields = ["@timestamp", "timestamp", "event.created", "created_at"]
    now = datetime.now(timezone.utc)

    has_timestamps = False
    result = []

    for event in events:
        flat = _flatten_event(event)
        ts_val = None
        for f in ts_fields:
            if f in flat:
                ts_val = flat[f]
                break

        if ts_val is None:
            result.append(event)
            continue

        has_timestamps = True
        try:
            if isinstance(ts_val, (int, float)):
                # Unix epoch ms or s
                if ts_val > 1e10:
                    ts_val = ts_val / 1000
                ev_time = datetime.fromtimestamp(ts_val, tz=timezone.utc)
            else:
                ts_str = str(ts_val).replace("Z", "+00:00")
                ev_time = datetime.fromisoformat(ts_str)
                if ev_time.tzinfo is None:
                    ev_time = ev_time.replace(tzinfo=timezone.utc)
            delta_hours = (now - ev_time).total_seconds() / 3600
            if delta_hours <= hours:
                result.append(event)
        except Exception:
            result.append(event)

    return result if has_timestamps else events


# ── Event flattening ──────────────────────────────────────────────────────────

def _flatten_event(event: dict, prefix: str = "") -> dict:
    """Flatten a nested event dict into dot-notation keys."""
    result: dict = {}
    for key, value in event.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            result.update(_flatten_event(value, full_key))
        elif value is not None:
            result[full_key] = value
    return result


# ── Field value resolution ─────────────────────────────────────────────────────

def _get_field_values(field_name: str, event: dict, flat: dict) -> list[str]:
    """
    Collect all string values for a Sigma field from an event.

    Resolution order:
      1. Exact flat key match (Sigma field name)
      2. ECS-lite dot-path from field_mappings
      3. Case-insensitive flat key match
    """
    values: list[str] = []

    # 1. Exact flat key
    if field_name in flat:
        v = flat[field_name]
        if v is not None:
            values.append(str(v))

    # 2. ECS-lite mapped paths
    for ecs_path in get_ecs_paths(field_name):
        if ecs_path in flat and str(flat[ecs_path]) not in values:
            values.append(str(flat[ecs_path]))

    # 3. Case-insensitive match on flat keys
    field_lower = field_name.lower()
    for k, v in flat.items():
        if k.lower() == field_lower and str(v) not in values:
            values.append(str(v))

    return values


# ── Detection evaluation ──────────────────────────────────────────────────────

def _evaluate_detection(detection: dict, event: dict, flat: dict) -> bool:
    """Evaluate the full detection block for a single event."""
    condition = detection.get("condition", "")
    if not condition:
        return False

    # Pre-evaluate each named block
    named: dict[str, bool] = {}
    for name, block in detection.items():
        if name in ("condition", "_timeframe") or name.startswith("_"):
            continue
        named[name] = _evaluate_block(block, event, flat)

    return _evaluate_condition(condition, named, detection, event, flat)


def _evaluate_block(block: dict, event: dict, flat: dict) -> bool:
    """Evaluate a single named detection block (keywords or fields)."""
    btype = block.get("_type", "")

    if btype == "keywords":
        return _evaluate_keywords(block["_values"], flat)

    if btype == "fields":
        return _evaluate_fields(block["_specs"], event, flat)

    return False


def _evaluate_keywords(keywords: list, flat: dict) -> bool:
    """Keywords: ANY keyword must appear in ANY field value (OR logic)."""
    all_values = " ".join(str(v).lower() for v in flat.values() if v is not None)
    for kw in keywords:
        if str(kw).lower() in all_values:
            return True
    return False


def _evaluate_fields(specs: list[dict], event: dict, flat: dict) -> bool:
    """
    Field specs: ALL specs must match (AND across fields).
    Within a spec: ANY value matches (OR), unless all_of=True.
    """
    for spec in specs:
        if not _evaluate_field_spec(spec, event, flat):
            return False
    return True


def _evaluate_field_spec(spec: dict, event: dict, flat: dict) -> bool:
    """Evaluate a single field specification against the event."""
    field     = spec["field"]
    modifiers = spec["modifiers"]
    all_of    = spec["all_of"]
    values    = spec["values"]

    # null / not-null checks
    if modifiers == ["null"] or values == [None]:
        ev_vals = _get_field_values(field, event, flat)
        return len(ev_vals) == 0

    if modifiers == ["notnull"]:
        ev_vals = _get_field_values(field, event, flat)
        return len(ev_vals) > 0

    ev_vals = _get_field_values(field, event, flat)
    if not ev_vals:
        return False

    if all_of:
        # All rule values must match somewhere in the event values
        return all(
            any(_value_matches(ev_val, rule_val, modifiers) for ev_val in ev_vals)
            for rule_val in values
        )
    else:
        # Any rule value matches any event value
        return any(
            any(_value_matches(ev_val, rule_val, modifiers) for ev_val in ev_vals)
            for rule_val in values
        )


def _value_matches(ev_val: str, rule_val, modifiers: list[str]) -> bool:
    """Apply modifiers to compare a single event value against a rule value."""
    if rule_val is None:
        return False

    # Numeric comparisons
    if modifiers and modifiers[0] in ("gt", "lt", "gte", "lte"):
        try:
            ev_num   = float(ev_val)
            rule_num = float(rule_val)
            op = modifiers[0]
            if op == "gt":  return ev_num > rule_num
            if op == "lt":  return ev_num < rule_num
            if op == "gte": return ev_num >= rule_num
            if op == "lte": return ev_num <= rule_num
        except (ValueError, TypeError):
            return False

    ev_str   = str(ev_val)
    rule_str = str(rule_val)

    # windash: treat - and / as equivalent
    if "windash" in modifiers:
        ev_str   = ev_str.replace("/", "-")
        rule_str = rule_str.replace("/", "-")

    # Case handling — Sigma is case-insensitive by default
    ev_lower   = ev_str.lower()
    rule_lower = rule_str.lower()

    if not modifiers or modifiers == ["windash"]:
        # Exact match (case-insensitive), with wildcard support
        return _wildcard_match(ev_lower, rule_lower)

    if "contains" in modifiers:
        return rule_lower in ev_lower

    if "startswith" in modifiers:
        return ev_lower.startswith(rule_lower)

    if "endswith" in modifiers:
        return ev_lower.endswith(rule_lower)

    if "re" in modifiers:
        try:
            return bool(re.search(rule_str, ev_str, re.IGNORECASE))
        except re.error:
            return False

    if "base64" in modifiers:
        import base64
        try:
            decoded = base64.b64decode(rule_str).decode("utf-8", errors="replace").lower()
            return decoded in ev_lower
        except Exception:
            return False

    if "base64offset" in modifiers:
        import base64
        for offset in (0, 1, 2):
            try:
                padded = rule_str + "=" * ((-len(rule_str) - offset) % 4)
                decoded = base64.b64decode(padded).decode("utf-8", errors="replace").lower()
                if decoded in ev_lower:
                    return True
            except Exception:
                pass
        return False

    if "utf16le" in modifiers or "wide" in modifiers:
        wide = " ".join(c for c in rule_lower)
        return wide in ev_lower or rule_lower in ev_lower

    if "cidr" in modifiers:
        return _cidr_match(ev_str, rule_str)

    # Fallback: exact match with wildcards
    return _wildcard_match(ev_lower, rule_lower)


def _wildcard_match(ev: str, pattern: str) -> bool:
    """Match a string against a pattern that may contain * and ? wildcards."""
    if "*" not in pattern and "?" not in pattern:
        return ev == pattern
    # Convert wildcards to regex
    regex = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return bool(re.fullmatch(regex, ev))


def _cidr_match(ip_str: str, cidr: str) -> bool:
    """Basic CIDR range matching."""
    try:
        import ipaddress
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False


# ── Condition parser ──────────────────────────────────────────────────────────
# Implements a recursive-descent parser for Sigma condition expressions.
#
# Grammar (simplified):
#   expr      := or_expr
#   or_expr   := and_expr ('or' and_expr)*
#   and_expr  := not_expr ('and' not_expr)*
#   not_expr  := 'not' not_expr | primary
#   primary   := '(' expr ')' | quantifier | name
#   quantifier:= ('all'|N|'1') 'of' ('them' | glob_pattern)

def _evaluate_condition(
    condition: str,
    named: dict[str, bool],
    detection: dict,
    event: dict,
    flat: dict,
) -> bool:
    tokens = _tokenize_condition(condition)
    try:
        result, pos = _parse_expr(tokens, 0, named, detection, event, flat)
        return result
    except Exception as exc:
        logger.debug("Condition eval error (%r): %s", condition, exc)
        return False


def _tokenize_condition(condition: str) -> list[str]:
    """Tokenise a Sigma condition string into a list of token strings."""
    # Split on whitespace, preserving parentheses as separate tokens
    raw = re.split(r'(\s+|\(|\))', condition.strip())
    return [t for t in raw if t.strip()]


def _parse_expr(tokens, pos, named, detection, event, flat):
    return _parse_or(tokens, pos, named, detection, event, flat)


def _parse_or(tokens, pos, named, detection, event, flat):
    left, pos = _parse_and(tokens, pos, named, detection, event, flat)
    while pos < len(tokens) and tokens[pos].lower() == "or":
        pos += 1
        right, pos = _parse_and(tokens, pos, named, detection, event, flat)
        left = left or right
    return left, pos


def _parse_and(tokens, pos, named, detection, event, flat):
    left, pos = _parse_not(tokens, pos, named, detection, event, flat)
    while pos < len(tokens) and tokens[pos].lower() == "and":
        pos += 1
        right, pos = _parse_not(tokens, pos, named, detection, event, flat)
        left = left and right
    return left, pos


def _parse_not(tokens, pos, named, detection, event, flat):
    if pos < len(tokens) and tokens[pos].lower() == "not":
        pos += 1
        val, pos = _parse_not(tokens, pos, named, detection, event, flat)
        return not val, pos
    return _parse_primary(tokens, pos, named, detection, event, flat)


def _parse_primary(tokens, pos, named, detection, event, flat):
    if pos >= len(tokens):
        return False, pos

    tok = tokens[pos]

    # Parenthesised expression
    if tok == "(":
        pos += 1
        val, pos = _parse_expr(tokens, pos, named, detection, event, flat)
        if pos < len(tokens) and tokens[pos] == ")":
            pos += 1
        return val, pos

    # Quantifier: "all of ..." or "N of ..." or "1 of ..."
    tok_lower = tok.lower()
    if tok_lower in ("all", "1") or re.match(r"^\d+$", tok):
        if pos + 2 < len(tokens) and tokens[pos + 1].lower() == "of":
            quantifier = tok_lower
            pattern    = tokens[pos + 2]
            pos       += 3
            val = _evaluate_quantifier(quantifier, pattern, named, detection, event, flat)
            return val, pos

    # Named selection reference
    if tok in named:
        return named[tok], pos + 1

    # Wildcard glob pattern reference (e.g. "selection*")
    if "*" in tok or "?" in tok:
        val = _evaluate_quantifier("1", tok, named, detection, event, flat)
        return val, pos + 1

    # Fallback: treat as True (unknown reference — be permissive for display)
    logger.debug("Unknown condition token: %r", tok)
    return True, pos + 1


def _evaluate_quantifier(
    quantifier: str,
    pattern: str,
    named: dict[str, bool],
    detection: dict,
    event: dict,
    flat: dict,
) -> bool:
    """Evaluate 'all of X', '1 of X', 'N of X'."""
    if pattern.lower() == "them":
        # Refers to all named blocks
        candidates = list(named.values())
    else:
        # Glob pattern over named block names
        regex = re.compile(
            "^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$",
            re.IGNORECASE,
        )
        candidates = [v for k, v in named.items() if regex.match(k)]

    if not candidates:
        return False

    if quantifier == "all":
        return all(candidates)
    if quantifier == "1":
        return any(candidates)
    # Numeric
    try:
        n = int(quantifier)
        return sum(1 for v in candidates if v) >= n
    except ValueError:
        return any(candidates)
