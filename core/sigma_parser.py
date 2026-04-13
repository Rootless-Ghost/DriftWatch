"""
DriftWatch — Sigma YAML parser.

Parses a Sigma rule YAML string into a structured representation
suitable for evaluation by the sigma_matcher module.
"""

import re
import logging
import yaml

logger = logging.getLogger("driftwatch.parser")


class SigmaParseError(Exception):
    pass


def parse_sigma_rule(yaml_text: str) -> dict:
    """
    Parse a Sigma rule YAML string.

    Returns a normalised dict:
      {
        "title":       str,
        "id":          str,
        "status":      str,
        "description": str,
        "author":      str,
        "date":        str,
        "level":       str,          # critical|high|medium|low|informational
        "tags":        [str, ...],
        "logsource":   {product, category, service, ...},
        "detection":   {<name>: <selection|list>, condition: str},
        "falsepositives": [str, ...],
        "_raw_yaml":   str,
        "_parse_error": str|None,
      }
    """
    result: dict = {
        "title":         "",
        "id":            "",
        "status":        "experimental",
        "description":   "",
        "author":        "",
        "date":          "",
        "level":         "medium",
        "tags":          [],
        "logsource":     {},
        "detection":     {},
        "falsepositives": [],
        "_raw_yaml":     yaml_text,
        "_parse_error":  None,
    }

    try:
        rule = yaml.safe_load(yaml_text) or {}
        if not isinstance(rule, dict):
            raise SigmaParseError("YAML did not parse to a dict")

        result["title"]         = str(rule.get("title", "Untitled"))
        result["id"]            = str(rule.get("id", ""))
        result["status"]        = str(rule.get("status", "experimental"))
        result["description"]   = str(rule.get("description", ""))
        result["author"]        = str(rule.get("author", ""))
        result["date"]          = str(rule.get("date", ""))
        result["level"]         = str(rule.get("level", "medium")).lower()
        result["falsepositives"] = rule.get("falsepositives", []) or []

        # Tags
        tags = rule.get("tags", []) or []
        result["tags"] = [str(t) for t in tags]

        # Logsource
        ls = rule.get("logsource", {}) or {}
        result["logsource"] = {
            "product":  str(ls.get("product", "")),
            "category": str(ls.get("category", "")),
            "service":  str(ls.get("service", "")),
            "definition": str(ls.get("definition", "")),
        }

        # Detection
        det = rule.get("detection", {}) or {}
        result["detection"] = _normalise_detection(det)

    except SigmaParseError as exc:
        result["_parse_error"] = str(exc)
        logger.warning("Sigma parse error: %s", exc)
    except Exception as exc:
        result["_parse_error"] = f"Unexpected parse error: {exc}"
        logger.warning("Sigma unexpected parse error: %s", exc)

    return result


# ── Detection normalisation ───────────────────────────────────────────────────

def _normalise_detection(det: dict) -> dict:
    """
    Normalise the detection block.

    Each named block (not 'condition') becomes one of:
      - FieldMatchBlock: dict of {field_spec: value_list}
      - KeywordBlock:    list of keyword strings
    """
    out: dict = {}

    for name, content in det.items():
        if name == "condition":
            out["condition"] = str(content)
            continue

        if name == "timeframe":
            out["_timeframe"] = str(content)
            continue

        if isinstance(content, list):
            # Keywords list
            out[name] = {
                "_type": "keywords",
                "_values": [str(v) for v in content],
            }
        elif isinstance(content, dict):
            out[name] = {
                "_type": "fields",
                "_specs": _parse_field_specs(content),
            }
        elif isinstance(content, str):
            # String-based keyword
            out[name] = {
                "_type": "keywords",
                "_values": [content],
            }
        else:
            logger.debug("Unhandled detection block type for %r: %s", name, type(content))

    if "condition" not in out:
        # Infer condition if not specified
        non_meta = [k for k in out if not k.startswith("_")]
        if len(non_meta) == 1:
            out["condition"] = non_meta[0]
        elif non_meta:
            out["condition"] = " and ".join(non_meta)

    return out


def _parse_field_specs(block: dict) -> list[dict]:
    """
    Parse a field-match dict into a list of FieldSpec dicts.

    Each FieldSpec:
      {
        "field":      str,          # bare field name (no modifiers)
        "modifiers":  [str, ...],   # e.g. ["contains"], ["startswith"]
        "all_of":     bool,         # from |all modifier
        "values":     [str|int, ...]
      }
    """
    specs = []
    for key, value in block.items():
        parts      = key.split("|")
        field_name = parts[0]
        raw_mods   = [m.lower() for m in parts[1:]]

        all_of    = "all" in raw_mods
        modifiers = [m for m in raw_mods if m != "all"]

        if value is None:
            continue

        # Normalise values to a list
        if isinstance(value, list):
            values = value
        else:
            values = [value]

        # Convert all to strings where needed (keep int for numeric comparisons)
        norm_values = []
        for v in values:
            if v is None:
                continue
            norm_values.append(v)

        specs.append({
            "field":     field_name,
            "modifiers": modifiers,
            "all_of":    all_of,
            "values":    norm_values,
        })

    return specs


# ── MITRE tactic extraction ───────────────────────────────────────────────────

def extract_mitre_tactics(rule: dict) -> list[str]:
    """Extract MITRE ATT&CK tactic names from Sigma rule tags."""
    tactic_map = {
        "initial_access":       "Initial Access",
        "execution":            "Execution",
        "persistence":          "Persistence",
        "privilege_escalation": "Privilege Escalation",
        "defense_evasion":      "Defense Evasion",
        "credential_access":    "Credential Access",
        "discovery":            "Discovery",
        "lateral_movement":     "Lateral Movement",
        "collection":           "Collection",
        "command_and_control":  "Command and Control",
        "exfiltration":         "Exfiltration",
        "impact":               "Impact",
    }
    tactics = []
    for tag in rule.get("tags", []):
        tag_lower = tag.lower().replace("attack.", "").replace("-", "_")
        if tag_lower in tactic_map:
            t = tactic_map[tag_lower]
            if t not in tactics:
                tactics.append(t)
    return tactics
