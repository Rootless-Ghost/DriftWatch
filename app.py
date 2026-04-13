"""
DriftWatch — Detection Drift Analyzer
Sigma rules + ECS-lite events → drift report (never-fired / overfiring / healthy)

Author:  Rootless-Ghost
Version: 1.0.0
Port:    5008 (default)

Usage:
    python app.py
    python app.py --port 5008
    python app.py --config /path/to/config.yaml --debug
"""

import argparse
import io
import json
import logging
import os

import yaml
from flask import Flask, jsonify, render_template, request, send_file

from core.engine import DriftEngine

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("driftwatch")

# ── Config ────────────────────────────────────────────────────────────────────

_DEFAULTS: dict = {
    "port":       5008,
    "db_path":    "./driftwatch.db",
    "output_dir": "./output",
    "analysis": {
        "overfire_threshold":   100.0,   # hits/hour
        "default_window_hours": 168,     # 7 days
        "max_events":           50000,
        "max_rules":            500,
        "auto_save":            True,
    },
    "integrations": {
        "lognorm_url":    "http://127.0.0.1:5006",
        "sigmaforge_url": "http://127.0.0.1:5000",
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and key in result and isinstance(result[key], dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: str) -> dict:
    config = _deep_merge({}, _DEFAULTS)
    if not os.path.exists(path):
        logger.warning("Config not found: %s — using defaults", path)
        return config
    try:
        with open(path, encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        config = _deep_merge(config, loaded)
    except Exception as exc:
        logger.error("Failed to load config: %s — using defaults", exc)
    return config


# ── App factory ───────────────────────────────────────────────────────────────

app     = Flask(__name__)
_config: dict        = {}
_engine: DriftEngine = None  # type: ignore


def create_app(config_path: str = "config.yaml") -> Flask:
    global _config, _engine
    _config = load_config(config_path)
    _engine = DriftEngine(_config)
    os.makedirs(_config.get("output_dir", "./output"), exist_ok=True)
    return app


# ── Page routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/report/<report_id>")
def report_page(report_id: str):
    report = _engine.get_report(report_id)
    if report is None:
        return render_template("index.html", error=f"Report {report_id!r} not found"), 404
    return render_template("report.html", report=report)


@app.route("/reports")
def reports_page():
    return render_template("library.html")


# ── API: health ───────────────────────────────────────────────────────────────

@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok", "tool": "driftwatch", "version": "1.0.0"})


# ── API: analyze ──────────────────────────────────────────────────────────────

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    Run drift analysis.

    Body:
      {
        "rules": [{"rule_id": "...", "sigma_yaml": "..."}],
        "events": [{...ECS-lite...}],
        "time_window_hours": 168,
        "label": "optional label",
        "save": true
      }

    Also accepts multipart/form-data:
      rules_file  — YAML file (single rule or multiple rules separated by ---)
      events_file — JSON file (array of events)
      time_window_hours, label fields
    """
    cfg_analysis = _config.get("analysis", {})
    max_events   = int(cfg_analysis.get("max_events", 50000))
    max_rules    = int(cfg_analysis.get("max_rules", 500))
    auto_save    = bool(cfg_analysis.get("auto_save", True))

    content_type = request.content_type or ""

    # ── multipart/form-data upload ────────────────────────────────────────────
    if "multipart/form-data" in content_type:
        rules_list  = _parse_rules_from_upload()
        events_list = _parse_events_from_upload()
        window      = int(request.form.get("time_window_hours", cfg_analysis.get("default_window_hours", 168)))
        label       = request.form.get("label", "").strip()
        save        = request.form.get("save", "true").lower() != "false"
    else:
        # ── JSON body ─────────────────────────────────────────────────────────
        body        = request.get_json(silent=True) or {}
        # Accept either pre-parsed lists or raw YAML/JSON strings from the web UI
        if body.get("rules_yaml"):
            rules_list = _split_sigma_yaml(body["rules_yaml"])
        else:
            rules_list = body.get("rules") or []
        if body.get("events_json"):
            events_list = _parse_events_json(body["events_json"])
        else:
            events_list = body.get("events") or []
        if body.get("overfire_threshold") is not None:
            try:
                _config.setdefault("analysis", {})["overfire_threshold"] = float(body["overfire_threshold"])
            except (TypeError, ValueError):
                pass
        window      = int(body.get("time_window_hours", cfg_analysis.get("default_window_hours", 168)))
        label       = str(body.get("label", "")).strip()
        save        = bool(body.get("save", auto_save))

    if not rules_list:
        return jsonify({"success": False, "error": "No rules provided"}), 400
    if len(rules_list) > max_rules:
        return jsonify({"success": False, "error": f"Too many rules (max {max_rules})"}), 400
    if len(events_list) > max_events:
        events_list = events_list[:max_events]
        logger.warning("Event list truncated to %d", max_events)

    try:
        result = _engine.analyze(
            rules=rules_list,
            events=events_list,
            time_window_hours=window,
            label=label,
            save=save,
        )
        return jsonify({"success": True, "report": result})
    except Exception as exc:
        logger.error("Analysis error: %s", exc, exc_info=True)
        return jsonify({"success": False, "error": str(exc)}), 500


def _parse_rules_from_upload() -> list[dict]:
    """Parse rules from a multipart upload or form field."""
    rules_list: list[dict] = []

    # File upload
    if "rules_file" in request.files:
        f = request.files["rules_file"]
        try:
            raw = f.read().decode("utf-8", errors="replace")
            rules_list = _split_sigma_yaml(raw)
        except Exception as exc:
            logger.warning("Failed to parse rules file: %s", exc)

    # Inline YAML text field
    elif "rules_yaml" in request.form:
        raw = request.form["rules_yaml"]
        rules_list = _split_sigma_yaml(raw)

    return rules_list


def _parse_events_from_upload() -> list[dict]:
    """Parse events from a multipart upload or form field."""
    events_list: list[dict] = []

    if "events_file" in request.files:
        f = request.files["events_file"]
        try:
            raw = f.read().decode("utf-8", errors="replace")
            events_list = _parse_events_json(raw)
        except Exception as exc:
            logger.warning("Failed to parse events file: %s", exc)

    elif "events_json" in request.form:
        raw = request.form["events_json"]
        events_list = _parse_events_json(raw)

    return events_list


def _split_sigma_yaml(raw: str) -> list[dict]:
    """
    Split a YAML string containing one or more Sigma rules
    (separated by --- document markers) into a list of rule dicts.
    """
    import re
    # Split on --- document separator
    docs = re.split(r'\n---\s*\n', raw.strip())
    rules = []
    for i, doc in enumerate(docs):
        doc = doc.strip()
        if not doc:
            continue
        # Try to extract a title for rule_id
        rule_id = f"rule_{i+1}"
        try:
            parsed = yaml.safe_load(doc) or {}
            if isinstance(parsed, dict):
                rule_id = parsed.get("id") or parsed.get("title") or rule_id
        except Exception:
            pass
        rules.append({"rule_id": str(rule_id), "sigma_yaml": doc})
    return rules


def _parse_events_json(raw: str) -> list[dict]:
    """Parse events from a JSON string. Supports array or NDJSON."""
    raw = raw.strip()
    if raw.startswith("["):
        # JSON array
        data = json.loads(raw)
        if isinstance(data, list):
            return [e for e in data if isinstance(e, dict)]
    else:
        # NDJSON (one JSON object per line)
        events = []
        for line in raw.splitlines():
            line = line.strip()
            if line:
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        events.append(obj)
                except Exception:
                    pass
        return events
    return []


# ── API: validate single rule ─────────────────────────────────────────────────

@app.route("/api/validate", methods=["POST"])
def api_validate():
    """
    Validate a single rule against events.

    Body: {"rule": {"sigma_yaml": "..."}, "events": [{ECS-lite}]}
    """
    body   = request.get_json(silent=True) or {}
    rule   = body.get("rule") or {}
    events = body.get("events") or []

    if not rule.get("sigma_yaml"):
        return jsonify({"success": False, "error": "rule.sigma_yaml is required"}), 400

    result = _engine.validate_rule(rule, events)
    return jsonify(result)


# ── API: reports list ─────────────────────────────────────────────────────────

@app.route("/api/reports")
def api_reports():
    page     = max(1, int(request.args.get("page", 1)))
    per_page = max(1, min(200, int(request.args.get("per_page", 50))))
    search   = request.args.get("search", "")
    result   = _engine.get_reports(page=page, per_page=per_page, search=search)
    return jsonify({"success": True, **result})


# ── API: single report ────────────────────────────────────────────────────────

@app.route("/api/report/<report_id>")
def api_report(report_id: str):
    report = _engine.get_report(report_id)
    if report is None:
        return jsonify({"success": False, "error": "Report not found"}), 404
    return jsonify({"success": True, "report": report})


@app.route("/api/report/<report_id>", methods=["DELETE"])
def api_report_delete(report_id: str):
    deleted = _engine.delete_report(report_id)
    if not deleted:
        return jsonify({"success": False, "error": "Report not found"}), 404
    return jsonify({"success": True, "deleted": report_id})


# ── API: export report ────────────────────────────────────────────────────────

@app.route("/api/report/<report_id>/export")
def api_export(report_id: str):
    fmt    = request.args.get("format", "json").lower()
    report = _engine.get_report(report_id)
    if report is None:
        return jsonify({"success": False, "error": "Report not found"}), 404

    ts       = (report.get("analyzed_at") or "")[:10].replace("-", "")
    filename = f"driftwatch_report_{ts}"

    if fmt == "markdown":
        md       = _engine.to_markdown(report)
        md_bytes = md.encode("utf-8")
        return send_file(
            io.BytesIO(md_bytes),
            mimetype="text/markdown",
            as_attachment=True,
            download_name=f"{filename}.md",
        )

    json_bytes = json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
    return send_file(
        io.BytesIO(json_bytes),
        mimetype="application/json",
        as_attachment=True,
        download_name=f"{filename}.json",
    )


# ── API: pull rules from SigmaForge ──────────────────────────────────────────

@app.route("/api/integrations/sigmaforge/rules")
def api_sigmaforge_rules():
    """
    Proxy: pull rule list from SigmaForge at port 5000.
    Returns {"success": bool, "rules": [...], "error": str|None}
    """
    try:
        import requests as req
        sf_url = _config.get("integrations", {}).get("sigmaforge_url", "http://127.0.0.1:5000")
        resp   = req.get(f"{sf_url}/api/library/list", timeout=4)
        if resp.status_code == 200:
            data = resp.json()
            return jsonify({"success": True, "rules": data.get("rules", []), "source": "sigmaforge"})
        return jsonify({"success": False, "error": f"SigmaForge returned {resp.status_code}", "rules": []})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc), "rules": []})


# ── CLI entry point ───────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="DriftWatch — Flask web app")
    p.add_argument("--config",    default="config.yaml")
    p.add_argument("--port",      type=int, default=None)
    p.add_argument("--debug",     action="store_true")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.getLogger().setLevel(args.log_level)
    create_app(args.config)
    port = args.port if args.port is not None else int(_config.get("port", 5008))
    logger.info("DriftWatch starting on http://127.0.0.1:%d", port)
    app.run(debug=args.debug, host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()
