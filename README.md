# DriftWatch — Detection Drift Analyzer

Part of the **Nebula Forge** security tools suite.

DriftWatch identifies detection drift in your Sigma rule sets by correlating rules against normalized log events (ECS-lite). It classifies every rule as **never-fired**, **overfiring**, or **healthy**, and generates per-rule stats, gap analysis, and tuning suggestions.

---

## Features

- **Sigma rule parsing** — full field modifier support (contains, startswith, endswith, re, all, windash, base64, cidr), multi-document YAML files
- **Three-state classification** — never-fired (0 hits), overfiring (>threshold hits/hr), healthy (in range)
- **Per-rule statistics** — hit count, rate/hour, last seen, FP estimate, matched events (sample), hit timeline
- **Gap analysis** — uncovered MITRE tactics, never-fired %, overfiring %, high-FP rules
- **Tuning suggestions** — actionable advice per rule status
- **Report library** — persistent SQLite storage, search, pagination, export
- **Export** — JSON and Markdown formats
- **CLI** — offline analysis without the web UI
- **Integrations** — pull rules from SigmaForge (port 5000), accepts ECS-lite events from LogNorm (port 5006)

---

## Quick Start

```bash
cd DriftWatch
pip install -r requirements.txt
cp config.example.yaml config.yaml   # optional — defaults work out of the box
python app.py
```

Open [http://127.0.0.1:5008](http://127.0.0.1:5008).

---

## Usage

### Web UI

1. Paste or upload Sigma rules (YAML, single or multi-document with `---` separators).
2. Paste or upload ECS-lite events (JSON array or NDJSON).
3. Set the time window, report label, and overfire threshold.
4. Click **Run Analysis**.

Rule cards are clickable — each opens a detail modal with:
- **Overview** — hit count, rate/hr, FP estimate, description, tags
- **Matched Events** — raw event samples (up to 10)
- **Tuning Suggestions** — actionable recommendations

### CLI

```bash
# Analyze rules against events, print summary
python cli.py --rules rules.yml --events events.json

# Directory of rule files, custom window, save to Markdown
python cli.py --rules ./rules/ --events events.json --window 72 --output report.md

# Validate a single rule
python cli.py --validate --rule rule.yml --events events.json

# Print as JSON
python cli.py --rules rules.yml --events events.json --format json

# Skip saving to database
python cli.py --rules rules.yml --events events.json --no-save
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET  | `/api/health` | Health check |
| POST | `/api/analyze` | Run drift analysis |
| POST | `/api/validate` | Validate a single rule |
| GET  | `/api/reports` | List saved reports (paginated) |
| GET  | `/api/report/<id>` | Get a single report |
| DELETE | `/api/report/<id>` | Delete a report |
| GET  | `/api/report/<id>/export` | Export report (JSON or Markdown) |
| GET  | `/api/integrations/sigmaforge/rules` | Fetch rules from SigmaForge |

### POST /api/analyze — JSON body

```json
{
  "rules_yaml":         "title: ...\n---\ntitle: ...",
  "events_json":        "[{...}, {...}]",
  "time_window_hours":  168,
  "label":              "Weekly drift review",
  "overfire_threshold": 100.0
}
```

Also accepts `multipart/form-data` with `rules_file` and `events_file` fields.

### Drift report structure

```json
{
  "id":                "uuid",
  "label":             "Weekly drift review",
  "time_window_hours": 168,
  "event_count":       4821,
  "analyzed_at":       "2025-01-01T12:00:00",
  "summary": {
    "total_rules":       25,
    "never_fired_count": 10,
    "overfiring_count":  3,
    "healthy_count":     12,
    "coverage_pct":      52.0,
    "noise_score":       0.12,
    "total_matches":     1024,
    "gap_analysis": {
      "uncovered_tactics":   ["collection", "exfiltration"],
      "never_fired_pct":     40.0,
      "overfiring_pct":      12.0,
      "coverage_breadth":    60.0,
      "low_confidence_rules": []
    }
  },
  "never_fired":  [ { "rule_id": "...", "title": "...", "hit_count": 0, ... } ],
  "overfiring":   [ ... ],
  "healthy":      [ ... ]
}
```

---

## Supported Sigma Modifiers

| Modifier | Description |
|----------|-------------|
| `contains` | Field contains value (case-insensitive substring) |
| `startswith` | Field starts with value |
| `endswith` | Field ends with value |
| `re` | Field matches regex |
| `all` | All values must match (AND instead of OR) |
| `windash` | Matches both `-` and `/` as flag prefixes |
| `base64` | Value is base64-encoded in event |
| `base64offset` | Handles base64 offset variants (0/1/2) |
| `utf16le` / `wide` | UTF-16LE encoding |
| `cidr` | Network CIDR range matching |
| Wildcards | `*` and `?` glob patterns |

Condition expressions: `and`, `or`, `not`, `all of <name>`, `N of <name>`, `all of them`, `1 of them`.

---

## ECS-lite Field Mappings

DriftWatch maps Sigma field names to ECS-lite dot-notation paths used by LogNorm:

| Sigma field | ECS-lite path |
|-------------|---------------|
| `CommandLine` | `process.command_line` |
| `Image` | `process.executable` |
| `EventID` | `event.code` |
| `DestinationIp` | `destination.ip` |
| `DestinationPort` | `destination.port` |
| `TargetObject` | `registry.path` |
| `ScriptBlockText` | `powershell.script_block_text` |

See `core/field_mappings.py` for the complete mapping table.

---

## Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `host` | `127.0.0.1` | Bind address |
| `port` | `5008` | HTTP port |
| `db_path` | `./driftwatch.db` | SQLite database |
| `analysis.overfire_threshold` | `100.0` | hits/hr overfire cutoff |
| `analysis.default_window_hours` | `168` | Default time window |
| `analysis.max_events` | `100000` | Event input cap |
| `analysis.max_rules` | `500` | Rule input cap |
| `analysis.auto_save` | `true` | Save reports automatically |
| `integrations.sigmaforge_url` | `http://127.0.0.1:5000` | SigmaForge endpoint |
| `integrations.lognorm_url` | `http://127.0.0.1:5006` | LogNorm endpoint |

---

## Nebula Forge Integration

DriftWatch is registered in the Nebula Forge dashboard. Add to `nebula-dashboard/config.yaml`:

```yaml
tools:
  driftwatch:
    label:       "DriftWatch"
    url:         "http://127.0.0.1:5008"
    health_path: "/api/health"
    description: "Detection drift analyzer for Sigma rules"
    category:    "Detection"
```

---

## License

MIT — Copyright (c) 2025 Rootless-Ghost. Part of the Nebula Forge security tools suite.
