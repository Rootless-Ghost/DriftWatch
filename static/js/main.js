/* DriftWatch — Main JavaScript */

'use strict';

// ── Utility ───────────────────────────────────────────────────────────────────

function esc(str) {
    return String(str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Count YAML documents separated by ---
function countRules(yaml) {
    if (!yaml.trim()) return 0;
    const parts = yaml.split(/^---\s*$/m).filter(p => p.trim().length > 0);
    return parts.length || (yaml.trim() ? 1 : 0);
}

// Count events from JSON array or NDJSON
function countEvents(text) {
    if (!text.trim()) return 0;
    const t = text.trim();
    if (t.startsWith('[')) {
        try {
            return JSON.parse(t).length;
        } catch {
            return '?';
        }
    }
    // NDJSON
    return t.split('\n').filter(l => l.trim()).length;
}

// ── File upload helpers ───────────────────────────────────────────────────────

function setupDropZone(zoneId, fileInputId, textareaId, counterId, mode) {
    const zone  = document.getElementById(zoneId);
    const input = document.getElementById(fileInputId);
    const ta    = document.getElementById(textareaId);
    const ctr   = document.getElementById(counterId);
    if (!zone || !input || !ta) return;

    function updateCounter(text) {
        if (!ctr) return;
        if (mode === 'rules') {
            const n = countRules(text);
            ctr.textContent = `${n} rule${n !== 1 ? 's' : ''} loaded`;
        } else {
            const n = countEvents(text);
            ctr.textContent = `${n} event${n !== 1 ? 's' : ''} loaded`;
        }
    }

    function readFile(file) {
        const reader = new FileReader();
        reader.onload = (e) => {
            ta.value = e.target.result;
            updateCounter(e.target.result);
        };
        reader.readAsText(file);
    }

    zone.addEventListener('dragover', (e) => {
        e.preventDefault();
        zone.classList.add('drag-over');
    });
    zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (file) readFile(file);
    });
    zone.addEventListener('click', () => input.click());

    input.addEventListener('change', () => {
        if (input.files[0]) readFile(input.files[0]);
    });

    ta.addEventListener('input', () => updateCounter(ta.value));
}

// ── SigmaForge integration ────────────────────────────────────────────────────

const loadSigmaForgeBtn = document.getElementById('loadSigmaForgeBtn');
if (loadSigmaForgeBtn) {
    loadSigmaForgeBtn.addEventListener('click', async () => {
        loadSigmaForgeBtn.disabled = true;
        loadSigmaForgeBtn.textContent = 'Loading…';
        try {
            const resp = await fetch('/api/integrations/sigmaforge/rules');
            const data = await resp.json();
            if (!data.success) throw new Error(data.error || 'Failed');
            const ta  = document.getElementById('rulesYaml');
            const ctr = document.getElementById('rulesCounter');
            ta.value = data.yaml;
            const n = countRules(data.yaml);
            if (ctr) ctr.textContent = `${n} rule${n !== 1 ? 's' : ''} loaded from SigmaForge`;
            loadSigmaForgeBtn.textContent = `✓ ${n} rules`;
        } catch (err) {
            loadSigmaForgeBtn.textContent = '✗ Error';
            console.error('SigmaForge pull failed:', err);
            setTimeout(() => { loadSigmaForgeBtn.textContent = '↓ SigmaForge'; }, 2000);
        } finally {
            loadSigmaForgeBtn.disabled = false;
        }
    });
}

// ── Analyze ───────────────────────────────────────────────────────────────────

let lastReport = null;

const analyzeBtn    = document.getElementById('analyzeBtn');
const analyzeStatus = document.getElementById('analyzeStatus');
const analyzeText   = document.getElementById('analyzeStatusText');

if (analyzeBtn) {
    analyzeBtn.addEventListener('click', runAnalysis);
}

async function runAnalysis() {
    const rulesYaml  = (document.getElementById('rulesYaml')  || {}).value || '';
    const eventsJson = (document.getElementById('eventsJson') || {}).value || '';

    if (!rulesYaml.trim()) {
        alert('Please enter or upload Sigma rules first.');
        return;
    }

    const timeWindow = parseInt(document.getElementById('timeWindow').value || '168', 10);
    const label      = (document.getElementById('reportLabel') || {}).value || '';
    const threshold  = parseFloat(document.getElementById('overfireThreshold').value || '100');

    analyzeBtn.disabled = true;
    if (analyzeStatus) analyzeStatus.classList.remove('hidden');
    if (analyzeText)   analyzeText.textContent = 'Analyzing…';

    try {
        const body = {
            rules_yaml:         rulesYaml,
            events_json:        eventsJson,
            time_window_hours:  timeWindow,
            label:              label,
            overfire_threshold: threshold,
        };

        const resp = await fetch('/api/analyze', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(body),
        });

        const data = await resp.json();
        if (!data.success) throw new Error(data.error || 'Analysis failed');

        lastReport = data.report;
        renderResults(data.report);

    } catch (err) {
        alert(`Analysis error: ${err.message}`);
    } finally {
        analyzeBtn.disabled = false;
        if (analyzeStatus) analyzeStatus.classList.add('hidden');
    }
}

// ── Render results ────────────────────────────────────────────────────────────

function renderResults(report) {
    const section = document.getElementById('resultsSection');
    if (section) section.classList.remove('hidden');

    const s = report.summary || {};

    // Summary stats
    setText('sumTotal',    s.total_rules   || 0);
    setText('sumNever',    s.never_fired_count || 0);
    setText('sumOver',     s.overfiring_count  || 0);
    setText('sumHealthy',  s.healthy_count     || 0);
    setText('sumCoverage', ((s.coverage_pct || 0).toFixed(1)) + '%');
    setText('sumNoise',    (s.noise_score || 0).toFixed(3));
    setText('sumHits',     (s.total_matches || 0).toLocaleString());

    // View report link
    if (report.id) {
        const link = document.getElementById('viewReportBtn');
        if (link) {
            link.href = `/report/${report.id}`;
            link.classList.remove('hidden');
        }
    }

    // Export buttons
    const exportJson = document.getElementById('exportJsonBtn');
    const exportMd   = document.getElementById('exportMdBtn');
    if (exportJson) {
        exportJson.onclick = () => {
            if (report.id) {
                window.location.href = `/api/report/${report.id}/export?format=json`;
            } else {
                downloadText(JSON.stringify(report, null, 2), 'driftwatch_report.json', 'application/json');
            }
        };
    }
    if (exportMd) {
        exportMd.onclick = () => {
            if (report.id) {
                window.location.href = `/api/report/${report.id}/export?format=markdown`;
            } else {
                alert('Save the report first by running analysis without --no-save.');
            }
        };
    }

    // Gap analysis
    renderGapAnalysis(s.gap_analysis || {});

    // Rule panels
    renderPanel('panelNever',   'panelNeverCount',   report.never_fired || []);
    renderPanel('panelOver',    'panelOverCount',    report.overfiring  || []);
    renderPanel('panelHealthy', 'panelHealthyCount', report.healthy     || []);

    // Scroll to results
    if (section) section.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

function renderGapAnalysis(gap) {
    const card = document.getElementById('gapCard');
    const body = document.getElementById('gapBody');
    if (!card || !body) return;

    const uncovered = gap.uncovered_tactics || [];
    const fpRules   = (gap.low_confidence_rules || []).slice(0, 5);

    let html = `
        <div class="gap-stat">
            <div class="gap-label">Coverage Breadth</div>
            <div class="gap-value">${(gap.coverage_breadth || 0).toFixed(1)}% of tactics</div>
        </div>
        <div class="gap-stat">
            <div class="gap-label">Uncovered Tactics</div>
            <div class="gap-value">
                ${uncovered.length
                    ? uncovered.map(t => `<span class="gap-tactic-tag">${esc(t)}</span>`).join('')
                    : '<span class="gap-ok">All tactics covered</span>'}
            </div>
        </div>
        <div class="gap-stat">
            <div class="gap-label">Never-fired Rate</div>
            <div class="gap-value">${(gap.never_fired_pct || 0).toFixed(1)}%</div>
        </div>
        <div class="gap-stat">
            <div class="gap-label">Overfiring Rate</div>
            <div class="gap-value">${(gap.overfiring_pct || 0).toFixed(1)}%</div>
        </div>
    `;

    if (fpRules.length) {
        html += `
        <div class="gap-stat gap-stat--full">
            <div class="gap-label">High FP Rules</div>
            <div class="gap-value" style="flex-direction:column;gap:4px;">
                ${fpRules.map(r =>
                    `<span class="gap-fp-rule">${esc((r.title||'').slice(0,40))} (${Math.round((r.fp_estimate||0)*100)}%)</span>`
                ).join('')}
            </div>
        </div>`;
    }

    body.innerHTML = html;
    card.classList.remove('hidden');
}

function renderPanel(panelId, countId, rules) {
    const panel = document.getElementById(panelId);
    const count = document.getElementById(countId);
    if (!panel) return;
    if (count) count.textContent = rules.length;

    if (!rules.length) {
        panel.innerHTML = '<div class="panel-empty">No rules in this category</div>';
        return;
    }

    panel.innerHTML = rules.map(r => ruleCardHtml(r)).join('');
}

function ruleCardHtml(r) {
    const coverage = (r.rate_per_hour || 0).toFixed(3);
    const fpPct    = Math.round((r.false_positive_estimate || 0) * 100);
    const lastSeen = r.last_seen ? r.last_seen.slice(0, 19).replace('T', ' ') : null;
    const tactics  = (r.tactics || []).slice(0, 2);
    const status   = r.status || 'never_fired';
    const statusCls = status === 'overfiring' ? 'overfiring' : status;

    const dataJson = esc(JSON.stringify(r));

    return `
    <div class="rule-card rule-card-${statusCls}" onclick='openRuleModal(${JSON.stringify(r)})'>
        <div class="rule-card-header">
            <div class="rule-card-level level-${esc(r.level || 'low')}">${esc(r.level || 'low')}</div>
            ${r.parse_error ? '<span class="rule-error-badge">⚠ parse error</span>' : ''}
        </div>
        <div class="rule-card-title">${esc((r.title || 'Untitled').slice(0, 55))}</div>
        <div class="rule-card-id">${esc(r.rule_id || '')}</div>
        <div class="rule-card-stats">
            <span class="rstat">${r.hit_count} hits</span>
            <span class="rstat">${coverage}/hr</span>
            <span class="rstat fp-stat">FP~${fpPct}%</span>
        </div>
        ${lastSeen ? `<div class="rule-card-last">Last: ${esc(lastSeen)}</div>` : ''}
        ${tactics.length ? `<div class="rule-card-tactics">${tactics.map(t => `<span class="tactic-mini-tag">${esc(t)}</span>`).join('')}</div>` : ''}
    </div>`;
}

// ── Rule detail modal ─────────────────────────────────────────────────────────

function openRuleModal(rule) {
    document.getElementById('modalRuleId').textContent    = rule.rule_id || '';
    document.getElementById('modalRuleTitle').textContent = rule.title   || '';

    // Overview tab
    const fpPct = Math.round((rule.false_positive_estimate || 0) * 100);
    document.getElementById('modalOverview').innerHTML = `
        <div class="modal-stats-grid">
            <div class="mstat">
                <div class="mstat-val">${rule.hit_count}</div>
                <div class="mstat-lbl">Hit Count</div>
            </div>
            <div class="mstat">
                <div class="mstat-val">${(rule.rate_per_hour || 0).toFixed(3)}</div>
                <div class="mstat-lbl">Rate/Hour</div>
            </div>
            <div class="mstat">
                <div class="mstat-val">${fpPct}%</div>
                <div class="mstat-lbl">FP Estimate</div>
            </div>
            <div class="mstat">
                <div class="mstat-val">${esc(rule.level || '—')}</div>
                <div class="mstat-lbl">Level</div>
            </div>
        </div>
        ${rule.description ? `<div class="modal-description">${esc(rule.description)}</div>` : ''}
        ${rule.last_seen   ? `<div class="modal-last-seen">Last seen: ${esc(rule.last_seen)}</div>` : ''}
        ${(rule.tags || []).length ? `<div class="modal-tags">${rule.tags.map(t => `<span class="tag-pill">${esc(t)}</span>`).join('')}</div>` : ''}
        ${rule.parse_error ? `<div class="modal-error">⚠ Parse error: ${esc(rule.parse_error)}</div>` : ''}
        ${rule.match_error ? `<div class="modal-error">⚠ Match error: ${esc(rule.match_error)}</div>` : ''}
    `;

    // Matched events tab
    const evts = rule.matched_events || [];
    document.getElementById('modalEvents').innerHTML = evts.length
        ? `<div class="events-count">${evts.length} matched event(s) shown</div>` +
          evts.map(e => `<pre class="event-pre">${esc(JSON.stringify(e, null, 2))}</pre>`).join('')
        : '<div class="modal-empty">No matched events</div>';

    // Tuning suggestions tab
    const sugs = rule.tuning_suggestions || [];
    document.getElementById('modalSuggestions').innerHTML = sugs.length
        ? sugs.map((s, i) => `
            <div class="suggestion-item">
                <span class="sug-num">${i + 1}</span>
                <span class="sug-text">${esc(s)}</span>
            </div>`).join('')
        : '<div class="modal-empty">No suggestions generated</div>';

    // Reset to overview tab
    document.querySelectorAll('.mtab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.mtab-content').forEach(c => c.classList.remove('active'));
    const overviewBtn = document.querySelector('.mtab-btn[data-mtab="overview"]');
    if (overviewBtn) overviewBtn.classList.add('active');
    const overviewContent = document.getElementById('mtab-overview');
    if (overviewContent) overviewContent.classList.add('active');

    const modal = document.getElementById('ruleModal');
    if (modal) modal.classList.remove('hidden');
}

// ── Modal wiring ──────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {

    // Close modal button
    const closeBtn = document.getElementById('closeModalBtn');
    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            const m = document.getElementById('ruleModal');
            if (m) m.classList.add('hidden');
        });
    }

    // Close on backdrop click
    const ruleModal = document.getElementById('ruleModal');
    if (ruleModal) {
        ruleModal.addEventListener('click', (e) => {
            if (e.target === ruleModal) ruleModal.classList.add('hidden');
        });
    }

    // Tab switching inside modal
    document.querySelectorAll('.mtab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.getAttribute('data-mtab');
            document.querySelectorAll('.mtab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.mtab-content').forEach(c => c.classList.remove('active'));
            btn.classList.add('active');
            const el = document.getElementById('mtab-' + tab);
            if (el) el.classList.add('active');
        });
    });

    // Setup file drop zones
    setupDropZone('rulesDropZone',  'rulesFile',  'rulesYaml',  'rulesCounter',  'rules');
    setupDropZone('eventsDropZone', 'eventsFile', 'eventsJson', 'eventsCounter', 'events');

    // Textarea live counter
    const rulesTA  = document.getElementById('rulesYaml');
    const eventsTA = document.getElementById('eventsJson');
    if (rulesTA) {
        rulesTA.addEventListener('input', () => {
            const ctr = document.getElementById('rulesCounter');
            if (ctr) {
                const n = countRules(rulesTA.value);
                ctr.textContent = `${n} rule${n !== 1 ? 's' : ''} loaded`;
            }
        });
    }
    if (eventsTA) {
        eventsTA.addEventListener('input', () => {
            const ctr = document.getElementById('eventsCounter');
            if (ctr) {
                const n = countEvents(eventsTA.value);
                ctr.textContent = `${n} event${n !== 1 ? 's' : ''} loaded`;
            }
        });
    }
});

// ── Download helper ───────────────────────────────────────────────────────────

function downloadText(content, filename, mime) {
    const blob = new Blob([content], { type: mime || 'text/plain' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}
