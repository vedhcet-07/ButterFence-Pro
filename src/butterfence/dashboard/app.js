/**
 * ButterFence Pro Dashboard — Single Page Application
 * Consumes the ButterFence REST API (/api/*)
 */

const API_BASE = '/api';
const API_KEY = localStorage.getItem('bf_api_key') || 'bf-dev-key-change-me';

// ---------------------------------------------------------------------------
// API Client
// ---------------------------------------------------------------------------

async function api(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const headers = {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
        ...options.headers,
    };

    try {
        const resp = await fetch(url, { ...options, headers });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({ detail: resp.statusText }));
            throw new Error(err.detail || `HTTP ${resp.status}`);
        }
        return await resp.json();
    } catch (e) {
        console.error(`API error [${endpoint}]:`, e);
        throw e;
    }
}

const apiGet = (ep) => api(ep);
const apiPost = (ep, body) => api(ep, { method: 'POST', body: JSON.stringify(body) });
const apiPut = (ep, body) => api(ep, { method: 'PUT', body: JSON.stringify(body) });

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

const pages = {
    'overview': renderOverview,
    'threats': renderThreats,
    'redteam': renderRedTeam,
    'supply-chain': renderSupplyChain,
    'audit-log': renderAuditLog,
    'settings': renderSettings,
};

let currentPage = 'overview';

function navigate(page) {
    currentPage = page;
    document.querySelectorAll('.nav-item').forEach(el => {
        el.classList.toggle('active', el.dataset.page === page);
    });

    const titles = {
        'overview': 'Overview',
        'threats': 'Threats',
        'redteam': 'Red Team',
        'supply-chain': 'Supply Chain',
        'audit-log': 'Audit Log',
        'settings': 'Settings',
    };
    document.getElementById('page-title').textContent = titles[page] || page;
    document.getElementById('last-updated').textContent =
        `Updated: ${new Date().toLocaleTimeString()}`;

    const container = document.getElementById('page-container');
    container.innerHTML = '<div class="loading-state"><div class="spinner"></div> Loading...</div>';

    const render = pages[page];
    if (render) render(container);
}

// Init navigation
document.querySelectorAll('.nav-item').forEach(el => {
    el.addEventListener('click', (e) => {
        e.preventDefault();
        navigate(el.dataset.page);
    });
});

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

function h(tag, attrs = {}, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
        if (k === 'className') el.className = v;
        else if (k === 'innerHTML') el.innerHTML = v;
        else if (k.startsWith('on')) el.addEventListener(k.slice(2).toLowerCase(), v);
        else el.setAttribute(k, v);
    }
    for (const child of children.flat()) {
        if (typeof child === 'string') el.appendChild(document.createTextNode(child));
        else if (child) el.appendChild(child);
    }
    return el;
}

function sevBadge(severity) {
    const s = (severity || '').toLowerCase();
    return `<span class="badge badge-${s}">${s.toUpperCase() || '—'}</span>`;
}

function decBadge(decision) {
    const d = (decision || '').toLowerCase();
    return `<span class="badge badge-${d}">${d.toUpperCase() || '—'}</span>`;
}

function buildGauge(value, max, label, color) {
    const pct = max > 0 ? Math.min(value / max * 100, 100) : 0;
    const r = 70;
    const circ = 2 * Math.PI * r;
    const offset = circ - (pct / 100) * circ;

    return `
        <div class="gauge-container">
            <div class="gauge">
                <svg width="180" height="180" viewBox="0 0 180 180">
                    <circle class="gauge-bg" cx="90" cy="90" r="${r}"/>
                    <circle class="gauge-fill" cx="90" cy="90" r="${r}"
                        style="stroke: ${color}; stroke-dasharray: ${circ}; stroke-dashoffset: ${offset}"/>
                </svg>
                <div class="gauge-text">
                    <div class="gauge-value" style="color: ${color}">${Math.round(pct)}%</div>
                    <div class="gauge-label">${label}</div>
                </div>
            </div>
        </div>
    `;
}

// ---------------------------------------------------------------------------
// Page: Overview
// ---------------------------------------------------------------------------

async function renderOverview(container) {
    try {
        const [threats, health] = await Promise.all([
            apiGet('/threats?limit=10').catch(() => ({ total: 0, threats: [] })),
            fetch('/health').then(r => r.json()).catch(() => ({ status: 'unknown' })),
        ]);

        const blocks = threats.threats.filter(t => t.decision === 'block').length;
        const total = threats.total;

        container.innerHTML = `
            <!-- Stats -->
            <div class="stat-grid">
                <div class="card stat-card danger">
                    <div class="card-title">Total Threats</div>
                    <div class="card-value">${total}</div>
                    <div class="card-subtitle">All recorded interceptions</div>
                </div>
                <div class="card stat-card warning">
                    <div class="card-title">Blocks (Recent)</div>
                    <div class="card-value">${blocks}</div>
                    <div class="card-subtitle">From last ${threats.threats.length} events</div>
                </div>
                <div class="card stat-card success">
                    <div class="card-title">API Status</div>
                    <div class="card-value" style="font-size: 1.6rem; color: var(--accent-green)">
                        ${health.status === 'ok' ? '● Online' : '○ Offline'}
                    </div>
                    <div class="card-subtitle">${health.service || 'butterfence-api'}</div>
                </div>
                <div class="card stat-card info">
                    <div class="card-title">Security Score</div>
                    ${buildGauge(
                        total > 0 ? Math.max(0, 100 - (blocks / Math.max(total, 1) * 100)) : 100,
                        100,
                        'Risk Score',
                        total === 0 ? 'var(--accent-green)' :
                        blocks > total * 0.3 ? 'var(--accent-red)' :
                        blocks > total * 0.1 ? 'var(--accent-yellow)' : 'var(--accent-green)'
                    )}
                </div>
            </div>

            <!-- Recent threats -->
            <div class="card">
                <div class="card-title">Recent Activity</div>
                ${threats.threats.length > 0 ? `
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Decision</th>
                                <th>Tool</th>
                                <th>Category</th>
                                <th>Severity</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${threats.threats.map(t => `
                                <tr>
                                    <td>${decBadge(t.decision)}</td>
                                    <td>${t.tool_name || '—'}</td>
                                    <td>${t.category || '—'}</td>
                                    <td>${sevBadge(t.severity)}</td>
                                    <td style="color: var(--text-muted)">${t.timestamp ? new Date(t.timestamp).toLocaleString() : '—'}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                ` : `
                    <div class="empty-state">
                        <div class="empty-state-icon">🛡️</div>
                        <div class="empty-state-text">No threats recorded yet</div>
                        <div style="color: var(--text-muted)">Events will appear here as ButterFence intercepts commands</div>
                    </div>
                `}
            </div>
        `;
    } catch (e) {
        container.innerHTML = `<div class="alert alert-danger">⚠ Error loading overview: ${e.message}</div>`;
    }
}

// ---------------------------------------------------------------------------
// Page: Threats
// ---------------------------------------------------------------------------

async function renderThreats(container) {
    try {
        const data = await apiGet('/threats?limit=100');

        container.innerHTML = `
            <div class="stat-grid">
                <div class="card stat-card danger">
                    <div class="card-title">Total</div>
                    <div class="card-value">${data.total}</div>
                </div>
                <div class="card stat-card warning">
                    <div class="card-title">Blocks</div>
                    <div class="card-value">${data.threats.filter(t => t.decision === 'block').length}</div>
                </div>
                <div class="card stat-card info">
                    <div class="card-title">Warnings</div>
                    <div class="card-value">${data.threats.filter(t => t.decision === 'warn').length}</div>
                </div>
                <div class="card stat-card success">
                    <div class="card-title">Allowed</div>
                    <div class="card-value">${data.threats.filter(t => t.decision === 'allow').length}</div>
                </div>
            </div>

            <div class="card">
                <div class="card-title">All Threats</div>
                ${data.threats.length > 0 ? `
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Decision</th>
                                <th>Tool</th>
                                <th>Category</th>
                                <th>Severity</th>
                                <th>Reason</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${data.threats.map(t => `
                                <tr>
                                    <td style="color: var(--text-muted)">#${t.id}</td>
                                    <td>${decBadge(t.decision)}</td>
                                    <td>${t.tool_name}</td>
                                    <td>${t.category || '—'}</td>
                                    <td>${sevBadge(t.severity)}</td>
                                    <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis">${t.reason || '—'}</td>
                                    <td style="color: var(--text-muted); white-space: nowrap">${t.timestamp ? new Date(t.timestamp).toLocaleString() : ''}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                ` : `
                    <div class="empty-state">
                        <div class="empty-state-icon">✓</div>
                        <div class="empty-state-text">No threats recorded</div>
                    </div>
                `}
            </div>
        `;
    } catch (e) {
        container.innerHTML = `<div class="alert alert-danger">⚠ ${e.message}</div>`;
    }
}

// ---------------------------------------------------------------------------
// Page: Red Team
// ---------------------------------------------------------------------------

async function renderRedTeam(container) {
    container.innerHTML = `
        <div class="card" style="margin-bottom: 24px">
            <div class="card-title">Launch Red Team Assessment</div>
            <p style="color: var(--text-secondary); margin-bottom: 20px">
                Use AI models to generate novel attack scenarios and test your defenses.
            </p>
            <div class="form-row">
                <div class="input-group">
                    <label class="input-label">Scenarios</label>
                    <input class="input" type="number" id="rt-count" value="5" min="1" max="50">
                </div>
                <div class="input-group">
                    <label class="input-label">Model</label>
                    <select class="input" id="rt-model">
                        <option value="claude">Claude (Anthropic)</option>
                        <option value="gemini">Gemini (Google)</option>
                    </select>
                </div>
            </div>
            <button class="btn btn-danger" id="rt-start" onclick="startRedTeam()">
                🔴 Launch Red Team
            </button>
            <div id="rt-status" style="margin-top: 16px"></div>
        </div>

        <div class="card" id="rt-results">
            <div class="card-title">Previous Scans</div>
            <div class="loading-state"><div class="spinner"></div> Loading...</div>
        </div>
    `;

    // Load previous scans
    try {
        const scans = await apiGet('/threats?limit=5&category=redteam').catch(() => ({ threats: [] }));
        const resultsDiv = document.getElementById('rt-results');
        resultsDiv.innerHTML = `
            <div class="card-title">Previous Scans</div>
            <p style="color: var(--text-muted)">
                Run a red team assessment to see results here.
                Use CLI: <code>butterfence redteam --models claude,gemini</code>
            </p>
        `;
    } catch (e) {
        // ignore
    }
}

async function startRedTeam() {
    const btn = document.getElementById('rt-start');
    const status = document.getElementById('rt-status');
    const count = parseInt(document.getElementById('rt-count').value) || 5;
    const model = document.getElementById('rt-model').value;

    btn.disabled = true;
    btn.textContent = '⏳ Running...';
    status.innerHTML = '<div class="alert alert-warning">🔴 Red team assessment in progress... This may take 30-60 seconds.</div>';

    try {
        // We pass the model as an array in the `models` field. 
        // This triggers the multi-model orchestrator in the backend,
        // which correctly handles Gemini-only executions.
        const result = await apiPost('/redteam/start', { count, models: [model] });
        status.innerHTML = `
            <div class="alert alert-success">
                ✅ ${result.message}<br>
                Scan ID: <strong>${result.scan_id}</strong>
            </div>
        `;
    } catch (e) {
        status.innerHTML = `<div class="alert alert-danger">⚠ ${e.message}</div>`;
    } finally {
        btn.disabled = false;
        btn.textContent = '🔴 Launch Red Team';
    }
}

// ---------------------------------------------------------------------------
// Page: Supply Chain
// ---------------------------------------------------------------------------

async function renderSupplyChain(container) {
    container.innerHTML = `
        <div class="card" style="margin-bottom: 24px">
            <div class="card-title">Scan Dependencies</div>
            <p style="color: var(--text-secondary); margin-bottom: 16px">
                Check for typosquatting, malicious packages, and dependency confusion.
            </p>
            <button class="btn btn-primary" id="sc-scan" onclick="runSupplyChainScan()">
                📦 Scan Now
            </button>
            <div id="sc-status" style="margin-top: 16px"></div>
        </div>
        <div id="sc-results"></div>
    `;
}

async function runSupplyChainScan() {
    const btn = document.getElementById('sc-scan');
    const status = document.getElementById('sc-status');
    const results = document.getElementById('sc-results');

    btn.disabled = true;
    btn.textContent = '⏳ Scanning...';
    status.innerHTML = '<div class="loading-state"><div class="spinner"></div> Scanning dependency files...</div>';

    try {
        const data = await apiPost('/supply-chain/scan', {});

        status.innerHTML = data.total_issues === 0
            ? '<div class="alert alert-success">✅ No supply chain issues found!</div>'
            : `<div class="alert alert-danger">⚠ Found ${data.total_issues} issue(s): ${data.malicious_found} malicious, ${data.typosquats_found} typosquats</div>`;

        if (data.findings.length > 0) {
            results.innerHTML = `
                <div class="card">
                    <div class="card-title">Findings</div>
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>Package</th>
                                <th>File</th>
                                <th>Reason</th>
                                <th>Safe Alternative</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${data.findings.map(f => `
                                <tr>
                                    <td>${sevBadge(f.severity)}</td>
                                    <td><strong>${f.package}</strong></td>
                                    <td style="color: var(--text-muted)">${f.source_file}</td>
                                    <td>${f.reason}</td>
                                    <td style="color: var(--accent-green)">${f.safe_alternative || '—'}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        }
    } catch (e) {
        status.innerHTML = `<div class="alert alert-danger">⚠ ${e.message}</div>`;
    } finally {
        btn.disabled = false;
        btn.textContent = '📦 Scan Now';
    }
}

// ---------------------------------------------------------------------------
// Page: Audit Log
// ---------------------------------------------------------------------------

async function renderAuditLog(container) {
    try {
        const data = await apiGet('/audit-log?limit=50&verify=true');

        container.innerHTML = `
            <div class="stat-grid">
                <div class="card stat-card ${data.chain_valid ? 'success' : 'danger'}">
                    <div class="card-title">Chain Integrity</div>
                    <div class="card-value" style="font-size: 1.4rem; color: ${data.chain_valid ? 'var(--accent-green)' : 'var(--accent-red)'}">
                        ${data.chain_valid ? '✓ Valid' : '✗ TAMPERED'}
                    </div>
                    <div class="card-subtitle">${data.entries_checked} entries verified</div>
                </div>
                <div class="card stat-card info">
                    <div class="card-title">Total Entries</div>
                    <div class="card-value">${data.entries.length}</div>
                </div>
            </div>

            ${!data.chain_valid ? '<div class="alert alert-danger">⚠ Audit log integrity check FAILED — potential tampering detected!</div>' : ''}

            <div class="card">
                <div class="card-title">Audit Log Entries</div>
                ${data.entries.length > 0 ? `
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Type</th>
                                <th>Data</th>
                                <th>Hash</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${data.entries.map(e => `
                                <tr>
                                    <td style="color: var(--text-muted)">#${e.id}</td>
                                    <td><span class="badge badge-medium">${e.event_type}</span></td>
                                    <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; font-size: 0.8rem; color: var(--text-secondary)">
                                        ${JSON.stringify(e.event_data).substring(0, 80)}...
                                    </td>
                                    <td><span class="hash">${e.entry_hash.substring(0, 16)}...</span></td>
                                    <td style="color: var(--text-muted); white-space: nowrap">${e.timestamp ? new Date(e.timestamp).toLocaleString() : ''}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                ` : `
                    <div class="empty-state">
                        <div class="empty-state-icon">📜</div>
                        <div class="empty-state-text">No audit log entries</div>
                    </div>
                `}
            </div>
        `;
    } catch (e) {
        container.innerHTML = `<div class="alert alert-danger">⚠ ${e.message}</div>`;
    }
}

// ---------------------------------------------------------------------------
// Page: Settings
// ---------------------------------------------------------------------------

async function renderSettings(container) {
    container.innerHTML = `
        <div class="section-grid">
            <!-- API Key -->
            <div class="card">
                <div class="card-title">API Key</div>
                <div class="input-group">
                    <label class="input-label">Current API Key</label>
                    <input class="input" type="password" id="settings-key" value="${API_KEY}">
                </div>
                <button class="btn btn-primary" onclick="saveApiKey()">Save Key</button>
                <div id="key-status" style="margin-top: 12px"></div>
            </div>

            <!-- Whitelist -->
            <div class="card">
                <div class="card-title">Add Whitelist Pattern</div>
                <div class="input-group">
                    <label class="input-label">Pattern</label>
                    <input class="input" type="text" id="wl-pattern" placeholder="*.md">
                </div>
                <div class="input-group">
                    <label class="input-label">Reason</label>
                    <input class="input" type="text" id="wl-reason" placeholder="Documentation files">
                </div>
                <button class="btn btn-primary" onclick="addWhitelist()">Add Pattern</button>
                <div id="wl-status" style="margin-top: 12px"></div>
            </div>

            <!-- Custom Rule -->
            <div class="card">
                <div class="card-title">Add Custom Rule</div>
                <div class="input-group">
                    <label class="input-label">Category</label>
                    <input class="input" type="text" id="rule-cat" placeholder="custom_category">
                </div>
                <div class="input-group">
                    <label class="input-label">Pattern (regex)</label>
                    <input class="input" type="text" id="rule-pattern" placeholder="dangerous_command.*">
                </div>
                <div class="form-row">
                    <div class="input-group">
                        <label class="input-label">Action</label>
                        <select class="input" id="rule-action">
                            <option value="block">Block</option>
                            <option value="warn">Warn</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label class="input-label">Severity</label>
                        <select class="input" id="rule-severity">
                            <option value="critical">Critical</option>
                            <option value="high" selected>High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                        </select>
                    </div>
                </div>
                <button class="btn btn-primary" onclick="addCustomRule()">Add Rule</button>
                <div id="rule-status" style="margin-top: 12px"></div>
            </div>

            <!-- Export -->
            <div class="card">
                <div class="card-title">Export Report</div>
                <p style="color: var(--text-secondary); margin-bottom: 16px">Generate a security report.</p>
                <button class="btn btn-ghost" onclick="exportReport('markdown')">📄 Markdown</button>
                <div id="export-status" style="margin-top: 12px"></div>
            </div>
        </div>
    `;
}

function saveApiKey() {
    const key = document.getElementById('settings-key').value;
    localStorage.setItem('bf_api_key', key);
    document.getElementById('key-status').innerHTML =
        '<div class="alert alert-success">✅ API key saved. Reload to apply.</div>';
}

async function addWhitelist() {
    const pattern = document.getElementById('wl-pattern').value;
    const reason = document.getElementById('wl-reason').value;
    if (!pattern) return;

    try {
        const data = await apiPut('/rules/whitelist', { pattern, reason });
        document.getElementById('wl-status').innerHTML =
            `<div class="alert alert-success">✅ ${data.message}</div>`;
    } catch (e) {
        document.getElementById('wl-status').innerHTML =
            `<div class="alert alert-danger">⚠ ${e.message}</div>`;
    }
}

async function addCustomRule() {
    const category = document.getElementById('rule-cat').value;
    const pattern = document.getElementById('rule-pattern').value;
    const action = document.getElementById('rule-action').value;
    const severity = document.getElementById('rule-severity').value;
    if (!category || !pattern) return;

    try {
        const data = await apiPost('/rules/custom', { category, pattern, action, severity });
        document.getElementById('rule-status').innerHTML =
            `<div class="alert alert-success">✅ ${data.message}</div>`;
    } catch (e) {
        document.getElementById('rule-status').innerHTML =
            `<div class="alert alert-danger">⚠ ${e.message}</div>`;
    }
}

async function exportReport(format) {
    try {
        const data = await apiGet(`/report/export?format=${format}`);
        document.getElementById('export-status').innerHTML =
            `<div class="alert alert-success">✅ ${data.message}${data.path ? ` → ${data.path}` : ''}</div>`;
    } catch (e) {
        document.getElementById('export-status').innerHTML =
            `<div class="alert alert-danger">⚠ ${e.message}</div>`;
    }
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

navigate('overview');
