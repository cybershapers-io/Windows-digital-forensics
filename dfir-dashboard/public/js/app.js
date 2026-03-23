/* ═══════════════════════════════════════════════
   DFIR Intel Dashboard — Integrated App
   Data Dashboard + AI Risk Intelligence + AbuseIPDB
   ═══════════════════════════════════════════════ */

// ── STATE ──
let appData            = null;
let aiEnabled          = false;
let abuseEnabled       = false;
let currentTab         = 'data';
const tableState       = {};
const riskCache        = {};
const globalRiskCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

// ── SECTION CONFIG ──
const SECTION_CONFIG = {
  network:     { label: 'Network',     icon: '◈' },
  users:       { label: 'Users',       icon: '◉' },
  persistence: { label: 'Persistence', icon: '⬡' },
  processes:   { label: 'Processes',   icon: '⊡' },
  software:    { label: 'Software',    icon: '▣' },
  events:      { label: 'Events',      icon: '◈' },
  devices:     { label: 'Devices',     icon: '⬡' },
  artifacts:   { label: 'Artifacts',   icon: '◉' },
  security:    { label: 'Security',    icon: '▣' },
  other:       { label: 'Other',       icon: '◈' },
};
const SECTION_ORDER = ['network','users','persistence','processes','software','events','devices','artifacts','security','other'];
const PAGE_SIZE = 50;
const IP_SECTIONS = new Set(['network','events','processes','other']);

// ── INIT ──
document.addEventListener('DOMContentLoaded', async () => {
  const health = await fetch('/api/health').then(r => r.json()).catch(() => ({}));
  aiEnabled    = !!health.ai;
  abuseEnabled = !!health.abuseipdb;

  renderEngineBadge(health);
  if (abuseEnabled) document.getElementById('abuseIndicator').classList.remove('hidden');

  setupThemeToggle();
  setupUpload();
  setupAiPanel();

  // Mobile menu
  const menuBtn = document.createElement('button');
  menuBtn.className = 'menu-btn';
  menuBtn.innerHTML = '☰';
  menuBtn.addEventListener('click', () => toggleSidebar());
  document.querySelector('.topbar-left').prepend(menuBtn);

  // Backdrop for mobile sidebar dismiss
  const backdrop = document.createElement('div');
  backdrop.className = 'sidebar-backdrop';
  backdrop.id = 'sidebarBackdrop';
  backdrop.addEventListener('click', () => closeSidebar());
  document.body.appendChild(backdrop);
});

// ── THEME ──
function setupThemeToggle() {
  const btn  = document.getElementById('themeToggle');
  const icon = document.getElementById('themeIcon');
  const saved = localStorage.getItem('dfir-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  icon.textContent = saved === 'dark' ? '☀' : '☽';
  btn.addEventListener('click', () => {
    const cur  = document.documentElement.getAttribute('data-theme');
    const next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    icon.textContent = next === 'dark' ? '☀' : '☽';
    localStorage.setItem('dfir-theme', next);
  });
}

// ── UPLOAD ──
function setupUpload() {
  const dropZone  = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');

  dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault(); dropZone.classList.remove('drag-over');
    if (e.dataTransfer.files[0]) processUpload(e.dataTransfer.files[0]);
  });
  dropZone.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => { if (fileInput.files[0]) processUpload(fileInput.files[0]); });
  document.getElementById('newUploadBtn').addEventListener('click', resetToUpload);
}

async function processUpload(file) {
  if (!file.name.endsWith('.zip')) { showUploadError('Please upload a .zip file'); return; }
  setStatus('Uploading and extracting forensic package…');
  showProgress(true); hideUploadError();
  const fd = new FormData();
  fd.append('zipfile', file);
  try {
    animateProgress(0, 60, 800);
    const res = await fetch('/api/upload', { method: 'POST', body: fd });
    animateProgress(60, 90, 400);
    if (!res.ok) { const e = await res.json(); throw new Error(e.error || 'Upload failed'); }
    const data = await res.json();
    animateProgress(90, 100, 200);
    setTimeout(() => renderDashboard(data), 300);
  } catch (err) {
    showProgress(false);
    showUploadError(err.message);
    setStatus('Upload failed');
  }
}

function animateProgress(from, to, duration) {
  const bar  = document.getElementById('progressBar');
  const text = document.getElementById('progressText');
  const steps = 20, stepTime = duration / steps;
  let i = 0;
  const iv = setInterval(() => {
    i++; const val = from + (to - from) * (i / steps);
    bar.style.width = val + '%';
    text.textContent = val < 30 ? 'Uploading package…' : val < 60 ? 'Extracting files…' : val < 85 ? 'Parsing CSV artifacts…' : 'Rendering dashboard…';
    if (i >= steps) clearInterval(iv);
  }, stepTime);
}

function showProgress(show) { document.getElementById('uploadProgress').classList.toggle('hidden', !show); }
function showUploadError(msg) {
  const el = document.getElementById('uploadError');
  el.textContent = '⚠ ' + msg; el.classList.remove('hidden');
}
function hideUploadError() { document.getElementById('uploadError').classList.add('hidden'); }
function setStatus(msg)    { document.getElementById('statusText').textContent = msg; }

function resetToUpload() {
  document.getElementById('dashboard').classList.add('hidden');
  document.getElementById('uploadScreen').classList.remove('hidden');
  document.getElementById('fileInput').value = '';
  document.getElementById('progressBar').style.width = '0%';
  showProgress(false); hideUploadError();
  setStatus('Awaiting forensic package…');
  appData = null;
  Object.keys(riskCache).forEach(k => delete riskCache[k]);
  Object.assign(globalRiskCounts, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 });
  currentTab = 'data';
}

// ── RENDER DASHBOARD ──
function renderDashboard(data) {
  appData = data;
  document.getElementById('uploadScreen').classList.add('hidden');
  document.getElementById('dashboard').classList.remove('hidden');
  document.getElementById('metaHostname').textContent = data.meta.hostname;
  document.getElementById('metaTime').textContent     = data.meta.timestamp;
  setStatus(`Analysing: ${data.meta.hostname} · ${data.meta.timestamp}`);

  renderStatCards(data);
  renderSidebarNav(data.sections);
  renderDataSections(data.sections);
  renderRiskSections(data.sections);

  document.getElementById('analyzeAllBtn').addEventListener('click', () => {
    switchSidebarTab('risks'); analyzeAllSections();
  });
  document.getElementById('analyzeAllSectionsBtn')?.addEventListener('click', analyzeAllSections);
  switchSidebarTab('data');
}

function renderStatCards(data) {
  document.getElementById('statCards').innerHTML = [
    { label: 'Data Sections',  value: Object.keys(data.sections).length },
    { label: 'Artifact Files', value: data.stats.totalCSVs },
    { label: 'Total Records',  value: data.stats.totalRows.toLocaleString() },
    { label: 'Host',           value: data.meta.hostname },
  ].map(c => `<div class="stat-card"><div class="stat-value">${c.value}</div><div class="stat-label">${c.label}</div></div>`).join('');
}

function renderSidebarNav(sections) {
  const nav = document.getElementById('sidebarNav');
  nav.innerHTML = '<div class="nav-section-label">Artifacts</div>';
  sectionOrder(sections).forEach(key => {
    const cfg = SECTION_CONFIG[key] || { label: key, icon: '◈' };
    const totalRows = sections[key].reduce((a, t) => a + t.rows.length, 0);
    const item = document.createElement('div');
    item.className = 'nav-item'; item.dataset.section = key;
    item.innerHTML = `<span class="nav-item-icon">${cfg.icon}</span><span>${cfg.label}</span><span class="nav-item-count">${totalRows.toLocaleString()}</span>`;
    item.addEventListener('click', () => {
      document.querySelectorAll('#sidebarNav .nav-item').forEach(n => n.classList.remove('active'));
      item.classList.add('active');
      if (currentTab !== 'data') switchSidebarTab('data');
      document.getElementById('section-' + key)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      closeSidebar();
    });
    nav.appendChild(item);
  });
}

// ── RISK SECTIONS ──
function renderRiskSections(sections) {
  const container = document.getElementById('riskResultsContainer');
  container.innerHTML = '';
  const ordered = sectionOrder(sections);

  ordered.forEach(key => {
    const cfg    = SECTION_CONFIG[key] || { label: key, icon: '◈' };
    const hasIPs = IP_SECTIONS.has(key);
    const block  = document.createElement('div');
    block.className = 'risk-section-block';
    block.id = 'risk-block-' + key;

    block.innerHTML = `
      <div class="risk-section-header" onclick="toggleRiskBlock('${key}')">
        <span class="risk-section-icon">${cfg.icon}</span>
        <span class="risk-section-title">${cfg.label}</span>
        <div class="risk-section-meta" id="risk-meta-${key}">
          ${abuseEnabled && hasIPs
            ? `<button class="btn-ip-scan" onclick="event.stopPropagation();scanSectionIPs('${key}')">🌐 Scan IPs</button>`
            : ''}
          ${aiEnabled
            ? `<button class="btn-risk" onclick="event.stopPropagation();runRiskAnalysis('${key}')">⚡ Analyse</button>`
            : '<span style="color:var(--text-muted);font-size:0.72rem">AI unavailable</span>'}
        </div>
      </div>
      <div class="collapsible" id="risk-body-${key}">
        <div class="risk-section-loading hidden" id="risk-loading-${key}">
          <div class="spinner"></div><span>Analysing with AI…</span>
        </div>
        <div id="ip-panel-${key}" class="ip-scan-panel hidden"></div>
        <div id="risk-results-${key}">
          <div class="risk-placeholder">Click ⚡ Analyse to run AI risk assessment${abuseEnabled && hasIPs ? ', or 🌐 Scan IPs to check IP reputation.' : '.'}</div>
        </div>
      </div>
    `;
    container.appendChild(block);
  });

  buildRiskSidebarNav(ordered);
}

function buildRiskSidebarNav(orderedKeys) {
  const nav = document.getElementById('riskNavItems');
  nav.innerHTML = '';
  orderedKeys.forEach(key => {
    const cfg  = SECTION_CONFIG[key] || { label: key, icon: '◈' };
    const item = document.createElement('div');
    item.className = 'risk-nav-item'; item.dataset.section = key;
    item.innerHTML = `<span class="nav-item-icon">${cfg.icon}</span><span class="rni-label">${cfg.label}</span><span class="rni-count" id="rni-count-${key}">—</span>`;
    item.addEventListener('click', () => {
      if (currentTab !== 'risks') switchSidebarTab('risks');
      document.getElementById('risk-block-' + key)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      document.querySelectorAll('#riskNavItems .risk-nav-item').forEach(n => n.classList.remove('active'));
      item.classList.add('active');
      closeSidebar();
    });
    nav.appendChild(item);
  });
}

function sectionOrder(sections) {
  return [...SECTION_ORDER.filter(s => sections[s]), ...Object.keys(sections).filter(s => !SECTION_ORDER.includes(s))];
}

// ── SIDEBAR TAB SWITCH ──
function switchSidebarTab(tab) {
  currentTab = tab;
  document.getElementById('stabData').classList.toggle('active',  tab === 'data');
  document.getElementById('stabRisks').classList.toggle('active', tab === 'risks');
  document.getElementById('sidebarNav').classList.toggle('hidden',     tab !== 'data');
  document.getElementById('riskNav').classList.toggle('hidden',        tab !== 'risks');
  document.getElementById('dataSections').classList.toggle('hidden',   tab !== 'data');
  document.getElementById('overviewSection').classList.toggle('hidden', tab !== 'data');
  document.getElementById('riskSections').classList.toggle('hidden',   tab !== 'risks');
}

// ── DATA SECTIONS ──
function renderDataSections(sections) {
  const container = document.getElementById('dataSections');
  container.innerHTML = '';
  sectionOrder(sections).forEach(key => {
    const cfg    = SECTION_CONFIG[key] || { label: key, icon: '◈' };
    const tables = sections[key];
    const totalRows = tables.reduce((a, t) => a + t.rows.length, 0);
    const hasIPs    = IP_SECTIONS.has(key);

    const group = document.createElement('div');
    group.className = 'data-section-group'; group.id = 'section-' + key;
    group.innerHTML = `
      <div class="group-header">
        <span class="group-icon">${cfg.icon}</span>
        <span class="group-title">${cfg.label}</span>
        <span class="group-badge">${totalRows.toLocaleString()} records</span>
        ${abuseEnabled && hasIPs
          ? `<button class="btn-ip-scan" onclick="switchSidebarTab('risks');scanSectionIPs('${key}');document.getElementById('risk-block-${key}')?.scrollIntoView({behavior:'smooth'})">🌐 Scan IPs</button>`
          : ''}
        ${aiEnabled
          ? `<button class="btn-risk" onclick="switchSidebarTab('risks');runRiskAnalysis('${key}');document.getElementById('risk-block-${key}')?.scrollIntoView({behavior:'smooth'})">⚡ Risk Analysis</button>`
          : ''}
        <button class="btn-secondary btn-sm" onclick="toggleGroup('${key}')">▾</button>
      </div>
      <div class="collapsible" id="group-body-${key}">
        ${tables.map(t => renderTableCard(t)).join('')}
      </div>`;
    container.appendChild(group);
    tables.forEach(t => initTableState(t));
  });
}

function toggleGroup(key) { document.getElementById('group-body-' + key)?.classList.toggle('collapsed'); }

// ── TABLE RENDERING ──
function renderTableCard(table) {
  const id   = table.id;
  const cols = table.columns.slice(0, 10);
  return `
    <div class="table-card" id="card-${id}">
      <div class="table-card-header">
        <span class="table-card-title">${table.label}</span>
        <span class="table-card-count mono">${table.rows.length} rows</span>
        <div class="table-controls">
          <input type="text" class="search-input" placeholder="Search…" id="search-${id}" oninput="filterTable('${id}')" />
          ${cols.length > 1
            ? `<select class="filter-select" id="colfilter-${id}" onchange="filterTable('${id}')">
                <option value="">All columns</option>
                ${cols.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join('')}
               </select>` : ''}
          <button class="export-btn" onclick="exportCSV('${id}')">↓ CSV</button>
          <button class="collapse-toggle" onclick="toggleCard('${id}')">▾</button>
        </div>
      </div>
      <div class="collapsible" id="body-${id}">
        <div class="table-wrap" id="tablewrap-${id}"></div>
        <div class="table-footer">
          <div class="page-info" id="pageinfo-${id}"></div>
          <div class="pagination" id="pagination-${id}"></div>
        </div>
      </div>
    </div>`;
}

function initTableState(table) {
  tableState[table.id] = { rows: table.rows, columns: table.columns.slice(0,10), filtered: table.rows, page: 1, sortCol: null, sortDir: 'asc', label: table.label };
  renderTable(table.id);
}

function renderTable(id) {
  const state = tableState[id]; if (!state) return;
  const wrap  = document.getElementById('tablewrap-' + id); if (!wrap) return;
  const { filtered, page, columns, sortCol, sortDir } = state;
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage   = Math.min(page, totalPages); state.page = safePage;
  const start = (safePage - 1) * PAGE_SIZE;
  const pageRows  = filtered.slice(start, start + PAGE_SIZE);
  const searchTerm = document.getElementById('search-' + id)?.value || '';

  let html = `<table class="data-table"><thead><tr>`;
  columns.forEach(col => {
    const cls = sortCol === col ? (sortDir === 'asc' ? 'sorted-asc' : 'sorted-desc') : '';
    html += `<th class="${cls}" onclick="sortTable('${id}','${esc(col)}')">${esc(col)}</th>`;
  });
  html += `<th style="width:30px"></th></tr></thead><tbody>`;

  if (!pageRows.length) {
    html += `<tr><td colspan="${columns.length+1}" class="empty-state">No records found</td></tr>`;
  } else {
    pageRows.forEach((row, ri) => {
      html += '<tr>';
      columns.forEach(col => {
        const val = String(row[col] ?? '');
        html += `<td title="${esc(val)}">${searchTerm ? highlight(esc(val), searchTerm) : esc(val)}</td>`;
      });
      html += `<td><button class="export-btn btn-sm" title="Explain row" onclick="explainRow('${id}',${start+ri})">⬡</button></td></tr>`;
    });
  }
  html += '</tbody></table>';
  wrap.innerHTML = html;

  document.getElementById('pageinfo-' + id).textContent = `${filtered.length} records · Page ${safePage}/${totalPages}`;
  let pHtml = `<button class="page-btn" onclick="goPage('${id}',${safePage-1})" ${safePage<=1?'disabled':''}>‹</button>`;
  let pStart = Math.max(1, safePage-2), pEnd = Math.min(totalPages, pStart+4);
  if (pEnd-pStart < 4) pStart = Math.max(1, pEnd-4);
  for (let p = pStart; p <= pEnd; p++) pHtml += `<button class="page-btn ${p===safePage?'active':''}" onclick="goPage('${id}',${p})">${p}</button>`;
  pHtml += `<button class="page-btn" onclick="goPage('${id}',${safePage+1})" ${safePage>=totalPages?'disabled':''}>›</button>`;
  document.getElementById('pagination-' + id).innerHTML = pHtml;
}

function filterTable(id) {
  const state = tableState[id]; if (!state) return;
  const query = document.getElementById('search-' + id)?.value.toLowerCase() || '';
  const col   = document.getElementById('colfilter-' + id)?.value || '';
  state.filtered = state.rows.filter(row =>
    !query ? true : col ? String(row[col]??'').toLowerCase().includes(query)
                        : Object.values(row).some(v => String(v??'').toLowerCase().includes(query))
  );
  state.page = 1; renderTable(id);
}

function sortTable(id, col) {
  const state = tableState[id]; if (!state) return;
  if (state.sortCol === col) state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
  else { state.sortCol = col; state.sortDir = 'asc'; }
  state.filtered = [...state.filtered].sort((a,b) => {
    const av = String(a[col]??'').toLowerCase(), bv = String(b[col]??'').toLowerCase();
    return state.sortDir === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av);
  });
  renderTable(id);
}

function goPage(id, page) {
  const state = tableState[id]; if (!state) return;
  state.page = Math.max(1, Math.min(page, Math.ceil(state.filtered.length / PAGE_SIZE)));
  renderTable(id);
}

function toggleCard(id) { document.getElementById('body-' + id)?.classList.toggle('collapsed'); }

function exportCSV(id) {
  const state = tableState[id]; if (!state) return;
  const cols = state.columns;
  let csv = cols.map(c => `"${c}"`).join(',') + '\n';
  state.filtered.forEach(row => { csv += cols.map(c => `"${String(row[c]??'').replace(/"/g,'""')}"`).join(',') + '\n'; });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = `${state.label.replace(/\s+/g,'_')}.csv`; a.click();
}

// ══════════════════════════════════════════════════════
// AI RISK ANALYSIS
// ══════════════════════════════════════════════════════

async function runRiskAnalysis(key) {
  if (!aiEnabled) { alert('AI engine not configured. Set LM_STUDIO_BASE_URL, OPENAI_API_KEY, or ANTHROPIC_API_KEY in your .env file, then restart the server.'); return; }
  if (riskCache[key]) { renderRiskResults(key, riskCache[key]); return; }

  const tables    = appData?.sections[key] || [];
  const loadingEl = document.getElementById('risk-loading-' + key);
  const resultsEl = document.getElementById('risk-results-' + key);

  if (loadingEl) loadingEl.classList.remove('hidden');
  if (resultsEl) resultsEl.innerHTML = '';
  document.getElementById('risk-block-' + key)?.scrollIntoView({ behavior: 'smooth', block: 'start' });

  try {
    const res = await fetch('/api/risks/analyse', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        section:   key,
        datasets:  tables.map(t => ({ label: t.label, columns: t.columns, rows: t.rows.slice(0,30) })),
        hostname:  appData?.meta?.hostname,
        timestamp: appData?.meta?.timestamp
      })
    });
    const result = await res.json();
    if (result.error) throw new Error(result.error);

    riskCache[key] = result;
    addToGlobalCounts(result.risks || []);
    renderRiskResults(key, result);
    updateNavBadge(key, result.risks || []);
    updateTopbarCounters();
    updateRiskOverviewStrip();
  } catch (err) {
    if (loadingEl) loadingEl.classList.add('hidden');
    if (resultsEl) resultsEl.innerHTML = `<div class="risk-error">⚠ ${esc(err.message)}</div>`;
  }
}

function renderRiskResults(key, result) {
  const loadingEl = document.getElementById('risk-loading-' + key);
  const resultsEl = document.getElementById('risk-results-' + key);
  const metaEl    = document.getElementById('risk-meta-' + key);
  if (loadingEl) loadingEl.classList.add('hidden');

  const risks  = result.risks || [];
  const counts = countBySeverity(risks);
  const hasIPs = IP_SECTIONS.has(key);

  if (metaEl) {
    metaEl.innerHTML = `
      ${counts.CRITICAL ? `<span class="risk-sev-badge CRITICAL">${counts.CRITICAL} Critical</span>` : ''}
      ${counts.HIGH     ? `<span class="risk-sev-badge HIGH">${counts.HIGH} High</span>` : ''}
      ${counts.MEDIUM   ? `<span class="risk-sev-badge MEDIUM">${counts.MEDIUM} Med</span>` : ''}
      ${counts.LOW      ? `<span class="risk-sev-badge LOW">${counts.LOW} Low</span>` : ''}
      ${abuseEnabled && hasIPs
        ? `<button class="btn-ip-scan" onclick="event.stopPropagation();scanSectionIPs('${key}')">🌐 Scan IPs</button>`
        : ''}
      <button class="btn-risk" onclick="event.stopPropagation();delete riskCache['${key}'];runRiskAnalysis('${key}')">↺ Re-analyse</button>`;
  }

  if (!resultsEl) return;

  const SEV_ORDER = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
  const sorted    = [...risks].sort((a,b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));

  let html = result.summary ? `<div class="risk-section-summary">${esc(result.summary)}</div>` : '';
  html += `<div class="risk-section-body">`;

  if (!sorted.length) {
    html += `<div class="risk-placeholder">No significant risks identified.</div>`;
  } else {
    sorted.forEach((risk, idx) => {
      const uid    = `${key}-${idx}`;
      const isOpen = risk.severity === 'CRITICAL' || risk.severity === 'HIGH';
      const ipsInAffected  = extractIPsFromText(risk.affected || '');
      const ipContainerId  = `ip-inline-${uid}`;

      html += `
        <div class="risk-card ${isOpen ? 'open' : ''}" id="rcard-${uid}">
          <div class="risk-card-header" onclick="toggleRiskCard('${uid}')">
            <span class="risk-sev-badge ${risk.severity}">${risk.severity}</span>
            <span class="risk-card-title">${esc(risk.title)}</span>
            <span class="risk-chevron">▼</span>
          </div>
          <div class="risk-card-body">
            <p class="risk-description">${esc(risk.description)}</p>
            <div class="risk-detail-grid">`;

      if (risk.affected) {
        html += `
          <div class="risk-detail-block ${!risk.nist ? 'full' : ''}">
            <div class="rdb-label">Affected
              ${abuseEnabled && ipsInAffected.length
                ? `<button class="btn-ip-scan-inline" onclick="event.stopPropagation();scanInlineIPs(${JSON.stringify(ipsInAffected)},'${ipContainerId}')">🌐 Check ${ipsInAffected.length} IP${ipsInAffected.length>1?'s':''}</button>`
                : ''}
            </div>
            <div class="rdb-content">${esc(risk.affected)}</div>
            <div id="${ipContainerId}" class="ip-inline-results hidden"></div>
          </div>`;
      }

      if (risk.nist) {
        html += `
          <div class="risk-detail-block">
            <div class="rdb-label">NIST SP 800-53</div>
            <div class="rdb-content">${esc(risk.nist)}</div>
          </div>`;
      }

      if (risk.cis_controls?.length) {
        html += `
          <div class="risk-detail-block ${!risk.nist && !risk.affected ? 'full' : ''}">
            <div class="rdb-label">CIS Controls v8</div>
            <div class="rdb-content">${risk.cis_controls.map(c => `<span class="cis-tag">${esc(c)}</span>`).join('')}</div>
          </div>`;
      }

      if (risk.remediation?.length) {
        html += `
          <div class="risk-detail-block full">
            <div class="rdb-label">Remediation Steps</div>
            <div class="rdb-content">
              ${risk.remediation.map((step, i) => `
                <div class="fix-step">
                  <span class="fix-num">${i+1}.</span>
                  <span class="fix-text">${formatStep(esc(step))}</span>
                </div>`).join('')}
            </div>
          </div>`;
      }

      html += `</div></div></div>`;
    });
  }

  html += `</div>`;
  resultsEl.innerHTML = html;
}

function toggleRiskCard(uid) { document.getElementById('rcard-' + uid)?.classList.toggle('open'); }
function toggleRiskBlock(key) { document.getElementById('risk-body-' + key)?.classList.toggle('collapsed'); }

async function analyzeAllSections() {
  if (!aiEnabled) { alert('AI engine not configured. Set LM_STUDIO_BASE_URL, OPENAI_API_KEY, or ANTHROPIC_API_KEY in your .env file, then restart the server.'); return; }
  if (!appData) return;
  switchSidebarTab('risks');
  for (const key of sectionOrder(appData.sections)) {
    if (!riskCache[key]) {
      await runRiskAnalysis(key);
      await new Promise(r => setTimeout(r, 800));
    }
  }
}

function addToGlobalCounts(risks) {
  risks.forEach(r => { if (globalRiskCounts[r.severity] !== undefined) globalRiskCounts[r.severity]++; });
}

function updateTopbarCounters() {
  document.getElementById('riskCounters').classList.remove('hidden');
  document.getElementById('rcCritical').textContent = globalRiskCounts.CRITICAL + ' Critical';
  document.getElementById('rcHigh').textContent     = globalRiskCounts.HIGH     + ' High';
  document.getElementById('rcMedium').textContent   = globalRiskCounts.MEDIUM   + ' Med';
  document.getElementById('rcLow').textContent      = globalRiskCounts.LOW      + ' Low';
}

function updateRiskOverviewStrip() {
  document.getElementById('riskOverviewStrip').classList.remove('hidden');
  document.getElementById('rosPills').innerHTML = [
    globalRiskCounts.CRITICAL ? `<span class="ros-pill ros-critical">${globalRiskCounts.CRITICAL} Critical</span>` : '',
    globalRiskCounts.HIGH     ? `<span class="ros-pill ros-high">${globalRiskCounts.HIGH} High</span>`             : '',
    globalRiskCounts.MEDIUM   ? `<span class="ros-pill ros-medium">${globalRiskCounts.MEDIUM} Medium</span>`       : '',
    globalRiskCounts.LOW      ? `<span class="ros-pill ros-low">${globalRiskCounts.LOW} Low</span>`                : '',
  ].join('');
}

function updateNavBadge(key, risks) {
  const el = document.getElementById('rni-count-' + key); if (!el) return;
  const c  = countBySeverity(risks);
  el.textContent = c.CRITICAL ? c.CRITICAL+' crit' : c.HIGH ? c.HIGH+' high' : risks.length+' risks';
  const badge = document.getElementById('stabRiskCount');
  if (badge) badge.textContent = Object.values(riskCache).reduce((a,r) => a+(r.risks?.length||0), 0);
}

function countBySeverity(risks) {
  const c = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, INFO:0 };
  risks.forEach(r => { if (c[r.severity]!==undefined) c[r.severity]++; });
  return c;
}

// ── ROW EXPLAIN ──
function setupAiPanel() {
  document.getElementById('closeAiPanel').addEventListener('click', () => {
    document.getElementById('aiPanel').classList.remove('open');
    document.getElementById('mainContent').classList.remove('ai-open');
  });
}

function explainRow(tableId, rowIndex) {
  if (!aiEnabled) { alert('AI engine not configured. Set LM_STUDIO_BASE_URL, OPENAI_API_KEY, or ANTHROPIC_API_KEY in your .env file, then restart the server.'); return; }
  const state = tableState[tableId]; if (!state) return;
  const row   = state.filtered[rowIndex]; if (!row) return;

  document.getElementById('explainModal').classList.remove('hidden');
  document.getElementById('explainModalBody').innerHTML = `<div class="spinner-wrap"><div class="spinner"></div><div class="spinner-label">Analysing row…</div></div>`;

  fetch('/api/analysis/explain', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rowData: row, context: state.label })
  }).then(r => r.json()).then(data => {
    const body = document.getElementById('explainModalBody');
    body.innerHTML = data.error ? `<div class="upload-error">${data.error}</div>` : `
      <div style="margin-bottom:14px;padding:10px;background:var(--bg-surface);border-radius:4px;font-family:var(--font-mono);font-size:0.72rem;color:var(--text-secondary);">
        ${Object.entries(row).map(([k,v]) => `<span style="color:var(--accent)">${esc(k)}</span>: ${esc(String(v??''))}`).join('<br>')}
      </div>
      <div style="line-height:1.7;">${data.explanation}</div>`;
  }).catch(err => {
    document.getElementById('explainModalBody').innerHTML = `<div class="upload-error">${err.message}</div>`;
  });
}

function closeExplainModal() { document.getElementById('explainModal').classList.add('hidden'); }
document.getElementById('explainModal')?.addEventListener('click', e => { if (e.target.id === 'explainModal') closeExplainModal(); });

// ── HELPERS ──
function esc(str) {
  return String(str ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function highlight(text, query) {
  const re = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')})`, 'gi');
  return text.replace(re, '<mark>$1</mark>');
}
function formatStep(s) { return s.replace(/`([^`]+)`/g, '<code>$1</code>'); }

/** Extract public IPv4s from a string — mirrors server-side logic */
function extractIPsFromText(text) {
  const matches = String(text).match(/\b(\d{1,3}\.){3}\d{1,3}\b/g) || [];
  return [...new Set(matches)].filter(ip => {
    const parts = ip.split('.').map(Number);
    if (parts.some(p => p > 255)) return false;
    const [a, b] = parts;
    if (a===10||a===127||a===0||a>=224) return false;
    if (a===172 && b>=16 && b<=31)      return false;
    if (a===192 && b===168)             return false;
    if (a===169 && b===254)             return false;
    return true;
  });
}

// ══════════════════════════════════════════════════════
// ABUSEIPDB — IP REPUTATION
// ══════════════════════════════════════════════════════

/** Scan all IPs in a section and show results in that section's risk block */
async function scanSectionIPs(key) {
  if (!abuseEnabled) {
    alert('AbuseIPDB not configured.\nAdd ABUSEIPDB_API_KEY=your_key to your .env file.\nGet a free key at https://www.abuseipdb.com/api');
    return;
  }
  if (currentTab !== 'risks') switchSidebarTab('risks');

  const panel = document.getElementById('ip-panel-' + key);
  const body  = document.getElementById('risk-body-' + key);
  if (body?.classList.contains('collapsed')) body.classList.remove('collapsed');

  if (panel) {
    panel.classList.remove('hidden');
    panel.innerHTML = buildIPPanelShell(key, ipLoadingHTML('Scanning section for IPs…'));
  }
  document.getElementById('risk-block-' + key)?.scrollIntoView({ behavior: 'smooth', block: 'start' });

  const tables   = appData?.sections[key] || [];
  const datasets = tables.map(t => ({ rows: t.rows.slice(0, 200) }));

  try {
    const res  = await fetch('/api/abuseipdb/check', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ datasets })
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    if (panel) panel.innerHTML = buildIPPanelShell(key, renderIPResultsHTML(data.results || [], data.message, false));
  } catch (err) {
    if (panel) panel.innerHTML = buildIPPanelShell(key, `<div class="ip-error">⚠ ${esc(err.message)}</div>`);
  }
}

/** Scan a specific list of IPs and render inline inside a risk card's Affected block */
async function scanInlineIPs(ipList, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.classList.remove('hidden');
  container.innerHTML = ipLoadingHTML('Checking IPs…');

  try {
    const res  = await fetch('/api/abuseipdb/check', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ips: ipList })
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    container.innerHTML = renderIPResultsHTML(data.results || [], data.message, true);
  } catch (err) {
    container.innerHTML = `<div class="ip-error">⚠ ${esc(err.message)}</div>`;
  }
}

function buildIPPanelShell(key, content) {
  return `
    <div class="ip-panel-header">
      <span class="ip-panel-title">🌐 IP Reputation</span>
      <span class="ip-panel-sub">AbuseIPDB · last 90 days</span>
      <button class="btn-ghost btn-sm" style="margin-left:auto"
        onclick="document.getElementById('ip-panel-${key}').classList.add('hidden')">✕</button>
    </div>
    ${content}`;
}

function ipLoadingHTML(label) {
  return `<div class="ip-loading"><div class="spinner"></div><span>${esc(label)}</span></div>`;
}

function renderIPResultsHTML(results, message, compact) {
  if (!results || !results.length) {
    return `<div class="ip-empty">${esc(message || 'No public IP addresses found in this data.')}</div>`;
  }

  const sorted    = [...results].sort((a, b) => (b.abuseScore||0) - (a.abuseScore||0));
  const malicious = sorted.filter(r => (r.abuseScore||0) >= 20);
  const clean     = sorted.filter(r => (r.abuseScore||0) <  20 && !r.error);
  const errors    = sorted.filter(r => r.error);

  const critCount = sorted.filter(r => (r.abuseScore||0) >= 80).length;
  const highCount = sorted.filter(r => (r.abuseScore||0) >= 50 && (r.abuseScore||0) < 80).length;
  const medCount  = sorted.filter(r => (r.abuseScore||0) >= 20 && (r.abuseScore||0) < 50).length;

  let html = `<div class="ip-results-wrap">`;
  html += `<div class="ip-summary-bar">
    <span class="ip-stat"><strong>${sorted.length}</strong> IP${sorted.length!==1?'s':''} checked</span>
    ${critCount ? `<span class="ip-stat-pill ip-pill-crit">${critCount} Critical</span>` : ''}
    ${highCount ? `<span class="ip-stat-pill ip-pill-high">${highCount} High</span>`     : ''}
    ${medCount  ? `<span class="ip-stat-pill ip-pill-med">${medCount} Medium</span>`     : ''}
    <span class="ip-stat-pill ip-pill-clean">${clean.length} Clean</span>
  </div>`;

  if (malicious.length) {
    html += `<div class="ip-group-label ip-group-warn">⚠ Flagged IPs (${malicious.length})</div>`;
    malicious.forEach(r => { html += renderIPRow(r, compact); });
  }

  if (clean.length) {
    const cid = 'ipc-' + Math.random().toString(36).slice(2,7);
    html += `
      <div class="ip-group-label" style="cursor:pointer"
           onclick="document.getElementById('${cid}').classList.toggle('hidden')">
        ✓ Clean IPs (${clean.length})
        <span class="ip-toggle-hint">click to ${malicious.length ? 'expand' : 'collapse'}</span>
      </div>
      <div id="${cid}" ${malicious.length ? 'class="hidden"' : ''}>
        ${clean.map(r => renderIPRow(r, compact)).join('')}
      </div>`;
  }

  if (errors.length) {
    html += `<div class="ip-group-label">⚠ Lookup Errors</div>`;
    errors.forEach(r => {
      html += `<div class="ip-row"><code class="ip-addr">${esc(r.ip)}</code><span class="ip-err-msg">${esc(r.error)}</span></div>`;
    });
  }

  return html + `</div>`;
}

function renderIPRow(r, compact) {
  const score = r.abuseScore ?? 0;
  const sev   = r.severity   || 'CLEAN';
  const cls   = { CRITICAL:'ip-score-crit', HIGH:'ip-score-high', MEDIUM:'ip-score-med', LOW:'ip-score-low', CLEAN:'ip-score-clean' }[sev] || 'ip-score-clean';
  const flag  = r.countryCode ? getFlagEmoji(r.countryCode) : '';
  const lastSeen = r.lastReportedAt ? new Date(r.lastReportedAt).toLocaleDateString() : null;

  return `
    <div class="ip-row ${score >= 20 ? 'ip-row-flagged' : ''}">
      <div class="ip-row-main">
        <code class="ip-addr">${esc(r.ip)}</code>
        <span class="ip-score-badge ${cls}">${score}%</span>
        ${flag ? `<span class="ip-flag" title="${esc(r.countryCode)}">${flag}</span>` : ''}
        <span class="ip-meta">${esc(r.isp || '—')}</span>
        ${r.totalReports ? `<span class="ip-reports">${r.totalReports.toLocaleString()} report${r.totalReports!==1?'s':''}</span>` : ''}
        ${r.isWhitelisted ? `<span class="ip-whitelist-badge">whitelisted</span>` : ''}
      </div>
      ${!compact && (r.usageType || lastSeen || r.domain) ? `
        <div class="ip-row-sub">
          ${r.usageType ? `<span class="ip-usage">${esc(r.usageType)}</span>`           : ''}
          ${r.domain    ? `<span class="ip-domain">${esc(r.domain)}</span>`             : ''}
          ${lastSeen    ? `<span class="ip-last-seen">last report ${lastSeen}</span>`   : ''}
        </div>` : ''}
    </div>`;
}

function getFlagEmoji(cc) {
  if (!cc || cc.length !== 2) return '';
  return cc.toUpperCase().split('').map(c => String.fromCodePoint(c.charCodeAt(0) + 127397)).join('');
}

// ══════════════════════════════════════════════════════
// ENGINE BADGE — shows active AI engine in topbar + upload screen
// ══════════════════════════════════════════════════════

const ENGINE_META = {
  lmstudio:  { icon: '🖥',  color: 'var(--green)',  label: 'LM Studio' },
  openai:    { icon: '⬡',   color: 'var(--accent)', label: 'OpenAI'    },
  anthropic: { icon: '☁',   color: 'var(--accent)', label: 'Anthropic' },
};

function renderEngineBadge(health) {
  // ── Topbar badge ──────────────────────────────────────────────────────────
  const badge   = document.getElementById('engineBadge');
  const iconEl  = document.getElementById('engineIcon');
  const labelEl = document.getElementById('engineLabel');
  const modelEl = document.getElementById('engineModel');

  // ── Upload screen status ──────────────────────────────────────────────────
  const uploadStatus = document.getElementById('uploadEngineStatus');

  const meta       = health.ai && health.aiEngine
    ? ENGINE_META[health.aiEngine] || { icon: '⬡', color: 'var(--accent)', label: health.aiLabel || health.aiEngine }
    : null;
  const modelStr     = health.aiModel || '';
  const modelDisplay = modelStr.length > 40 ? modelStr.slice(0, 38) + '…' : modelStr;

  // ── Topbar badge (only when AI is active) ─────────────────────────────────
  if (badge) {
    if (meta) {
      badge.classList.remove('hidden');
      badge.setAttribute('data-engine', health.aiEngine);
      iconEl.textContent  = meta.icon;
      labelEl.textContent = meta.label;
      modelEl.textContent = modelDisplay ? `· ${modelDisplay}` : '';
      badge.title = health.aiEngine === 'lmstudio'
        ? `LM Studio — ${health.aiBase || 'localhost:1234'} — ${modelStr}`
        : `${meta.label} — ${modelStr}`;
    } else {
      badge.classList.add('hidden');
    }
  }

  // ── Upload screen — AI engine row + AbuseIPDB row ─────────────────────────
  if (!uploadStatus) return;

  let html = '';

  // AI engine row
  if (meta) {
    const sub = health.aiEngine === 'lmstudio'
      ? `Local · ${health.aiBase || 'localhost:1234'} · ${modelDisplay}`
      : `Cloud · ${modelDisplay}`;
    html += `
      <div class="engine-status-strip engine-status-${health.aiEngine}">
        <span class="ess-icon">${meta.icon}</span>
        <div class="ess-text">
          <span class="ess-label">${meta.label} active</span>
          <span class="ess-sub">${sub}</span>
        </div>
        <span class="ess-dot"></span>
      </div>`;
  } else {
    html += `
      <div class="engine-status-strip engine-status-none">
        <span class="ess-icon">⚠</span>
        <div class="ess-text">
          <span class="ess-label">No AI engine configured</span>
          <span class="ess-sub">Set LM_STUDIO_BASE_URL, OPENAI_API_KEY, or ANTHROPIC_API_KEY in .env</span>
        </div>
      </div>`;
  }

  // AbuseIPDB row
  if (health.abuseipdb) {
    html += `
      <div class="engine-status-strip engine-status-abuse">
        <span class="ess-icon">🌐</span>
        <div class="ess-text">
          <span class="ess-label">AbuseIPDB active</span>
          <span class="ess-sub">IP reputation checks enabled · 1,000 lookups/day free tier</span>
        </div>
        <span class="ess-dot ess-dot-abuse"></span>
      </div>`;
  } else {
    html += `
      <div class="engine-status-strip engine-status-abuse-off">
        <span class="ess-icon">🌐</span>
        <div class="ess-text">
          <span class="ess-label">AbuseIPDB not configured</span>
          <span class="ess-sub">Set ABUSEIPDB_API_KEY in .env — free at abuseipdb.com/api</span>
        </div>
      </div>`;
  }

  uploadStatus.innerHTML = html;
}

// ── SIDEBAR MOBILE HELPERS ────────────────────────────────
function toggleSidebar() {
  const sidebar  = document.getElementById('sidebar');
  const backdrop = document.getElementById('sidebarBackdrop');
  const isOpen   = sidebar.classList.contains('mobile-open');
  if (isOpen) {
    closeSidebar();
  } else {
    sidebar.classList.add('mobile-open');
    if (backdrop) backdrop.classList.add('active');
  }
}
function closeSidebar() {
  const sidebar  = document.getElementById('sidebar');
  const backdrop = document.getElementById('sidebarBackdrop');
  sidebar.classList.remove('mobile-open');
  if (backdrop) backdrop.classList.remove('active');
}