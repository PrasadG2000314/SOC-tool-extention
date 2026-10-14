/**
 * Sidepanel & Analyst Console Controller
 * Coordinates the 5-step triage framework, UI interactions, and state.
 */

import { TELEMETRY_PRESETS } from './engine/presets.js';
import { executeTriage } from './engine/ai-client.js';
import { MITRE_TECHNIQUES } from './engine/mitre-db.js';

// Application State
let currentAnalysis = null;
let currentActiveQuery = 'splunk';
let currentDetectionView = 'sigma';
let appConfig = {
  provider: 'offline',
  apiKey: '',
  model: 'gemini-1.5-flash',
  endpoint: '',
  defangByDefault: true
};

// DOM Elements
const telemetryInput = document.getElementById('telemetry-input');
const telemetryMeta = document.getElementById('telemetry-meta');
const presetSelector = document.getElementById('preset-selector');
const btnClear = document.getElementById('btn-clear-telemetry');
const btnAnalyze = document.getElementById('btn-analyze');
const resultsArea = document.getElementById('results-area');
const btnOpenWorkbench = document.getElementById('btn-open-workbench');
const btnSettings = document.getElementById('btn-settings');
const settingsModal = document.getElementById('settings-modal');
const btnCloseSettings = document.getElementById('btn-close-settings');
const btnSaveSettings = document.getElementById('btn-save-settings');

// Settings Elements
const settingProvider = document.getElementById('setting-provider');
const apiKeyGroup = document.getElementById('api-key-group');
const settingApiKey = document.getElementById('setting-api-key');
const modelGroup = document.getElementById('model-group');
const settingModel = document.getElementById('setting-model');
const endpointGroup = document.getElementById('endpoint-group');
const settingEndpoint = document.getElementById('setting-endpoint');
const toggleDefang = document.getElementById('toggle-defang');

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  await loadSettings();
  populatePresets();
  setupEventListeners();
  checkUrlParamsOrClipboard();
});

// Load Settings from chrome.storage or localStorage
async function loadSettings() {
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    const saved = await chrome.storage.local.get(['socConfig']);
    if (saved.socConfig) {
      appConfig = { ...appConfig, ...saved.socConfig };
    }
  } else {
    const saved = localStorage.getItem('socConfig');
    if (saved) {
      try {
        appConfig = { ...appConfig, ...JSON.parse(saved) };
      } catch (e) {
        console.error(e);
      }
    }
  }
  updateSettingsUI();
}

async function saveSettings() {
  appConfig.provider = settingProvider.value;
  appConfig.apiKey = settingApiKey.value.trim();
  appConfig.model = settingModel.value.trim() || 'gemini-1.5-flash';
  appConfig.endpoint = settingEndpoint.value.trim();

  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    await chrome.storage.local.set({ socConfig: appConfig });
  } else {
    localStorage.setItem('socConfig', JSON.stringify(appConfig));
  }
  settingsModal.classList.remove('active');
  showToast('Settings saved successfully');
}

function updateSettingsUI() {
  settingProvider.value = appConfig.provider;
  settingApiKey.value = appConfig.apiKey || '';
  settingModel.value = appConfig.model || 'gemini-1.5-flash';
  settingEndpoint.value = appConfig.endpoint || '';

  const isGemini = appConfig.provider === 'gemini';
  const isOpenAI = appConfig.provider === 'openai';
  apiKeyGroup.style.display = (isGemini || isOpenAI) ? 'block' : 'none';
  modelGroup.style.display = (isGemini || isOpenAI) ? 'block' : 'none';
  endpointGroup.style.display = isOpenAI ? 'block' : 'none';
}

function populatePresets() {
  TELEMETRY_PRESETS.forEach(p => {
    const opt = document.createElement('option');
    opt.value = p.id;
    opt.textContent = `[${p.category}] ${p.name}`;
    presetSelector.appendChild(opt);
  });
}

function setupEventListeners() {
  // Preset Selection
  presetSelector.addEventListener('change', (e) => {
    const selected = TELEMETRY_PRESETS.find(p => p.id === e.target.value);
    if (selected) {
      telemetryInput.value = selected.telemetry;
      updateInputMeta();
      runAnalysis();
    }
  });

  // Clear button
  btnClear.addEventListener('click', () => {
    telemetryInput.value = '';
    presetSelector.value = '';
    updateInputMeta();
    resultsArea.style.display = 'none';
  });

  // Textarea input count
  telemetryInput.addEventListener('input', updateInputMeta);

  // Analyze button
  btnAnalyze.addEventListener('click', () => runAnalysis());

  // Expand / Workbench launcher
  if (btnOpenWorkbench) {
    btnOpenWorkbench.addEventListener('click', () => {
      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) {
        chrome.tabs.create({ url: chrome.runtime.getURL('workbench.html') });
      } else {
        window.open('workbench.html', '_blank');
      }
    });
  }

  // Settings Modal controls
  btnSettings.addEventListener('click', () => {
    updateSettingsUI();
    settingsModal.classList.add('active');
  });
  btnCloseSettings.addEventListener('click', () => settingsModal.classList.remove('active'));
  btnSaveSettings.addEventListener('click', saveSettings);
  settingProvider.addEventListener('change', () => {
    const val = settingProvider.value;
    apiKeyGroup.style.display = (val === 'gemini' || val === 'openai') ? 'block' : 'none';
    modelGroup.style.display = (val === 'gemini' || val === 'openai') ? 'block' : 'none';
    endpointGroup.style.display = val === 'openai' ? 'block' : 'none';
  });

  // Tab switching
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      document.getElementById(targetId)?.classList.add('active');
    });
  });

  // Query Subtabs (Splunk, KQL, Elastic)
  document.querySelectorAll('.subtab-btn[data-query]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.subtab-btn[data-query]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentActiveQuery = btn.getAttribute('data-query');
      renderQueryContent();
    });
  });

  // Copy Query button
  document.getElementById('btn-copy-query').addEventListener('click', () => {
    const text = document.getElementById('query-content').textContent;
    copyToClipboard(text, 'Threat hunting query copied!');
  });

  // Copy Wireshark filter
  document.getElementById('btn-copy-wireshark').addEventListener('click', () => {
    const text = document.getElementById('wireshark-filter').textContent;
    copyToClipboard(text, 'Wireshark filter copied!');
  });

  // Copy Containment Snippets
  document.querySelectorAll('.btn-copy-snippet').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');
      const text = document.getElementById(targetId).textContent;
      copyToClipboard(text, 'Containment CLI command copied!');
    });
  });

  // Toggle Sigma / YARA
  document.getElementById('btn-toggle-sigma').addEventListener('click', () => {
    document.getElementById('btn-toggle-sigma').classList.add('active');
    document.getElementById('btn-toggle-yara').classList.remove('active');
    currentDetectionView = 'sigma';
    renderDetectionContent();
  });
  document.getElementById('btn-toggle-yara').addEventListener('click', () => {
    document.getElementById('btn-toggle-yara').classList.add('active');
    document.getElementById('btn-toggle-sigma').classList.remove('active');
    currentDetectionView = 'yara';
    renderDetectionContent();
  });

  // Copy Rule
  document.getElementById('btn-copy-rule').addEventListener('click', () => {
    const text = document.getElementById('detection-rule-content').textContent;
    copyToClipboard(text, `${currentDetectionView.toUpperCase()} rule copied!`);
  });

  // Copy Final Ticket
  document.getElementById('btn-copy-ticket').addEventListener('click', () => {
    if (!currentAnalysis) return;
    copyToClipboard(currentAnalysis.report.markdown, 'Export-ready ticket copied to clipboard!');
  });

  // Download Markdown Report
  document.getElementById('btn-download-md').addEventListener('click', () => {
    if (!currentAnalysis) return;
    const blob = new Blob([currentAnalysis.report.markdown], { type: 'text/markdown' });
    downloadBlob(blob, `INCIDENT_REPORT_${Date.now()}.md`);
  });

  // Download SOAR JSON
  document.getElementById('btn-download-json').addEventListener('click', () => {
    if (!currentAnalysis) return;
    const blob = new Blob([currentAnalysis.report.theHiveJson], { type: 'application/json' });
    downloadBlob(blob, `SOAR_TICKET_${Date.now()}.json`);
  });

  // Defang Toggle Checkbox
  toggleDefang.addEventListener('change', () => {
    if (currentAnalysis) renderIoCGrid();
  });

  // Listen for messages from background script (Context Menu)
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((request) => {
      if (request.action === 'triage_selection' && request.text) {
        telemetryInput.value = request.text;
        updateInputMeta();
        runAnalysis();
      }
    });
  }
}

function updateInputMeta() {
  const chars = telemetryInput.value.length;
  const lines = telemetryInput.value.split('\n').filter(Boolean).length;
  telemetryMeta.textContent = `${chars.toLocaleString()} chars | ${lines} lines`;
}

async function checkUrlParamsOrClipboard() {
  const params = new URLSearchParams(window.location.search);
  const telemetryParam = params.get('telemetry');
  const presetParam = params.get('preset');

  if (telemetryParam) {
    telemetryInput.value = decodeURIComponent(telemetryParam);
    updateInputMeta();
    runAnalysis();
    return;
  }

  // Check if context menu saved telemetry
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    const saved = await chrome.storage.local.get(['lastSelectedTelemetry']);
    if (saved.lastSelectedTelemetry) {
      telemetryInput.value = saved.lastSelectedTelemetry;
      await chrome.storage.local.remove(['lastSelectedTelemetry']);
      updateInputMeta();
      runAnalysis();
      return;
    }
  }

  if (presetParam) {
    presetSelector.value = presetParam;
    const selected = TELEMETRY_PRESETS.find(p => p.id === presetParam);
    if (selected) {
      telemetryInput.value = selected.telemetry;
      updateInputMeta();
      runAnalysis();
      return;
    }
  }

  if (!telemetryInput.value) {
    // Load first preset by default as initial demonstration
    presetSelector.value = 'sysmon_cobalt_strike';
    telemetryInput.value = TELEMETRY_PRESETS[0].telemetry;
    updateInputMeta();
    runAnalysis();
  }
}

// Execute Analysis
async function runAnalysis() {
  const raw = telemetryInput.value.trim();
  if (!raw) {
    showToast('Please paste raw security telemetry first.', 'error');
    return;
  }

  btnAnalyze.disabled = true;
  btnAnalyze.innerHTML = `
    <svg class="spin" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
    </svg>
    <span>Hunting & Correlating...</span>
  `;

  try {
    currentAnalysis = await executeTriage(raw, {
      provider: appConfig.provider,
      apiKey: appConfig.apiKey,
      model: appConfig.model,
      endpoint: appConfig.endpoint
    });

    renderAllResults(currentAnalysis);
    resultsArea.style.display = 'flex';
    showToast(`Triage Complete: ${currentAnalysis.parsed.verdict.status}`);
  } catch (err) {
    console.error('Analysis error:', err);
    showToast(`Analysis Failed: ${err.message}`, 'error');
  } finally {
    btnAnalyze.disabled = false;
    btnAnalyze.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10"/>
        <path d="M12 6v6l4 2"/>
      </svg>
      <span>Initiate Tier 3 Hunt & Triage</span>
    `;
  }
}

// Render Results
function renderAllResults(data) {
  const { parsed, queries, sigmaRule, yaraRule, containment, report } = data;

  // 1. Verdict Banner
  const verdictBanner = document.getElementById('verdict-banner');
  const verdictBadge = document.getElementById('verdict-badge');
  const threatName = document.getElementById('threat-name');
  const verdictJustification = document.getElementById('verdict-justification');

  verdictBanner.className = 'verdict-banner ' + (
    parsed.verdict.status === 'True Positive' ? 'status-tp' :
    parsed.verdict.status === 'False Positive' ? 'status-fp' : 'status-btp'
  );

  verdictBadge.className = 'badge ' + (
    parsed.verdict.status === 'True Positive' ? 'badge-tp' :
    parsed.verdict.status === 'False Positive' ? 'badge-fp' : 'badge-btp'
  );
  verdictBadge.textContent = parsed.verdict.status.toUpperCase();
  threatName.textContent = parsed.attribution.type;
  verdictJustification.textContent = parsed.verdict.justification;

  // Stats
  const totalIoCs = parsed.iocs.ips.length + parsed.iocs.domains.length +
    parsed.iocs.hashes.sha256.length + parsed.iocs.hashes.md5.length;
  document.getElementById('stat-iocs').textContent = totalIoCs;
  document.getElementById('stat-mitre').textContent = parsed.mitreTechniques.length;
  document.getElementById('stat-entropy').textContent = parsed.entropy.overall.toFixed(2);

  // 2. Tab 1: Alert Decomposition
  const primaryBin = parsed.lolbinsDetected[0]?.name || 'process';
  document.getElementById('summary-text').textContent =
    `Anomalous invocation of ${primaryBin} identified with suspicious parameters, indicating potential unauthorized payload delivery, defense evasion, and stage-2 command-and-control establishment.`;

  renderIoCGrid();

  // Entropy meter
  const entropyPct = Math.min(100, (parsed.entropy.overall / 8.0) * 100);
  document.getElementById('entropy-fill').style.width = `${entropyPct}%`;
  document.getElementById('entropy-value-display').textContent = `${parsed.entropy.overall.toFixed(2)} / 8.0`;

  // Decoded Base64
  const decodedArea = document.getElementById('decoded-base64-area');
  if (parsed.decodedBase64.length > 0) {
    decodedArea.style.display = 'block';
    document.getElementById('decoded-base64-content').textContent = parsed.decodedBase64[0].decodedContent;
  } else {
    decodedArea.style.display = 'none';
  }

  // MITRE Tags
  const mitreContainer = document.getElementById('mitre-tags-container');
  mitreContainer.innerHTML = '';
  parsed.mitreTechniques.forEach(techId => {
    const tech = MITRE_TECHNIQUES[techId];
    const a = document.createElement('a');
    a.className = 'mitre-tag';
    a.href = tech?.url || `https://attack.mitre.org/techniques/${techId.replace('.', '/')}/`;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.innerHTML = `
      <span style="font-weight:700;">${techId}</span>
      <span>${tech?.name || 'ATT&CK Technique'}</span>
    `;
    mitreContainer.appendChild(a);
  });

  // Attribution
  document.getElementById('attribution-title').textContent = parsed.attribution.type;
  const attrList = document.getElementById('attribution-indicators');
  attrList.innerHTML = '';
  parsed.attribution.indicators.forEach(ind => {
    const li = document.createElement('li');
    li.textContent = ind;
    attrList.appendChild(li);
  });

  // 3. Tab 2: Advanced Detection & Triage
  const firedEvents = parsed.eventIds.length > 0 ? parsed.eventIds.join(', ') : 'Sysmon Event ID 1 (Process Creation)';
  document.getElementById('telemetry-mechanism').innerHTML = `
    <strong>Trigger Mechanism:</strong> Event log decoders identified activity via <code>${firedEvents}</code>. 
    ${parsed.ruleDescription ? `<br><strong>Wazuh Rule Match:</strong> <code>[${parsed.ruleId}] ${parsed.ruleDescription}</code>` : ''}
    <br>Parent-child process tree anomaly: Executed with elevated privileges and suspicious execution arguments.
  `;

  renderQueryContent();

  // PCAP Correlation
  document.getElementById('wireshark-filter').textContent = queries.pcap.wiresharkFilter;
  document.getElementById('pcap-guidance-text').innerHTML = `
    <p style="margin-bottom:6px;"><strong>HTTP/TLS Inspection:</strong> ${queries.pcap.httpInspection} ${queries.pcap.tlsInspection}</p>
    <p><strong>C2 Jitter & Beaconing:</strong> ${queries.pcap.beaconingAnalysis}</p>
  `;

  // 4. Tab 3: Root Cause & Exploit Chain
  document.getElementById('attack-vector-text').textContent =
    `Adversary utilized living-off-the-land techniques to stage payload in-memory, attempting to evade static detection signatures and bypass host execution restrictions.`;

  const timelineSteps = document.getElementById('timeline-steps');
  timelineSteps.innerHTML = '';
  const stages = [
    { title: 'Initial Access / Ingress Transfer', desc: 'Payload dropped to temp path or fetched directly in memory via remote web client.' },
    { title: 'Execution & Defense Evasion', desc: `Invoked ${primaryBin} with -enc / hidden flags to evade script block monitoring.` },
    { title: 'Privilege Escalation / Token Impersonation', desc: `Executed under ${parsed.rootCause.privilegeLevel} security context.` },
    { title: 'C2 Callback & Beaconing', desc: `Attempted outbound connection to external node for stage-2 tasking.` }
  ];
  stages.forEach(s => {
    const div = document.createElement('div');
    div.className = 'timeline-step';
    div.innerHTML = `
      <div style="font-weight:700; font-size:12px; color:var(--cyber-cyan);">${s.title}</div>
      <div style="font-size:11px; color:var(--text-secondary); margin-top:2px;">${s.desc}</div>
    `;
    timelineSteps.appendChild(div);
  });

  // LOLBins
  const lolbinsContainer = document.getElementById('lolbins-container');
  if (parsed.lolbinsDetected.length > 0) {
    lolbinsContainer.innerHTML = parsed.lolbinsDetected.map(l => `
      <div style="background:var(--bg-inset); padding:10px 12px; border-radius:var(--radius-sm); border:1px solid var(--border-subtle); margin-bottom:8px;">
        <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:4px;">
          <span style="font-family:var(--font-mono); font-weight:700; color:#fff;">${l.name}</span>
          <span class="badge ${l.risk === 'Critical' ? 'badge-tp' : 'badge-btp'}">${l.risk} Risk</span>
        </div>
        <div style="font-size:11px; color:var(--text-secondary);">${l.desc}</div>
      </div>
    `).join('');
  } else {
    lolbinsContainer.innerHTML = '<div style="color:var(--text-dimmed); font-size:12px;">No known LOLBins detected in telemetry snippet.</div>';
  }

  // Blast Radius
  document.getElementById('privilege-level-val').textContent = parsed.rootCause.privilegeLevel;
  document.getElementById('blast-radius-val').textContent = parsed.rootCause.blastRadius;

  // 5. Tab 4: Verdict & Containment
  document.getElementById('verdict-detailed-box').innerHTML = `
    <p style="margin-bottom:8px;"><strong>Status:</strong> <span class="badge ${parsed.verdict.status === 'True Positive' ? 'badge-tp' : 'badge-btp'}">${parsed.verdict.status}</span></p>
    <p><strong>Technical Justification:</strong> ${parsed.verdict.justification}</p>
  `;

  document.getElementById('contain-edr').textContent = containment.edrIsolation.cli;
  document.getElementById('contain-ad').textContent = containment.adAccountRevocation.cli;
  document.getElementById('contain-nullroute').textContent = containment.perimeterNullRoute.cli;

  renderDetectionContent();

  // 6. Tab 5: Final Incident Report
  document.getElementById('ticket-display').textContent = report.markdown;
}

function renderIoCGrid() {
  if (!currentAnalysis) return;
  const isDefang = toggleDefang.checked;
  const { iocs } = currentAnalysis.parsed;

  // IPs
  const listIps = document.getElementById('list-ips');
  document.getElementById('count-ips').textContent = iocs.ips.length;
  listIps.innerHTML = iocs.ips.length > 0 ? iocs.ips.map(item => `
    <div class="ioc-pill ${item.isSuspicious ? 'suspicious' : ''}">
      <span>${isDefang ? item.defanged : item.ip}</span>
      <span class="badge ${item.isSuspicious ? 'badge-tp' : 'badge-cyan'}" style="font-size:9px;">${item.type.split('/')[0].trim()}</span>
    </div>
  `).join('') : '<div style="color:var(--text-dimmed); font-size:11px;">None extracted</div>';

  // Domains
  const listDomains = document.getElementById('list-domains');
  document.getElementById('count-domains').textContent = iocs.domains.length;
  listDomains.innerHTML = iocs.domains.length > 0 ? iocs.domains.map(item => `
    <div class="ioc-pill suspicious">
      <span>${isDefang ? item.defanged : item.value}</span>
      <span class="badge badge-tp" style="font-size:9px;">${item.type}</span>
    </div>
  `).join('') : '<div style="color:var(--text-dimmed); font-size:11px;">None extracted</div>';

  // Hashes
  const listHashes = document.getElementById('list-hashes');
  const allHashes = [
    ...iocs.hashes.sha256.map(h => ({ val: h, type: 'SHA256' })),
    ...iocs.hashes.sha1.map(h => ({ val: h, type: 'SHA1' })),
    ...iocs.hashes.md5.map(h => ({ val: h, type: 'MD5' }))
  ];
  document.getElementById('count-hashes').textContent = allHashes.length;
  listHashes.innerHTML = allHashes.length > 0 ? allHashes.map(item => `
    <div class="ioc-pill">
      <span style="font-size:10px;">${item.val.substring(0, 20)}...</span>
      <span class="badge badge-cyan" style="font-size:9px;">${item.type}</span>
    </div>
  `).join('') : '<div style="color:var(--text-dimmed); font-size:11px;">None extracted</div>';
}

function renderQueryContent() {
  if (!currentAnalysis) return;
  const content = document.getElementById('query-content');
  content.textContent = currentAnalysis.queries[currentActiveQuery] || '';
}

function renderDetectionContent() {
  if (!currentAnalysis) return;
  const content = document.getElementById('detection-rule-content');
  content.textContent = currentDetectionView === 'sigma' ? currentAnalysis.sigmaRule : currentAnalysis.yaraRule;
}

// Utility Helpers
function copyToClipboard(text, message = 'Copied to clipboard!') {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => showToast(message));
  } else {
    const el = document.createElement('textarea');
    el.value = text;
    document.body.appendChild(el);
    el.select();
    document.execCommand('copy');
    document.body.removeChild(el);
    showToast(message);
  }
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast(`Downloaded ${filename}`);
}

function showToast(message, type = 'info') {
  const existing = document.getElementById('soc-toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.id = 'soc-toast';
  toast.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    padding: 10px 16px;
    background: ${type === 'error' ? 'var(--cyber-crimson)' : 'rgba(11, 16, 29, 0.95)'};
    color: #fff;
    border: 1px solid ${type === 'error' ? 'var(--cyber-crimson)' : 'var(--cyber-cyan)'};
    border-radius: var(--radius-sm);
    box-shadow: 0 4px 20px rgba(0,0,0,0.6);
    font-size: 12px;
    font-family: var(--font-sans);
    z-index: 10000;
    backdrop-filter: blur(8px);
    display: flex;
    align-items: center;
    gap: 8px;
    animation: fadeIn 0.2s ease;
  `;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}
