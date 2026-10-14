import { TELEMETRY_PRESETS } from './engine/presets.js';
import { parseTelemetry } from './engine/analyzer.js';

const popupPreset = document.getElementById('popup-preset');
const popupInput = document.getElementById('popup-input');
const btnAnalyze = document.getElementById('btn-popup-analyze');
const btnExpand = document.getElementById('btn-popup-expand');
const btnWorkbench = document.getElementById('btn-popup-workbench');
const btnDeep = document.getElementById('btn-popup-deep');
const resultsBox = document.getElementById('popup-results');

document.addEventListener('DOMContentLoaded', () => {
  TELEMETRY_PRESETS.forEach(p => {
    const opt = document.createElement('option');
    opt.value = p.id;
    opt.textContent = p.name;
    popupPreset.appendChild(opt);
  });

  popupPreset.addEventListener('change', (e) => {
    const p = TELEMETRY_PRESETS.find(item => item.id === e.target.value);
    if (p) {
      popupInput.value = p.telemetry;
      runQuickTriage();
    }
  });

  btnAnalyze.addEventListener('click', runQuickTriage);

  btnExpand.addEventListener('click', async () => {
    if (typeof chrome !== 'undefined' && chrome.sidePanel && chrome.sidePanel.open) {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.id) {
        await chrome.sidePanel.open({ tabId: tab.id });
        window.close();
        return;
      }
    }
    openWorkbench();
  });

  btnWorkbench.addEventListener('click', openWorkbench);
  btnDeep.addEventListener('click', openWorkbench);
});

function openWorkbench() {
  const currentText = popupInput.value.trim();
  const url = 'workbench.html' + (currentText ? '?telemetry=' + encodeURIComponent(currentText) : '');
  if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) {
    chrome.tabs.create({ url: chrome.runtime.getURL(url) });
  } else {
    window.open(url, '_blank');
  }
}

function runQuickTriage() {
  const text = popupInput.value.trim();
  if (!text) return;

  const analysis = parseTelemetry(text);
  resultsBox.style.display = 'flex';

  const badge = document.getElementById('popup-badge');
  badge.className = 'badge ' + (
    analysis.verdict.status === 'True Positive' ? 'badge-tp' :
    analysis.verdict.status === 'False Positive' ? 'badge-fp' : 'badge-btp'
  );
  badge.textContent = analysis.verdict.status;
  document.getElementById('popup-threat').textContent = analysis.attribution.type;

  const primaryIp = analysis.iocs.ips[0]?.defanged || 'None';
  const mitreStr = analysis.mitreTechniques.slice(0, 3).join(', ') || 'None';
  document.getElementById('popup-summary').innerHTML = `
    <strong>IPs:</strong> ${primaryIp}<br>
    <strong>MITRE:</strong> ${mitreStr}<br>
    <strong>Entropy:</strong> ${analysis.entropy.overall.toFixed(2)}<br>
    <strong>Level:</strong> ${analysis.rootCause.privilegeLevel}
  `;
}
