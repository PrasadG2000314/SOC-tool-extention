/**
 * Content Script for SOC Console Enhancement
 * Adds quick-triage floating action chip when highlighting telemetry in web SIEMs.
 */

let chip = null;

document.addEventListener('mouseup', (e) => {
  const selection = window.getSelection().toString().trim();
  
  // Clean up existing chip
  if (chip) {
    chip.remove();
    chip = null;
  }

  // Only show for substantial telemetry snippets (> 25 chars)
  if (selection.length > 25 && !e.target.closest('#soc-t3-chip')) {
    createQuickChip(e.pageX, e.pageY, selection);
  }
});

document.addEventListener('mousedown', (e) => {
  if (chip && !chip.contains(e.target)) {
    chip.remove();
    chip = null;
  }
});

function createQuickChip(x, y, text) {
  chip = document.createElement('div');
  chip.id = 'soc-t3-chip';
  chip.style.cssText = `
    position: absolute;
    left: ${x + 10}px;
    top: ${y - 35}px;
    z-index: 999999;
    background: #0d1322;
    color: #00f0ff;
    border: 1px solid rgba(0, 240, 255, 0.4);
    box-shadow: 0 4px 16px rgba(0,0,0,0.6), 0 0 10px rgba(0, 240, 255, 0.2);
    border-radius: 6px;
    padding: 5px 10px;
    font-size: 11px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-weight: 600;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 6px;
    user-select: none;
    transition: transform 0.1s ease, background 0.15s ease;
  `;
  chip.innerHTML = `
    <span style="font-size:12px;">⚡</span>
    <span>SOC T3 Hunt</span>
  `;

  chip.addEventListener('mouseenter', () => {
    chip.style.background = '#162238';
    chip.style.transform = 'translateY(-2px)';
  });
  chip.addEventListener('mouseleave', () => {
    chip.style.background = '#0d1322';
    chip.style.transform = 'translateY(0)';
  });

  chip.addEventListener('click', () => {
    chrome.runtime.sendMessage({
      action: 'triage_selection',
      text: text
    });
    chip.remove();
    chip = null;
  });

  document.body.appendChild(chip);
}
