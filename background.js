/**
 * Background Service Worker (Manifest V3)
 * Handles context menus, side panel routing, and telemetry dispatch.
 */

chrome.runtime.onInstalled.addListener(() => {
  // Create Context Menu for Highlighted Text
  chrome.contextMenus.create({
    id: 'soc_t3_hunt',
    title: '⚡ Hunt & Triage with SOC T3 ("%s")',
    contexts: ['selection']
  });

  // Enable Side Panel on all supported sites
  if (chrome.sidePanel && chrome.sidePanel.setPanelBehavior) {
    chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true })
      .catch((error) => console.error(error));
  }
});

// Handle Context Menu Click
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'soc_t3_hunt' && info.selectionText) {
    const selectedText = info.selectionText.trim();
    
    // Save to local storage for automatic pickup by sidepanel or popup
    await chrome.storage.local.set({ lastSelectedTelemetry: selectedText });

    // Try opening side panel first
    if (chrome.sidePanel && tab?.id) {
      try {
        await chrome.sidePanel.open({ tabId: tab.id });
        // Send message to active sidepanel
        setTimeout(() => {
          chrome.runtime.sendMessage({
            action: 'triage_selection',
            text: selectedText
          }).catch(() => {});
        }, 500);
        return;
      } catch (err) {
        console.warn('Could not open sidepanel, falling back to workbench tab:', err);
      }
    }

    // Fallback: Open workbench in new tab
    const url = chrome.runtime.getURL('workbench.html') + '?telemetry=' + encodeURIComponent(selectedText);
    chrome.tabs.create({ url });
  }
});

// Handle Shortcut Commands
chrome.commands.onCommand.addListener(async (command) => {
  if (command === 'open_workbench') {
    chrome.tabs.create({ url: chrome.runtime.getURL('workbench.html') });
  }
});
