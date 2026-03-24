// ============================================================
// background.js — PhishGuard Service Worker (MV3)
// Tracks phishing status per tab so the popup can display
// the correct status without re-querying the API.
// ============================================================

// In-memory store: { tabId: { url, status, timestamp } }
const tabStatus = {};

// ── Listen for messages from content scripts ────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "PHISHING_DETECTED") {
    const tabId = sender.tab?.id;
    if (tabId) {
      tabStatus[tabId] = {
        url: message.url,
        status: "phishing",
        timestamp: Date.now(),
      };

      // Change the extension icon to red alert state
      chrome.action.setIcon({
        tabId: tabId,
        path: {
          16: "icons/icon_alert16.png",
          48: "icons/icon_alert48.png",
        },
      });

      // Show a badge on the extension icon
      chrome.action.setBadgeText({ tabId: tabId, text: "!" });
      chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: "#FF3B3B" });
    }
  }

  // Popup asks for the status of its tab
  if (message.type === "GET_TAB_STATUS") {
    const tabId = sender.tab?.id ?? message.tabId;
    sendResponse(tabStatus[tabId] ?? { status: "unknown" });
  }

  return true; // Keep message channel open for async sendResponse
});

// ── Clean up status when tab is closed or navigates away ────
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabStatus[tabId];
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    // Reset status on navigation — content.js will re-check
    delete tabStatus[tabId];
    chrome.action.setBadgeText({ tabId: tabId, text: "" });
    chrome.action.setIcon({
      tabId: tabId,
      path: {
        16: "icons/icon16.png",
        48: "icons/icon48.png",
      },
    });
  }
});
