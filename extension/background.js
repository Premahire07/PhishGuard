// ============================================================
// background.js — PhishGuard Service Worker (MV3)
//
// KEY ROLE: Acts as a proxy between content.js and the Flask API.
// Content scripts on HTTPS pages CANNOT call HTTP (localhost) APIs
// due to mixed-content restrictions. Service workers CAN.
// ============================================================

"use strict";

const API_URL = "http://127.0.0.1:5000/predict";

// Cache: { tabId: { url, prediction } }
const tabResults = {};

// ── Main message handler ──────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab?.id;

  // ── CHECK_URL: content.js asks us to call the Flask API ──
  // This is the core fix: background workers bypass mixed-content policy
  if (message.type === "CHECK_URL") {
    fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: message.url }),
    })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then((data) => {
        sendResponse({ prediction: data.prediction || "safe" });
      })
      .catch((err) => {
        console.warn("[PhishGuard BG] API fetch failed:", err.message);
        sendResponse({ prediction: "error" });
      });

    return true; // Keep message channel open for async response
  }

  // ── PHISHING_DETECTED: update badge to red ────────────────
  if (message.type === "PHISHING_DETECTED" && tabId) {
    tabResults[tabId] = { url: message.url, prediction: "phishing" };
    chrome.action.setBadgeText({ text: "⚠", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#FF0000", tabId });
    chrome.action.setTitle({ title: "PhishGuard: ⚠️ Phishing Detected!", tabId });
    sendResponse({ status: "ok" });
  }

  // ── SAFE: update badge to green ───────────────────────────
  if (message.type === "SAFE" && tabId) {
    tabResults[tabId] = { url: message.url, prediction: "safe" };
    chrome.action.setBadgeText({ text: "✓", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#00AA55", tabId });
    chrome.action.setTitle({ title: "PhishGuard: ✅ Site appears safe", tabId });
    sendResponse({ status: "ok" });
  }

  // ── GET_RESULT: popup asks for cached tab result ──────────
  if (message.type === "GET_RESULT" && tabId) {
    sendResponse(tabResults[tabId] || { prediction: "unknown" });
  }

  return true;
});

// ── Clear cache on tab close ──────────────────────────────
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabResults[tabId];
});

// ── Reset badge on navigation ─────────────────────────────
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    delete tabResults[tabId];
    chrome.action.setBadgeText({ text: "", tabId });
    chrome.action.setTitle({ title: "PhishGuard: Checking…", tabId });
  }
});

console.log("[PhishGuard] Service worker ready.");
