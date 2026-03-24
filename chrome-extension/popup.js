// ============================================================
// popup.js — PhishGuard Popup Script
// Gets the current tab URL, queries the Flask API, and
// displays the result inside the popup UI.
// ============================================================

const API_URL = "http://127.0.0.1:5000/predict";

// ── DOM references ──────────────────────────────────────────
const statusCard  = document.getElementById("statusCard");
const statusIcon  = document.getElementById("statusIcon");
const statusLabel = document.getElementById("statusLabel");
const statusDesc  = document.getElementById("statusDesc");
const urlDisplay  = document.getElementById("urlDisplay");
const checkBtn    = document.getElementById("checkBtn");
const apiDot      = document.getElementById("apiDot");
const apiStatusText = document.getElementById("apiStatusText");

// ── On popup open: check the active tab ────────────────────
document.addEventListener("DOMContentLoaded", () => {
  getCurrentTabAndCheck();
});

// ── Manual re-check button ──────────────────────────────────
checkBtn.addEventListener("click", () => {
  setChecking();
  getCurrentTabAndCheck();
});

// ── Get active tab URL then call the API ────────────────────
function getCurrentTabAndCheck() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || tabs.length === 0) {
      setUnknown("No active tab found.");
      return;
    }

    const tab = tabs[0];
    const url = tab.url;

    // Display URL (truncated for UI)
    urlDisplay.textContent = url || "No URL";

    // Skip non-http pages
    if (!url || !url.startsWith("http")) {
      setUnknown("Not a web page — nothing to check.");
      return;
    }

    checkURL(url);
  });
}

// ── Call Flask API ──────────────────────────────────────────
function checkURL(url) {
  setChecking();

  fetch(API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: url }),
  })
    .then((res) => {
      if (!res.ok) throw new Error("API returned " + res.status);
      return res.json();
    })
    .then((data) => {
      // Mark API as online
      apiDot.className = "api-dot online";
      apiStatusText.textContent = "API Online";

      if (data.prediction === "phishing") {
        setPhishing(url);
      } else {
        setSafe();
      }
    })
    .catch((err) => {
      console.error("[PhishGuard Popup] API error:", err);
      apiDot.className = "api-dot offline";
      apiStatusText.textContent = "API Offline";
      setUnknown("Could not reach the PhishGuard API. Is the Flask server running?");
    });
}

// ── UI State Helpers ────────────────────────────────────────

function setChecking() {
  statusCard.className = "status-card checking";
  statusIcon.textContent = "⏳";
  statusLabel.textContent = "Checking...";
  statusDesc.textContent = "Sending URL to ML model for analysis";
}

function setSafe() {
  statusCard.className = "status-card safe";
  statusIcon.textContent = "✅";
  statusLabel.textContent = "Site Looks Safe";
  statusDesc.textContent = "No phishing indicators detected by the ML model.";
}

function setPhishing(url) {
  statusCard.className = "status-card phishing";
  statusIcon.textContent = "🚨";
  statusLabel.textContent = "PHISHING DETECTED!";
  statusDesc.textContent =
    "This site has been flagged as a potential phishing page. Do NOT enter credentials.";
}

function setUnknown(message) {
  statusCard.className = "status-card unknown";
  statusIcon.textContent = "❓";
  statusLabel.textContent = "Status Unknown";
  statusDesc.textContent = message || "Unable to determine page safety.";
}
