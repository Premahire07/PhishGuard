// ============================================================
// popup.js — PhishGuard Popup Logic
// Routes all API calls through background.js to avoid CORS/mixed-content
// ============================================================
"use strict";

const statusCard  = document.getElementById("statusCard");
const spinnerEl   = document.getElementById("spinnerEl");
const statusTitle = document.getElementById("statusTitle");
const statusURL   = document.getElementById("statusURL");
const statusDesc  = document.getElementById("statusDesc");
const manualInput = document.getElementById("manualInput");
const checkBtn    = document.getElementById("checkBtn");

function renderResult(prediction, url) {
  if (spinnerEl) spinnerEl.remove();
  statusCard.className = "status-card";

  if (prediction === "phishing") {
    statusCard.classList.add("phishing");
    statusTitle.textContent = "⚠️ Phishing Site Detected!";
    statusDesc.textContent  = "Do NOT enter passwords or personal data on this page.";
    const icon = document.createElement("div");
    icon.className = "status-icon"; icon.textContent = "🚨";
    statusCard.insertAdjacentElement("afterbegin", icon);
  } else if (prediction === "safe") {
    statusCard.classList.add("safe");
    statusTitle.textContent = "✅ Site Appears Safe";
    statusDesc.textContent  = "No phishing indicators found. Stay cautious online.";
    const icon = document.createElement("div");
    icon.className = "status-icon"; icon.textContent = "✅";
    statusCard.insertAdjacentElement("afterbegin", icon);
  } else if (prediction === "error") {
    statusCard.classList.add("unknown");
    statusTitle.textContent = "⚙️ API Unreachable";
    statusDesc.textContent  = "Is Flask running? Run: python server.py in the backend folder.";
    const icon = document.createElement("div");
    icon.className = "status-icon"; icon.textContent = "⚙️";
    statusCard.insertAdjacentElement("afterbegin", icon);
  } else {
    statusCard.classList.add("unknown");
    statusTitle.textContent = "❓ Unknown";
    statusDesc.textContent  = "No result yet for this tab.";
    const icon = document.createElement("div");
    icon.className = "status-icon"; icon.textContent = "❓";
    statusCard.insertAdjacentElement("afterbegin", icon);
  }

  const display = url || "—";
  statusURL.textContent = display.length > 50 ? display.slice(0, 50) + "…" : display;
  statusURL.title = display;
}

// Route API call through background.js (avoids mixed-content block)
async function checkURLviaBackground(url) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "CHECK_URL", url }, (response) => {
      if (chrome.runtime.lastError) { resolve("error"); return; }
      resolve(response?.prediction || "error");
    });
  });
}

async function init() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) { renderResult("unknown", ""); return; }
    const tabURL = tab.url || "";
    statusURL.textContent = tabURL.length > 50 ? tabURL.slice(0, 50) + "…" : tabURL;

    chrome.runtime.sendMessage({ type: "GET_RESULT" }, (response) => {
      if (response?.prediction && response.prediction !== "unknown") {
        renderResult(response.prediction, response.url || tabURL);
      } else {
        checkURLviaBackground(tabURL).then((pred) => renderResult(pred, tabURL));
      }
    });
  } catch {
    renderResult("error", "");
  }
}

checkBtn.addEventListener("click", async () => {
  const url = manualInput.value.trim();
  if (!url) { manualInput.focus(); return; }
  const normalised = url.startsWith("http") ? url : "https://" + url;

  checkBtn.disabled = true;
  checkBtn.textContent = "…";
  statusCard.className = "status-card loading";
  statusTitle.textContent = "Scanning…";
  statusDesc.textContent  = "Sending to ML engine";
  statusURL.textContent   = normalised;

  const prediction = await checkURLviaBackground(normalised);
  renderResult(prediction, normalised);
  checkBtn.disabled = false;
  checkBtn.textContent = "Scan";
});

manualInput.addEventListener("keydown", (e) => { if (e.key === "Enter") checkBtn.click(); });

init();
