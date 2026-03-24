// ============================================================
// content.js — PhishGuard Content Script
// Runs on every webpage. Checks the current URL and all
// clicked links against the ML backend, then shows warnings.
//
// FIX: API calls are routed through background.js (service worker)
// because content scripts on HTTPS pages CANNOT directly call
// HTTP endpoints (mixed-content policy blocks it). The background
// service worker is not subject to this restriction.
// ============================================================

(function () {
  "use strict";

  const BANNER_ID = "phishguard-warning-banner";

  // ─────────────────────────────────────────────────────────
  // checkURL: asks background.js to call the Flask API
  // This is the KEY fix — background workers bypass mixed-content
  // ─────────────────────────────────────────────────────────
  async function checkURL(url) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(
          { type: "CHECK_URL", url },
          (response) => {
            if (chrome.runtime.lastError) {
              console.warn("[PhishGuard] BG error:", chrome.runtime.lastError.message);
              resolve("error");
              return;
            }
            resolve(response?.prediction || "error");
          }
        );
      } catch (err) {
        console.warn("[PhishGuard] Messaging failed:", err.message);
        resolve("error");
      }
    });
  }

  // ── Show red warning banner at top of page ────────────────
  function showWarningBanner(url) {
    if (document.getElementById(BANNER_ID)) return;

    const banner = document.createElement("div");
    banner.id = BANNER_ID;
    banner.setAttribute("role", "alert");
    banner.innerHTML = `
      <div class="phishguard-icon">🛡️</div>
      <div class="phishguard-content">
        <div class="phishguard-title">⚠️ Phishing Site Detected!</div>
        <div class="phishguard-message">
          This website may be a <strong>phishing site</strong> trying to steal your
          passwords or personal information. <strong>Do not enter any credentials.</strong>
        </div>
        <div class="phishguard-url" title="${url}">${url.length > 80 ? url.slice(0, 80) + "…" : url}</div>
      </div>
      <button class="phishguard-close" id="phishguard-close-btn" title="Dismiss warning">✕</button>
    `;

    document.body.insertAdjacentElement("afterbegin", banner);

    document.body.style.marginTop =
      (parseInt(document.body.style.marginTop || "0") + banner.offsetHeight + 8) + "px";

    document.getElementById("phishguard-close-btn").addEventListener("click", () => {
      removeBanner();
    });

    disableCredentialFields();
  }

  function removeBanner() {
    const banner = document.getElementById(BANNER_ID);
    if (banner) {
      const h = banner.offsetHeight;
      banner.remove();
      document.body.style.marginTop =
        Math.max(0, parseInt(document.body.style.marginTop || "0") - h - 8) + "px";
    }
  }

  function disableCredentialFields() {
    const inputs = document.querySelectorAll(
      'input[type="password"], input[type="email"], input[name*="user"], input[name*="login"], input[name*="pass"]'
    );
    inputs.forEach((input) => {
      input.setAttribute("disabled", "true");
      input.setAttribute("placeholder", "⚠️ Blocked by PhishGuard");
      input.style.borderColor = "#ff4444";
      input.style.backgroundColor = "#fff0f0";
    });
  }

  // ── Check current page on load ────────────────────────────
  async function checkCurrentPage() {
    const currentURL = window.location.href;
    if (
      currentURL.startsWith("chrome://") ||
      currentURL.startsWith("chrome-extension://") ||
      currentURL.startsWith("about:") ||
      currentURL.startsWith("moz-extension://")
    ) return;

    console.log("[PhishGuard] Checking:", currentURL);
    const result = await checkURL(currentURL);

    if (result === "phishing") {
      console.warn("[PhishGuard] ⚠️ PHISHING:", currentURL);
      showWarningBanner(currentURL);
      chrome.runtime.sendMessage({ type: "PHISHING_DETECTED", url: currentURL });
    } else if (result === "safe") {
      console.log("[PhishGuard] ✅ Safe:", currentURL);
      chrome.runtime.sendMessage({ type: "SAFE", url: currentURL });
    }
  }

  // ── Intercept link clicks ─────────────────────────────────
  document.addEventListener("click", async (event) => {
    let target = event.target;
    while (target && target.tagName !== "A") target = target.parentElement;
    if (!target?.href) return;

    const href = target.href;
    if (!href.startsWith("http://") && !href.startsWith("https://")) return;

    const result = await checkURL(href);
    if (result === "phishing") {
      event.preventDefault();
      const confirmed = window.confirm(
        `⚠️ PhishGuard Warning!\n\nThe link you clicked appears to be a PHISHING site:\n\n${href}\n\nDo you still want to proceed? (Not recommended)`
      );
      if (confirmed) window.location.href = href;
    }
  }, true);

  // ── Boot ──────────────────────────────────────────────────
  checkCurrentPage();
})();
