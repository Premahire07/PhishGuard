// ============================================================
// content.js — PhishGuard Content Script
// Runs on every page. Checks the current URL and all link
// clicks against the backend ML model.
// ============================================================

const API_URL = "http://127.0.0.1:5000/predict";

// ── Avoid running the check more than once per page load ────
let hasCheckedPage = false;

// ── 1. Check the page URL as soon as the script is injected ─
(function checkCurrentPage() {
  if (hasCheckedPage) return;
  hasCheckedPage = true;

  const url = window.location.href;

  // Skip internal browser pages (chrome://, about:, etc.)
  if (!url.startsWith("http")) return;

  checkURL(url, "page");
})();

// ── 2. Intercept every link click on the page ───────────────
document.addEventListener("click", function (event) {
  // Walk up the DOM from the clicked element to find an <a> tag
  let target = event.target;
  while (target && target.tagName !== "A") {
    target = target.parentElement;
  }

  if (!target || !target.href) return;

  const clickedURL = target.href;

  // Only check http/https links
  if (!clickedURL.startsWith("http")) return;

  // If the link goes to a different origin, check it before navigating
  if (new URL(clickedURL).origin !== window.location.origin) {
    event.preventDefault(); // Pause navigation temporarily

    checkURL(clickedURL, "link", function (isSafe) {
      if (isSafe) {
        // Resume navigation if safe
        window.location.href = clickedURL;
      }
      // If phishing, the warning banner is shown and navigation is blocked
    });
  }
}, true); // Use capture phase so we catch events early

// ── Core function: sends URL to Flask API ───────────────────
/**
 * @param {string} url       - The URL to check
 * @param {string} source    - "page" or "link" (for logging)
 * @param {function} [callback] - Called with (isSafe: boolean)
 */
function checkURL(url, source, callback) {
  console.log(`[PhishGuard] Checking ${source} URL:`, url);

  fetch(API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: url }),
  })
    .then((response) => response.json())
    .then((data) => {
      console.log(`[PhishGuard] Result for ${url}:`, data.prediction);

      if (data.prediction === "phishing") {
        showWarningBanner(url);
        blockCredentialInputs();
        // Notify the background script so the popup can update
        chrome.runtime.sendMessage({
          type: "PHISHING_DETECTED",
          url: url,
        });
        if (callback) callback(false); // NOT safe
      } else {
        if (callback) callback(true); // Safe
      }
    })
    .catch((err) => {
      // API unreachable — fail open (don't block the user)
      console.warn("[PhishGuard] Could not reach API:", err);
      if (callback) callback(true);
    });
}

// ── Show a full-width warning banner at the top of the page ─
function showWarningBanner(url) {
  // Don't add duplicate banners
  if (document.getElementById("phishguard-banner")) return;

  const banner = document.createElement("div");
  banner.id = "phishguard-banner";
  banner.innerHTML = `
    <div class="phishguard-icon">⚠️</div>
    <div class="phishguard-text">
      <strong>PhishGuard Warning:</strong>
      This website may be a <strong>phishing site</strong>.
      Your credentials and personal data could be stolen.
      <span class="phishguard-url">${escapeHTML(url)}</span>
    </div>
    <div class="phishguard-actions">
      <button id="phishguard-leave">Leave Site</button>
      <button id="phishguard-dismiss">Dismiss</button>
    </div>
  `;

  // Insert as the very first child of <body>
  document.body.insertBefore(banner, document.body.firstChild);

  // Push page content down so nothing is hidden behind the banner
  document.body.style.marginTop =
    (parseInt(document.body.style.marginTop || "0") + banner.offsetHeight + 10) + "px";

  // "Leave Site" → go to a safe page
  document.getElementById("phishguard-leave").addEventListener("click", () => {
    window.location.href = "about:blank";
  });

  // "Dismiss" → remove banner (user's choice to continue)
  document.getElementById("phishguard-dismiss").addEventListener("click", () => {
    banner.remove();
  });
}

// ── Disable all password & text inputs to prevent credential theft ──
function blockCredentialInputs() {
  const inputs = document.querySelectorAll(
    'input[type="password"], input[type="email"], input[type="text"]'
  );
  inputs.forEach((input) => {
    input.disabled = true;
    input.placeholder = "⚠ Blocked by PhishGuard";
    input.style.backgroundColor = "#ffe5e5";
    input.style.cursor = "not-allowed";
  });

  // Also watch for dynamically added inputs (SPAs, lazy-loaded forms)
  const observer = new MutationObserver(() => {
    const newInputs = document.querySelectorAll(
      'input[type="password"]:not([disabled]), input[type="email"]:not([disabled])'
    );
    newInputs.forEach((input) => {
      input.disabled = true;
      input.placeholder = "⚠ Blocked by PhishGuard";
      input.style.backgroundColor = "#ffe5e5";
    });
  });
  observer.observe(document.body, { childList: true, subtree: true });
}

// ── Utility: escape HTML to prevent XSS in the banner ───────
function escapeHTML(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
