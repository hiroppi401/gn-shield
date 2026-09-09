/**
 * GN-Shield Security Companion - Content Script
 *
 * Lightweight, privacy-preserving anti-phishing form-action-mismatch evaluator.
 * Detects password forms submitting credentials to unverified third-party origins.
 *
 * NFR Constraint: Page-load overhead must be strictly under 50ms.
 * Privacy Constraint: Zero transmission of page content or credentials to external servers.
 */

(function () {
  "use strict";

  const startTime = performance.now();

  // Fast-path known trusted identity providers in memory to avoid asynchronous delay
  const TRUSTED_IDPS = [
    "accounts.google.com",
    "login.microsoftonline.com",
    "github.com",
    "appleid.apple.com",
    "okta.com",
    "auth0.com"
  ];

  function matchesTrustedIdp(hostname) {
    const host = hostname.toLowerCase();
    return TRUSTED_IDPS.some((pattern) => {
      if (pattern.startsWith("*.")) {
        const base = pattern.slice(2);
        return host === base || host.endsWith("." + base);
      }
      return host === pattern || host.endsWith("." + pattern);
    });
  }

  function resolveActionUrl(action) {
    try {
      if (!action || action.trim() === "") {
        return window.location.href;
      }
      return new URL(action, window.location.href).href;
    } catch (e) {
      return window.location.href;
    }
  }

  function createWarningDialog(pageHost, actionHost, onProceed, onCancel) {
    const existing = document.getElementById("gn-shield-phishing-modal");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.id = "gn-shield-phishing-modal";
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.65);
      z-index: 2147483647;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    `;

    const card = document.createElement("div");
    card.style.cssText = `
      background: #1e1e24;
      color: #f1f1f1;
      border: 2px solid #e63946;
      border-radius: 12px;
      padding: 24px;
      max-width: 480px;
      width: 90%;
      box-shadow: 0 10px 30px rgba(0,0,0,0.5);
      text-align: left;
    `;

    card.innerHTML = `
      <div style="display:flex; align-items:center; gap: 12px; margin-bottom: 16px;">
        <span style="font-size: 28px;">🛡️</span>
        <div>
          <h3 style="margin:0; font-size:18px; color:#ff4d4f; font-weight:700;">GN-Shield Security Alert</h3>
          <p style="margin:2px 0 0 0; font-size:12px; color:#a0a0a0;">Anti-Phishing Form Protection</p>
        </div>
      </div>
      <p style="font-size:14px; line-height:1.5; margin:0 0 12px 0;">
        This page (<strong>${escapeHtml(pageHost)}</strong>) is attempting to submit your password to an external domain:
      </p>
      <div style="background:#2a2a35; padding:10px; border-radius:6px; font-family:monospace; font-size:13px; color:#fca311; word-break:break-all; margin-bottom:16px;">
        ${escapeHtml(actionHost)}
      </div>
      <p style="font-size:12px; line-height:1.4; color:#cccccc; margin:0 0 20px 0;">
        Unverified cross-origin credential submissions are commonly used in phishing attacks to capture login credentials.
      </p>
      <div style="display:flex; justify-content:flex-end; gap:12px;">
        <button id="gn-shield-btn-cancel" style="background:#4a4e69; color:#fff; border:none; border-radius:6px; padding:8px 16px; font-size:13px; cursor:pointer; font-weight:600;">
          Cancel Submission (Safe)
        </button>
        <button id="gn-shield-btn-proceed" style="background:#e63946; color:#fff; border:none; border-radius:6px; padding:8px 16px; font-size:13px; cursor:pointer; font-weight:600;">
          Proceed Anyway
        </button>
      </div>
    `;

    overlay.appendChild(card);
    document.body.appendChild(overlay);

    document.getElementById("gn-shield-btn-cancel").addEventListener("click", () => {
      overlay.remove();
      onCancel();
    });

    document.getElementById("gn-shield-btn-proceed").addEventListener("click", () => {
      overlay.remove();
      onProceed();
    });
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  function attachFormProtection(form) {
    if (form.__gn_shield_attached) return;
    form.__gn_shield_attached = true;

    form.addEventListener("submit", function (event) {
      if (form.__gn_shield_approved) {
        return; // User explicitly approved submission
      }

      const passwordInput = form.querySelector('input[type="password"]');
      if (!passwordInput) {
        return; // Form does not handle credentials
      }

      const currentOrigin = window.location.origin;
      const targetUrl = resolveActionUrl(form.action);
      let targetOrigin = currentOrigin;
      let targetHost = window.location.hostname;

      try {
        const parsed = new URL(targetUrl);
        targetOrigin = parsed.origin;
        targetHost = parsed.hostname;
      } catch (e) {
        return;
      }

      // 1. Same origin: Allow immediately
      if (currentOrigin === targetOrigin) {
        return;
      }

      // 2. Fast-path trusted IDP (Google, Microsoft, GitHub, Apple, Okta): Allow immediately
      if (matchesTrustedIdp(targetHost)) {
        return;
      }

      // 3. Potential phishing / form action mismatch: intercept and consult background worker
      event.preventDefault();
      event.stopPropagation();

      const pageOrigin = window.location.origin;

      if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage(
          {
            type: "check_form_action",
            page_origin: pageOrigin,
            action_origin: targetOrigin,
            has_password: true
          },
          function (response) {
            if (response && response.action === "Allow") {
              // Approved by daemon allowlist
              form.__gn_shield_approved = true;
              form.submit();
            } else {
              // Block or PromptUser
              createWarningDialog(
                window.location.hostname,
                targetHost,
                function onProceed() {
                  form.__gn_shield_approved = true;
                  form.submit();
                },
                function onCancel() {
                  console.warn("[GN-Shield] Phishing form submission canceled by user.");
                }
              );
            }
          }
        );
      } else {
        // Standalone fallback: show prompt directly
        createWarningDialog(
          window.location.hostname,
          targetHost,
          function onProceed() {
            form.__gn_shield_approved = true;
            form.submit();
          },
          function onCancel() {}
        );
      }
    }, true);
  }

  // Scan all existing forms
  const forms = document.querySelectorAll("form");
  forms.forEach(attachFormProtection);

  // Observe dynamically inserted forms
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE) {
          if (node.tagName === "FORM") {
            attachFormProtection(node);
          } else if (node.querySelectorAll) {
            node.querySelectorAll("form").forEach(attachFormProtection);
          }
        }
      }
    }
  });

  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  }

  const duration = performance.now() - startTime;
  if (duration > 50) {
    console.warn(`[GN-Shield] Content script overhead exceeded 50ms budget: ${duration.toFixed(2)}ms`);
  }
})();
