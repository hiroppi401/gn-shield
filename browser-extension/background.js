/**
 * GN-Shield Security Companion - Background Service Worker
 *
 * Manages native messaging synchronization with gn-shield-native-host,
 * updates declarativeNetRequest rules for page-load blocking without waking JS,
 * and handles credential form-action-mismatch queries.
 *
 * Privacy guarantee: Never transmits visited URLs or page content to external servers.
 */

const NATIVE_HOST = "com.gnshield.host";

// Built-in fallback trusted identity providers (SSO/OAuth)
const DEFAULT_TRUSTED_IDPS = [
  "accounts.google.com",
  "login.microsoftonline.com",
  "github.com",
  "appleid.apple.com",
  "okta.com",
  "auth0.com"
];

let isHostConnected = false;
let lastRulesCount = 0;

/**
 * Checks if a hostname matches the trusted identity providers list.
 */
function isTrustedIdp(hostname) {
  const host = hostname.toLowerCase();
  return DEFAULT_TRUSTED_IDPS.some(pattern => {
    if (pattern.startsWith("*.")) {
      const base = pattern.slice(2);
      return host === base || host.endsWith("." + base);
    }
    return host === pattern || host.endsWith("." + pattern);
  });
}

/**
 * Synchronizes domain blocklists (phishing, C2, and mining pools) from gn-shield-native-host.
 */
function syncBlocklistFromHost() {
  if (typeof chrome === "undefined" || !chrome.runtime || !chrome.runtime.sendNativeMessage) {
    console.warn("[GN-Shield] Native messaging API not available in this environment.");
    return;
  }

  try {
    chrome.runtime.sendNativeMessage(NATIVE_HOST, { type: "get_blocklist" }, (response) => {
      if (chrome.runtime.lastError) {
        // Fail-open: Do not block navigation if daemon or native host is not available
        console.warn("[GN-Shield] Host connection failed (fail-open):", chrome.runtime.lastError.message);
        isHostConnected = false;
        if (chrome.storage && chrome.storage.local) {
          chrome.storage.local.set({
            connected: false,
            error: chrome.runtime.lastError.message,
            lastSync: Date.now()
          });
        }
        return;
      }

      if (response && response.rules) {
        isHostConnected = true;
        lastRulesCount = response.rules.length;

        // Apply rules directly to declarativeNetRequest engine (native C++ blocking at network layer)
        if (chrome.declarativeNetRequest) {
          chrome.declarativeNetRequest.getDynamicRules((existingRules) => {
            const removeRuleIds = existingRules.map((r) => r.id);
            chrome.declarativeNetRequest.updateDynamicRules(
              {
                removeRuleIds: removeRuleIds,
                addRules: response.rules
              },
              () => {
                if (chrome.runtime.lastError) {
                  console.error("[GN-Shield] Failed to update dynamic rules:", chrome.runtime.lastError.message);
                } else {
                  console.log(`[GN-Shield] Updated ${response.rules.length} declarative blocking rules.`);
                }
              }
            );
          });
        }

        if (chrome.storage && chrome.storage.local) {
          chrome.storage.local.set({
            connected: true,
            rulesCount: response.rules.length,
            version: response.version,
            lastSync: Date.now()
          });
        }
      }
    });
  } catch (err) {
    console.warn("[GN-Shield] sendNativeMessage exception (fail-open):", err);
    isHostConnected = false;
  }
}

/**
 * Handles incoming messages from content scripts and popups.
 */
if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === "check_form_action") {
      const pageOrigin = request.page_origin || "";
      const actionOrigin = request.action_origin || "";
      const hasPassword = !!request.has_password;

      // Quick local evaluation if target is trusted SSO/OAuth
      try {
        const actionHost = new URL(actionOrigin).hostname;
        if (isTrustedIdp(actionHost)) {
          sendResponse({
            action: "Allow",
            reason: `trusted_identity_provider: ${actionHost}`,
            is_trusted_idp: true
          });
          return true;
        }
      } catch (e) {
        // Fall through to host evaluation
      }

      // Delegate to gn-shield-native-host and decision engine
      chrome.runtime.sendNativeMessage(
        NATIVE_HOST,
        {
          type: "check_form_action",
          page_origin: pageOrigin,
          action_origin: actionOrigin,
          has_password: hasPassword
        },
        (response) => {
          if (chrome.runtime.lastError || !response) {
            // Fail-open fallback: If host is offline, allow legitimate browsing
            console.warn("[GN-Shield] Native host unreachable, falling back to safe local check.");
            sendResponse({
              action: "Allow",
              reason: "fail_open_host_unavailable",
              is_trusted_idp: false
            });
          } else {
            sendResponse(response);
          }
        }
      );
      return true; // Keep message channel open for asynchronous response
    }

    if (request.type === "trigger_sync") {
      syncBlocklistFromHost();
      sendResponse({ status: "sync_triggered" });
      return false;
    }

    if (request.type === "get_status") {
      chrome.storage.local.get(["connected", "rulesCount", "version", "lastSync"], (items) => {
        sendResponse(items || { connected: false, rulesCount: 0 });
      });
      return true;
    }
  });
}

// Periodic synchronization via chrome.alarms (every 60 minutes)
if (typeof chrome !== "undefined" && chrome.alarms) {
  chrome.alarms.create("sync_blocklist", { periodInMinutes: 60 });
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "sync_blocklist") {
      syncBlocklistFromHost();
    }
  });
}

// Lifecycle listeners
if (typeof chrome !== "undefined" && chrome.runtime) {
  if (chrome.runtime.onInstalled) {
    chrome.runtime.onInstalled.addListener(() => {
      console.log("[GN-Shield] Companion installed. Initializing rules...");
      syncBlocklistFromHost();
    });
  }

  if (chrome.runtime.onStartup) {
    chrome.runtime.onStartup.addListener(() => {
      console.log("[GN-Shield] Browser started. Checking rules...");
      syncBlocklistFromHost();
    });
  }
}
