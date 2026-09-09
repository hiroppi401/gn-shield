/**
 * GN-Shield Security Companion - Popup Logic
 */

document.addEventListener("DOMContentLoaded", () => {
  const daemonStatus = document.getElementById("daemon-status");
  const rulesCount = document.getElementById("rules-count");
  const statusDot = document.getElementById("status-dot");
  const btnSync = document.getElementById("btn-sync");

  function refreshUI() {
    if (typeof chrome === "undefined" || !chrome.runtime || !chrome.runtime.sendMessage) {
      daemonStatus.textContent = "Offline (Dev)";
      daemonStatus.className = "value offline";
      rulesCount.textContent = "0 rules";
      statusDot.className = "status-dot offline";
      return;
    }

    chrome.runtime.sendMessage({ type: "get_status" }, (response) => {
      if (response && response.connected) {
        daemonStatus.textContent = "Connected";
        daemonStatus.className = "value online";
        rulesCount.textContent = `${response.rulesCount || 0} rules`;
        statusDot.className = "status-dot online";
      } else {
        daemonStatus.textContent = "Standalone (Fail-open)";
        daemonStatus.className = "value offline";
        rulesCount.textContent = `${response ? response.rulesCount || 0 : 0} rules (cached)`;
        statusDot.className = "status-dot offline";
      }
    });
  }

  btnSync.addEventListener("click", () => {
    btnSync.disabled = true;
    btnSync.textContent = "Syncing...";
    if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({ type: "trigger_sync" }, () => {
        setTimeout(() => {
          btnSync.disabled = false;
          btnSync.textContent = "Sync with Core";
          refreshUI();
        }, 600);
      });
    } else {
      setTimeout(() => {
        btnSync.disabled = false;
        btnSync.textContent = "Sync with Core";
      }, 300);
    }
  });

  refreshUI();
});
