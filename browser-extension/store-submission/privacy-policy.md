# GN-Shield Security Companion - Privacy Policy

**Effective Date:** September 2026
**Commitment:** 100% Local Processing & Strict Zero Cloud Telemetry

## 1. Zero External Transmission Principle
GN-Shield Security Companion is designed from the ground up for privacy-conscious developers and users.
The extension:
- **Never sends visited URLs**, page history, or browsing activity to any external server or third-party service.
- **Never transmits form inputs, passwords, or page content** outside your local system.
- **Does not collect analytics, diagnostics, crash reports, or telemetry**.

## 2. Local-Only Native Messaging
All blocklist verification and heuristic evaluations are performed entirely on your local machine by communicating with the local GN-Shield daemon via local standard input/output (`nativeMessaging`). The native host binary (`gn-shield-native-host`) runs on your local computer and queries your locally cached threat feeds.

## 3. Explanation of Requested Permissions

| Permission | Technical Requirement & Privacy Guardrail |
|---|---|
| `declarativeNetRequest` | Enforces blocklists against known phishing, malware C2, and in-page cryptomining domains natively at the browser network layer without waking JavaScript for every navigation. |
| `storage` | Caches local configuration and rule counts in `chrome.storage.local`. Data stays exclusively on your machine. |
| `alarms` | Periodically triggers a refresh from the local GN-Shield daemon once per hour to keep threat rules up to date. |
| `nativeMessaging` | Allows the companion extension to communicate strictly with the local binary `com.gnshield.host` over standard OS pipes. |
| Host Permissions (`<all_urls>`) | Required solely to apply declarative network blocking rules across visited domains and inspect password form targets against our local SSO/OAuth allowlist. Content is never exfiltrated. |

## 4. Contact & Open Source Verification
GN-Shield is completely open source under the GNU General Public License v3 or later. You can inspect the entire source code at:
`https://github.com/hiroppi401/gn-shield`
