# GN-Shield Companion - Store Submission Guide (Fase 4 Early MVP)

Following the project roadmap and `docs/ARCHITECTURE.md` section 3.9.1, store submissions to the **Chrome Web Store** and **Firefox Add-ons (AMO)** must be initiated at the beginning of Phase 4 to avoid review bottlenecks.

## 1. Fixed Deterministic Identifiers

| Platform | Fixed Identifier | Configured Location |
|---|---|---|
| **Chrome / Edge / Brave** | `acdgclnhgfblkcpbleihngdecipmalmb` | `key` in `manifest.json` and `allowed_origins` in host manifest |
| **Firefox (AMO)** | `companion@gn-shield.org` | `browser_specific_settings.gecko.id` in `manifest.json` |

## 2. Generating Submission Packages

Run the packaging script from this directory:
```bash
./package_extension.sh
```
This generates:
- `gn-shield-companion-chrome.zip`: Zip archive for Chrome Web Store Developer Dashboard.
- `gn-shield-companion-firefox.zip`: Zip archive for Mozilla Add-ons (AMO) Developer Hub.

## 3. Chrome Web Store Submission Steps
1. Navigate to the [Chrome Developer Dashboard](https://chrome.google.com/webstore/devconsole).
2. Click **New Item** and upload `gn-shield-companion-chrome.zip`.
3. Under **Visibility Options**: Select **Unlisted** (or Public when ready).
4. Under **Privacy Practices**:
   - Single Purpose: "Protects users against phishing and unauthorized cryptomining by enforcing local domain blocklists and checking password form destinations."
   - Permission Justification for `declarativeNetRequest`: "Enforces local domain blocklists against phishing and cryptominers without executing scripts on every page load."
   - Permission Justification for `nativeMessaging`: "Communicates with the local GN-Shield security daemon to retrieve threat feed updates and check allowlists."
   - Privacy Policy URL: link to `privacy-policy.md` hosted on GitHub.
   - Certify: "Data is not sold, used for creditworthiness, or transferred to third parties."
5. Submit for review.

## 4. Firefox Add-ons (AMO) Submission Steps
1. Navigate to the [Mozilla Add-on Developer Hub](https://addons.mozilla.org/developers/).
2. Click **Submit a New Add-on**.
3. Distribution Channel: Choose **On this site** (Public) or **On your own** (Unlisted, self-distributed).
4. Upload `gn-shield-companion-firefox.zip`.
5. Review warnings and submit.
