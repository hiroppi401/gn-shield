#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "==> Packaging GN-Shield Security Companion extensions..."

CHROME_ZIP="${EXT_DIR}/store-submission/gn-shield-companion-chrome.zip"
FIREFOX_ZIP="${EXT_DIR}/store-submission/gn-shield-companion-firefox.zip"

rm -f "${CHROME_ZIP}" "${FIREFOX_ZIP}"

# Package Chrome MV3
(
  cd "${EXT_DIR}"
  zip -r "${CHROME_ZIP}" \
    manifest.json \
    background.js \
    content.js \
    popup.html \
    popup.css \
    popup.js \
    icons/
)

echo "✅ Created Chrome package: ${CHROME_ZIP}"

# Package Firefox
(
  cd "${EXT_DIR}"
  zip -r "${FIREFOX_ZIP}" \
    manifest.json \
    background.js \
    content.js \
    popup.html \
    popup.css \
    popup.js \
    icons/
)

echo "✅ Created Firefox package: ${FIREFOX_ZIP}"
