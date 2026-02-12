#!/usr/bin/env bash
set -euo pipefail

# Publish local wiki pages to GitHub Wiki repository.
# Usage: ./wiki/publish.sh [owner/repo]

REPO="${1:-osvaldoandrade/tikti}"
WIKI_URL="https://github.com/${REPO}.wiki.git"

TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

cp -R wiki/* "$TMP_DIR"/
find "$TMP_DIR" -name 'publish.sh' -delete

cd "$TMP_DIR"
git init >/dev/null
git checkout -b master >/dev/null
git add .
git commit -m "docs: publish tikti wiki" >/dev/null

if git ls-remote "$WIKI_URL" >/dev/null 2>&1; then
  git remote add origin "$WIKI_URL"
  git push -u origin master
else
  echo "Wiki repository is not available: $WIKI_URL"
  echo "Enable wiki in repository settings and create first page in UI if required, then run again."
  exit 1
fi
