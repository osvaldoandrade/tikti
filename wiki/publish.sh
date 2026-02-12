#!/usr/bin/env bash
set -euo pipefail

# Publish local wiki pages to GitHub Wiki repository.
# Usage: ./wiki/publish.sh [owner/repo]

REPO="${1:-osvaldoandrade/tikti}"
WIKI_URL="https://github.com/${REPO}.wiki.git"

TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

if git ls-remote "$WIKI_URL" >/dev/null 2>&1; then
  git clone "$WIKI_URL" "$TMP_DIR/wiki" >/dev/null
  rsync -a --delete --exclude '.git' --exclude 'publish.sh' wiki/ "$TMP_DIR/wiki/"

  cd "$TMP_DIR/wiki"
  git add -A
  if git diff --cached --quiet; then
    echo "No wiki changes to publish."
    exit 0
  fi

  git commit -m "docs: publish tikti wiki" >/dev/null
  git push origin master
else
  echo "Wiki repository is not available: $WIKI_URL"
  echo "Enable wiki in repository settings and create first page in UI if required, then run again."
  exit 1
fi
