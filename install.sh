#!/bin/bash
set -e

VERSION=$(curl -s https://api.github.com/repos/Colin4k1024/goreview/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  armv7l) ARCH="arm7" ;;
esac

EXT="tar.gz"
if [ "$OS" = "windows" ]; then
  EXT="zip"
fi

FILENAME="goreview_${VERSION}_${OS}_${ARCH}.${EXT}"
URL="https://github.com/Colin4k1024/goreview/releases/download/v${VERSION}/${FILENAME}"

echo "Downloading GoReview v${VERSION} for ${OS}/${ARCH}..."
curl -fsSL "$URL" -o "/tmp/${FILENAME}"

mkdir -p "${HOME}/.local/bin"
tar -xzf "/tmp/${FILENAME}" -C "${HOME}/.local/bin/" 2>/dev/null || unzip -o "/tmp/${FILENAME}" -d "${HOME}/.local/bin/" 2>/dev/null
rm -f "/tmp/${FILENAME}"

echo "Installed to ${HOME}/.local/bin/goreview"
echo "Add to PATH: export PATH=\"\${HOME}/.local/bin:\${PATH}\""
