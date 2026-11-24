#!/usr/bin/env sh
set -eu

REPO="keytwig/keytwig"
BIN_NAME="keytwig"
INSTALL_DIR="${KEYTWIG_INSTALL_DIR:-$HOME/.local/bin}"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  linux)  OS="linux" ;;
  darwin) OS="darwin" ;;
  *)
    echo "Unsupported OS: $OS (download manually from https://github.com/$REPO/releases)" >&2
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

VERSION="${KEYTWIG_VERSION:-}"
if [ -z "$VERSION" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
fi
if [ -z "$VERSION" ]; then
  echo "Failed to resolve latest release tag from GitHub." >&2
  exit 1
fi

VER_NUM="${VERSION#v}"
ARCHIVE="${BIN_NAME}_${VER_NUM}_${OS}_${ARCH}.tar.gz"
BASE_URL="https://github.com/$REPO/releases/download/$VERSION"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' 0

echo "Downloading ${BIN_NAME} ${VERSION} (${OS}/${ARCH})..."
curl -fsSL "${BASE_URL}/${ARCHIVE}" -o "${TMP_DIR}/${ARCHIVE}"
curl -fsSL "${BASE_URL}/checksums.txt" -o "${TMP_DIR}/checksums.txt"

EXPECTED="$(awk -v archive="$ARCHIVE" '$2 == archive { print $1 }' "${TMP_DIR}/checksums.txt")"
if ! printf '%s\n' "$EXPECTED" | grep -Eq '^[0-9a-f]{64}$' || [ "${#EXPECTED}" -ne 64 ]; then
  echo "Missing, invalid, or duplicate checksum for ${ARCHIVE}" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "${TMP_DIR}/${ARCHIVE}")"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL="$(shasum -a 256 "${TMP_DIR}/${ARCHIVE}")"
else
  echo "Install sha256sum or shasum to verify ${ARCHIVE}" >&2
  exit 1
fi
ACTUAL="${ACTUAL%% *}"
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "Checksum mismatch for ${ARCHIVE}: expected ${EXPECTED}, got ${ACTUAL}" >&2
  exit 1
fi

tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "${TMP_DIR}"
mkdir -p "${INSTALL_DIR}"
install -m 755 "${TMP_DIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"

echo "Installed ${BIN_NAME} to ${INSTALL_DIR}/${BIN_NAME}"
"${INSTALL_DIR}/${BIN_NAME}" version

case ":$PATH:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo ""
    echo "Add ${INSTALL_DIR} to your PATH:"
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    ;;
esac
