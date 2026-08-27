#!/bin/sh
# TATAR-Kuber суулгагч.
#   curl -fsSL https://raw.githubusercontent.com/ochmunkh/Tatar-Kuber/main/install.sh | sh
# Хувьсагч:
#   VERSION=v1.0.0   тодорхой хувилбар (default: хамгийн сүүлийн)
#   BIN_DIR=~/.local/bin   суулгах хавтас (default: /usr/local/bin, эрхгүй бол ~/.local/bin)
set -eu

REPO="ochmunkh/Tatar-Kuber"
BIN="tatar-kuber"
VERSION="${VERSION:-latest}"

die() { echo "алдаа: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# --- OS / ARCH ---
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
  linux) os="linux" ;;
  darwin) os="darwin" ;;
  *) die "дэмжигдээгүй OS: $os (Windows дээр Release-ээс .zip татна уу)" ;;
esac
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) die "дэмжигдээгүй архитектур: $arch" ;;
esac

# --- татагч ---
if have curl; then dl() { curl -fsSL "$1"; }; dlo() { curl -fsSL "$1" -o "$2"; }
elif have wget; then dl() { wget -qO- "$1"; }; dlo() { wget -qO "$2" "$1"; }
else die "curl эсвэл wget шаардлагатай"; fi

# --- хувилбар тодорхойлох ---
if [ "$VERSION" = "latest" ]; then
  VERSION="$(dl "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
  [ -n "$VERSION" ] || die "хамгийн сүүлийн хувилбарыг тодорхойлж чадсангүй"
fi
echo "TATAR-Kuber $VERSION ($os/$arch) татаж байна..."

ver_no_v="${VERSION#v}"
archive="${BIN}_${ver_no_v}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$VERSION"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

dlo "$base/$archive" "$tmp/$archive" || die "татаж чадсангүй: $base/$archive"

# --- checksum шалгах (боломжтой бол) ---
if dlo "$base/checksums.txt" "$tmp/checksums.txt" 2>/dev/null; then
  ( cd "$tmp"
    if have sha256sum; then
      grep " $archive\$" checksums.txt | sha256sum -c - >/dev/null 2>&1 || die "checksum таарсангүй"
    elif have shasum; then
      grep " $archive\$" checksums.txt | shasum -a 256 -c - >/dev/null 2>&1 || die "checksum таарсангүй"
    fi
  )
  echo "checksum баталгаажлаа"
fi

tar -xzf "$tmp/$archive" -C "$tmp" || die "задлаж чадсангүй"

# --- суулгах ---
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
if [ ! -w "$BIN_DIR" ] 2>/dev/null; then
  if [ "$(id -u)" != "0" ] && have sudo; then
    SUDO="sudo"
  else
    BIN_DIR="$HOME/.local/bin"; mkdir -p "$BIN_DIR"; SUDO=""
  fi
else
  SUDO=""
fi

${SUDO:-} install -m 0755 "$tmp/$BIN" "$BIN_DIR/$BIN" 2>/dev/null \
  || ${SUDO:-} cp "$tmp/$BIN" "$BIN_DIR/$BIN"
${SUDO:-} chmod +x "$BIN_DIR/$BIN" 2>/dev/null || true

echo "суулгалаа: $BIN_DIR/$BIN"
case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;
  *) echo "анхаар: $BIN_DIR нь PATH-д алга. Нэмнэ үү: export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac
"$BIN_DIR/$BIN" version 2>/dev/null || true
