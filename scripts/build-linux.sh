#!/usr/bin/env bash
# Baut Doclatch für Linux (x86-64, ARM64, RISC-V) gegen glibc 2.28 und packt die Ergebnisse nach dist/.
#
# Voraussetzungen (einmalig):
#   cargo install --locked cargo-zigbuild        # oder: pip install cargo-zigbuild (bringt Zig mit)
#   rustup target add aarch64-unknown-linux-gnu riscv64gc-unknown-linux-gnu
#   optional für .deb:  cargo install --locked cargo-deb
#
# Aufruf im Projektordner:  scripts/build-linux.sh [Ziel ...]
#   ohne Argumente: alle drei Architekturen
set -euo pipefail
cd "$(dirname "$0")/.."

GLIBC="2.28"
TARGETS=("$@")
[ ${#TARGETS[@]} -eq 0 ] && TARGETS=(x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu riscv64gc-unknown-linux-gnu)

VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
DIST=dist
mkdir -p "$DIST"

command -v cargo-zigbuild >/dev/null || { echo "cargo-zigbuild fehlt (siehe Kopf dieses Skripts)"; exit 1; }
HAVE_DEB=0; command -v cargo-deb >/dev/null && HAVE_DEB=1

for T in "${TARGETS[@]}"; do
    ARCH=${T%%-*}; [ "$ARCH" = riscv64gc ] && ARCH=riscv64
    echo "==> $T (glibc $GLIBC)"
    cargo zigbuild --release --locked --target "$T.$GLIBC"

    BIN="target/$T/release/doclatch"
    MAXGLIBC=$(objdump -T "$BIN" 2>/dev/null | grep -oE 'GLIBC_[0-9.]+' | sort -Vu | tail -1 || true)
    echo "    benötigt: ${MAXGLIBC:-unbekannt}"

    NAME="doclatch-$VERSION-linux-$ARCH"
    STAGE=$(mktemp -d)
    mkdir -p "$STAGE/$NAME"
    cp "$BIN" README.md README.de.md LICENSE-MIT LICENSE-APACHE THIRD_PARTY_LICENSES.txt packaging/doclatch.desktop "$STAGE/$NAME/"
    tar -C "$STAGE" -czf "$DIST/$NAME.tar.gz" "$NAME"
    rm -rf "$STAGE"
    echo "    -> $DIST/$NAME.tar.gz"

    if [ $HAVE_DEB = 1 ]; then
        cargo deb --target "$T" --no-build --no-strip --output "$DIST/" >/dev/null
        echo "    -> $DIST/$(ls -t "$DIST" | grep -m1 '\.deb$')"
    fi
done

(cd "$DIST" && sha256sum ./*.tar.gz ./*.deb 2>/dev/null | sed 's# \./# #' > SHA256SUMS.txt)
echo "Prüfsummen: $DIST/SHA256SUMS.txt"
