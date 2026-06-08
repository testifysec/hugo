#!/usr/bin/env bash
#
# validate_binary.sh — offline integrity check of the built hugo binary.
# Go analogue of the litellm wheel-RECORD check: recompute the artifact digest,
# confirm the embedded version matches the source tag, and confirm Go build
# metadata (module pins) is present. Deterministic, no network.
#
set -euo pipefail

BIN="${1:-dist/hugo}"
EXPECT_VERSION="${2:-}"

[ -x "$BIN" ] || { echo "validate: $BIN missing or not executable" >&2; exit 1; }

DIGEST="$(shasum -a 256 "$BIN" | awk '{print $1}')"
echo "binary        : $BIN"
echo "sha256        : $DIGEST"

VERSION_LINE="$("$BIN" version 2>&1 | head -1)"
echo "version       : $VERSION_LINE"

if [ -n "$EXPECT_VERSION" ]; then
  case "$VERSION_LINE" in
    *"$EXPECT_VERSION"*) echo "version-match : OK ($EXPECT_VERSION)" ;;
    *) echo "version-match : FAIL (expected $EXPECT_VERSION)" >&2; exit 1 ;;
  esac
fi

# Go embeds module build info in the binary; its presence is evidence the
# dependency graph was pinned at build time (vgo go.sum semantics).
MODCOUNT="$(go version -m "$BIN" 2>/dev/null | grep -c $'\tdep\t' || true)"
echo "pinned-deps   : $MODCOUNT modules in embedded buildinfo"
[ "$MODCOUNT" -gt 0 ] || { echo "validate: no embedded module buildinfo" >&2; exit 1; }

echo "validate      : PASS"
