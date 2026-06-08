#!/usr/bin/env bash
#
# secure-release.sh — SSDF/SLSA secured release pipeline for the internal
# Hugo fork, driven entirely by cilock (offline, local file-signer).
#
# Each stage is wrapped in `cilock run`/`cilock attest`, producing a signed
# DSSE/in-toto attestation bundle. A Witness policy generated from those
# bundles is then signed and used by `cilock verify` to gate the hugo binary
# (fail-closed). All offline: --platform-url "" , local ECDSA P-256 key.
#
# Stages:  source -> build -> sbom -> vuln-scan -> validate -> policy -> verify
#
set -uo pipefail

SC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SC_DIR/.." && pwd)"
cd "$ROOT"

CILOCK="${CILOCK:-cilock}"
KEY="supply-chain/keys/release.key"
PUB="supply-chain/keys/release.pub"
B="supply-chain/bundles"
P="supply-chain/policy"
PLAT='--platform-url'; URL=''        # URL="" => fully offline (no platform/TSA)
COMMON=(--workload manual -k "$KEY" "$PLAT" "$URL")

VERSION="$(git describe --tags --always 2>/dev/null || echo unknown)"

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
hdr()  { printf '\n\033[1m=== %s ===\033[0m\n' "$*"; }
die()  { red "FATAL: $*"; exit 1; }

rm -rf dist "$B" "$P" supply-chain/sbom supply-chain/scans
mkdir -p "$B" "$P" supply-chain/sbom supply-chain/scans dist
# keep the build's git attestor status clean: our tooling/outputs aren't source
cat > .git/info/exclude <<'EOF'
/supply-chain/bundles/
/supply-chain/policy/
/supply-chain/sbom/
/supply-chain/scans/
/dist/
EOF

# ============================================================================
hdr "1/7 source — pin commit + build env  (SSDF PS.1 / SLSA Source)"
$CILOCK attest -s source -a git,environment "${COMMON[@]}" \
  -o "$B/source.bundle.json" || die "source attest failed"
grn "  -> $B/source.bundle.json"

# ============================================================================
hdr "2/7 build — go build, Go provenance + SLSA  (SSDF PS.2,PW.6 / SLSA Build)"
# go-build attestor records the Go toolchain + module graph; slsa emits
# provenance/v1.0; material+product keep the binary as an attested leaf.
$CILOCK run -s build -a git,environment,lockfiles,go-build,slsa,secretscan "${COMMON[@]}" \
  -o "$B/build.bundle.json" \
  -- go build -trimpath -o dist/hugo . || die "build failed"
BIN="dist/hugo"
[ -x "$BIN" ] || die "no hugo binary produced"
grn "  -> built $BIN ($($BIN version 2>&1 | head -1))"
grn "  -> $B/build.bundle.json"

# ============================================================================
hdr "3/7 sbom — CycloneDX of the binary's module graph  (SSDF PW.4)"
# syft reads Go buildinfo embedded in the binary -> full resolved dependency set.
$CILOCK run -s sbom -a environment,sbom --no-default-attestor material \
  --attestor-sbom-file supply-chain/sbom/hugo.cdx.json --attestor-sbom-export \
  "${COMMON[@]}" -o "$B/sbom.bundle.json" \
  -- syft scan "file:$BIN" -o cyclonedx-json=supply-chain/sbom/hugo.cdx.json -q \
  || die "sbom step failed"
grn "  -> supply-chain/sbom/hugo.cdx.json + $B/sbom.bundle.json"

# ============================================================================
hdr "4/7 vuln-scan — trivy over the SBOM -> SARIF  (SSDF RV.1)"
# Non-gating: records findings as evidence. Threshold/gating is a policy choice.
$CILOCK run -s vuln-scan -a environment,sarif --no-default-attestor material \
  "${COMMON[@]}" -o "$B/vuln-scan.bundle.json" \
  -- trivy sbom supply-chain/sbom/hugo.cdx.json --skip-db-update \
       --format sarif -o supply-chain/scans/trivy.sarif \
  || die "vuln-scan step failed"
grn "  -> supply-chain/scans/trivy.sarif + $B/vuln-scan.bundle.json"

# ============================================================================
hdr "5/7 validate — offline binary integrity  (SSDF PW.8)"
$CILOCK run -s validate -a environment --no-default-attestor material \
  "${COMMON[@]}" -o "$B/validate.bundle.json" \
  -- bash supply-chain/tools/validate_binary.sh "$BIN" "$VERSION" || die "validate failed"
grn "  -> $B/validate.bundle.json"

# ============================================================================
hdr "6/7 policy — generate + sign the release gate  (SSDF PS.2 / PS.3)"
$CILOCK policy from-bundles -k "$PUB" --expires 720h \
  -o "$P/release.policy.json" \
  "$B/source.bundle.json" "$B/build.bundle.json" "$B/sbom.bundle.json" \
  "$B/vuln-scan.bundle.json" "$B/validate.bundle.json" || die "from-bundles (full) failed"
$CILOCK sign -k "$KEY" -f "$P/release.policy.json" -o "$P/release.policy.signed.json" \
  || die "sign (full) failed"

$CILOCK policy from-bundles -k "$PUB" --expires 720h \
  -o "$P/build-gate.policy.json" "$B/build.bundle.json" || die "from-bundles (gate) failed"
$CILOCK sign -k "$KEY" -f "$P/build-gate.policy.json" -o "$P/build-gate.policy.signed.json" \
  || die "sign (gate) failed"

$CILOCK policy validate -p "$P/release.policy.signed.json" -k "$PUB" \
  || die "release policy failed schema/signature validation"
$CILOCK policy validate -p "$P/build-gate.policy.signed.json" -k "$PUB" \
  || die "build-gate policy failed schema/signature validation"
grn "  -> signed: release.policy.signed.json + build-gate.policy.signed.json"

# ============================================================================
hdr "7/7 verify — gate the binary, then prove fail-closed"
echo "[verify] honest artifact against the signed gate (expect PASS):"
if $CILOCK verify "$BIN" -p "$P/build-gate.policy.signed.json" -k "$PUB" \
     -a "$B/build.bundle.json" "$PLAT" "$URL"; then
  grn "  PASS: hugo binary satisfies the signed policy"
  VPASS=0
else
  red "  UNEXPECTED FAIL on the honest binary"; VPASS=1
fi

echo
echo "[tamper] mutate a copy of the binary, re-verify (expect FAIL / non-zero exit):"
cp "$BIN" /tmp/tampered-hugo
printf 'TAMPER' >> /tmp/tampered-hugo          # append bytes => guaranteed-different digest
cmp -s "$BIN" /tmp/tampered-hugo && die "tamper mutation was a no-op (test bug, not a gate result)"
if $CILOCK verify /tmp/tampered-hugo -p "$P/build-gate.policy.signed.json" -k "$PUB" \
     -a "$B/build.bundle.json" "$PLAT" "$URL" >/dev/null 2>&1; then
  red "  SECURITY BUG: tampered binary PASSED — gate is not fail-closed"; TPASS=1
else
  grn "  GOOD: tampered binary REJECTED (digest not in attested subjects)"; TPASS=0
fi
rm -f /tmp/tampered-hugo

hdr "summary"
echo "  honest-binary verify : $([ "${VPASS:-1}" = 0 ] && echo PASS || echo FAIL)"
echo "  tamper rejected      : $([ "${TPASS:-1}" = 0 ] && echo YES  || echo NO)"
echo "  bundles              : $(ls "$B"/*.bundle.json 2>/dev/null | wc -l | tr -d ' ') signed stages"
echo "  sbom components      : $(python3 -c "import json;print(len(json.load(open('supply-chain/sbom/hugo.cdx.json')).get('components',[])))" 2>/dev/null)"
[ "${VPASS:-1}" = 0 ] && [ "${TPASS:-1}" = 0 ] && grn "PIPELINE OK" || { red "PIPELINE FAILED"; exit 1; }
