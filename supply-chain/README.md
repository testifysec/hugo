# supply-chain/ — cilock-secured release for the internal Hugo fork

Proof-of-pipeline: builds `hugo` and gates the binary with **cilock**
attestations + a **signed Witness policy**, fully offline with a local key.

## Run it

```bash
bash supply-chain/secure-release.sh
```

Stages (each wrapped in `cilock run`/`attest`, each producing a signed bundle):

```
source → build → sbom → vuln-scan → validate → policy(sign) → verify(+tamper)
```

Expected tail:

```
honest-binary verify : PASS
tamper rejected      : YES
bundles              : 5 signed stages
sbom components      : 110
PIPELINE OK
```

## Layout

```
supply-chain/
├── secure-release.sh           # the orchestrator
├── SSDF-SLSA-MAPPING.md         # NIST SP 800-218 + SLSA v1.0 mapping (read this)
├── keys/   release.key/.pub     # local ECDSA P-256 signer (PROOF ONLY — not prod trust)
├── bundles/ *.bundle.json       # one signed DSSE/in-toto attestation per stage
├── policy/  *.signed.json       # signed Witness policies (release + build-gate)
├── sbom/    hugo.cdx.json        # CycloneDX SBOM (syft, from the binary's Go buildinfo)
├── scans/   trivy.sarif          # trivy CVE findings (SARIF)
└── tools/   validate_binary.sh   # offline binary integrity check
```

## Verify a release as a consumer (offline)

```bash
cilock verify dist/hugo \
  --policy        supply-chain/policy/build-gate.policy.signed.json \
  --publickey     supply-chain/keys/release.pub \
  --attestations  supply-chain/bundles/build.bundle.json \
  --platform-url ""           # exit 0 = trusted; non-zero = reject
```

## Notes / caveats

- **Local key, offline = SLSA Build L1** (+ the signing/provenance *content* of
  L2). Production L2/L3 = run the same steps on isolated CI with keyless OIDC.
  See `SSDF-SLSA-MAPPING.md §4`.
- `supply-chain/{bundles,policy,sbom,scans}` and `dist/` are added to
  `.git/info/exclude` so the `git` attestor records the **clean upstream commit**
  (`bba860e3…`, tag `v0.162.1`). In a real internal fork you'd commit this
  tooling and re-pin the source provenance.
- This is a **local fork** — nothing was pushed to GitHub.
