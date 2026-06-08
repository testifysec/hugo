# Secured Release — SSDF & SLSA Mapping (internal Hugo fork)

This fork's release is built and gated by **cilock** (`3.0.0`). Every stage runs
inside `cilock run`/`cilock attest`, producing a signed DSSE / in-toto
attestation; a **signed Witness policy** then gates the artifact via
`cilock verify` (fail-closed). This document maps that machinery to **NIST
SP 800-218 (SSDF v1.1)** and **SLSA v1.0**, and is explicit about what the
*local* configuration earns vs. what requires the hosted/CI path.

> **Trust model (current):** offline, single ECDSA P-256 **file key**
> (`supply-chain/keys/release.key`, keyid `ca23ffbd…6c4a`), `--platform-url ""`.
> This is a **proof of the pipeline + verification**, not the production trust
> root. Production hardening (keyless OIDC, isolated builder, transparency log)
> is called out in **§4 Gaps & path to production**. Per the Linus rule: this
> earns SLSA **Build L1 + the cryptographic *content* of L2**, not L2/L3.

---

## 1. The evidence (what each stage signs)

| # | Stage (`--step`) | cilock invocation | Attestor predicates emitted | Bundle |
|---|---|---|---|---|
| 1 | `source` | `cilock attest` | `git/v0.1`, `environment/v0.1`, `material/v0.3`, `product/v0.3`, `command-run/v0.2` | `bundles/source.bundle.json` |
| 2 | `build` | `cilock run -- go build -trimpath -o dist/hugo .` | `git`, `environment`, `lockfiles/v0.1` (`go.sum`), **`go-build/v0.1`**, **`slsa.dev/provenance/v1.0`**, `secretscan/v0.1`, `material/v0.3`, `product/v0.3`, `command-run` | `bundles/build.bundle.json` |
| 3 | `sbom` | `cilock run -- syft scan file:dist/hugo` | `sbom/v0.1` (CycloneDX 1.6, 110 components), `environment`, `product`, `command-run` | `bundles/sbom.bundle.json` |
| 4 | `vuln-scan` | `cilock run -- trivy sbom …` | `sarif/v0.1` (trivy CVE findings), `environment`, `product`, `command-run` | `bundles/vuln-scan.bundle.json` |
| 5 | `validate` | `cilock run -- validate_binary.sh` | `environment`, `product`, `command-run` (binary digest + embedded Go buildinfo / module-pin check) | `bundles/validate.bundle.json` |
| 6 | `policy` | `policy from-bundles` → `sign` → `policy validate` | Witness policy (signed DSSE) | `policy/*.signed.json` |
| 7 | `verify` | `cilock verify dist/hugo` | `policyverify` → `slsa.dev/verification_summary/v1` (VSA) | — |

The artifact under management: **`dist/hugo`**
(sha256 `4747f175…dde3f59`, `hugo v0.162.1`), built from pinned source commit
`bba860e3eda3091efe8c6d1a96bc49a29ad2d5f6` (tag `v0.162.1`).

---

## 2. SLSA v1.0 assessment

### Build track

| Requirement | Status | Evidence / note |
|---|---|---|
| **L1** — provenance exists, build is scripted/automatable | ✅ **Met** | `go build` wrapped by cilock; `slsa.dev/provenance/v1` + `go-build/v0.1` + full in-toto collection emitted and signed |
| Provenance is **complete** (builder, buildType, inputs, command, outputs) | ✅ | `slsa` carries the command + `resolvedDependencies`; `go-build` records the Go toolchain & module graph; `lockfiles` pins `go.sum`; output pinned as `go-build/v0.1/binary:dist/hugo` |
| Provenance is **signed** (authenticity, tamper-evident) | ✅ | DSSE-signed, verified at `verify` time (signature failure ⇒ reject) |
| **L2** — provenance from a **hosted build platform**; provenance unforgeable *after* the build | ⚠️ **Partial** | Signing requirement met; **builder is a developer workstation, not a hosted/managed platform** |
| **L3** — **hardened, isolated** builder; signing material inaccessible to build steps | ❌ **Not met** | Local key lives on the same host as the build → forgeable. Requires keyless OIDC on an isolated runner (see §4) |

**Honest verdict:** **Build L1**, with the full provenance *content* and *signing*
that L2 also requires — but not L2's hosted-builder or L3's isolation. The local
recipe is the exact mechanism; flipping it to L3 is a deployment change (run the
same steps on isolated CI with keyless signing), not a rewrite.

### Source track

| Requirement | Status | Note |
|---|---|---|
| **L1** — version control | ✅ | `git` attestor pins commit `bba860e3…`, tree, author, refs, remote `github.com/gohugoio/hugo` |
| **L2** — retained history + verified change provenance | ⚠️ Partial | Commit pinned; branch protection / retention not attested locally |
| **L3** — trusted source control + 2-person review | ❌ | Add `github-review` attestor + enforced branch protection in CI |

### Artifact binding (the part most pipelines get wrong)

`cilock verify dist/hugo` seeds policy evaluation with the **binary's own digest**
and requires a verified collection whose **subjects include that digest**.
Confirmed fail-closed: the honest binary verifies (exit 0, digest matches
`go-build/v0.1/binary:dist/hugo`); a binary with one appended byte is rejected
(exit 1) with *"supplied artifact digest(s) … not present in any subject of step
'build' collection."* The negative test asserts the mutation actually changed the
digest before trusting the reject, so a no-op tamper can't print a false pass.

---

## 3. SSDF (NIST SP 800-218 v1.1) practice mapping

PO = Prepare Org · PS = Protect Software · PW = Produce Well-secured · RV = Respond to Vulns.

| SSDF task | How this pipeline addresses it | Stage / artifact |
|---|---|---|
| **PO.3** Implement supporting toolchains | cilock pins the toolchain & build env into signed attestations | `environment`, `build` |
| **PO.4** Define criteria for security checks | The signed Witness policy *is* the machine-checkable release criteria | `policy/*.signed.json` |
| **PO.5** Secure build environments | `environment` attestor snapshots the build host/env per stage | all stages |
| **PS.1** Protect code from unauthorized access/tampering | `git` pins exact source commit + tree hash | `source`, `build` |
| **PS.2** **Verify software release integrity** | DSSE signing + `cilock verify` against signed policy (fail-closed) | `build`, `verify` |
| **PS.3** Archive & protect each release | Per-stage signed bundles + signed policy retained under `supply-chain/` (portable via `cilock bundle`) | `bundles/`, `policy/` |
| **PW.4** Reuse well-secured software (know your deps) | CycloneDX SBOM from the binary's embedded Go buildinfo (110 components); `lockfiles` pins `go.sum` | `sbom`, `build` |
| **PW.6** Configure build to improve security | Build provenance: exact command (`go build -trimpath`), `go-build` toolchain record, pinned module graph | `build` (`slsa`, `go-build`) |
| **PW.7** Review/analyze human-readable code | `secretscan` over products (no committed secrets); SAST hook point | `build` (`secretscan`) |
| **PW.8** Test executable code | `validate_binary.sh` recomputes the binary digest and confirms embedded Go module buildinfo is present | `validate` |
| **PW.9** Secure default settings | Release gate denies-by-default (unsigned/unknown artifact ⇒ no verify) | `verify` |
| **RV.1** Identify vulnerabilities on an ongoing basis | `trivy` CVE scan over the SBOM → SARIF, attested | `vuln-scan` |
| **RV.2** Assess/prioritize/remediate | SARIF findings carry severity; gating threshold is a policy decision (see §4) | `vuln-scan` + policy |
| **RV.3** Root-cause analysis | SBOM + provenance give the component→source trail per finding | `sbom` + `build` |

### SSDF tasks **not** covered here (require process/people, not just cilock)

- **PO.1 / PO.2** — security requirements & org roles (governance, not pipeline).
- **PW.1 / PW.2** — secure design & design review (pre-code).
- **PW.5** — secure-coding standards / linters (add as an attested `lint`/SAST stage, e.g. `golangci-lint`).
- **RV.2 remediation workflow** — ticketing/SLA outside the build.

---

## 4. Gaps & path to production

| Gap (current local setup) | Production fix |
|---|---|
| Single **local file key** on the build host (forgeable, no rotation) | **Keyless OIDC**: `cilock login --workflow-identity` + ambient CI token → platform Fulcio; key never at rest |
| Dev workstation builder (no isolation) ⇒ SLSA L1 not L2/L3 | Run `secure-release.sh` on an **isolated CI runner** (GitHub Actions w/ `id-token: write`, or `aflock-ai/cilock-action`); the `github`/`github-action` attestors then enrich provenance |
| No transparency log / RFC3161 timestamp (`--platform-url ""`) | Point `--platform-url` at the platform → **TSA timestamps + Archivista** storage (PS.3 at scale) |
| Source track L1 only | Add `github-review` attestor + enforced branch protection ⇒ Source L3 |
| Vuln scan is **non-gating** | Set a severity threshold in the policy (rego) and/or `trivy --exit-code 1 --severity CRITICAL`, or swap in the `govulncheck` attestor for Go-native gating |
| Cross-step provenance not enforced in the gate | The gate verifies the self-contained `build` step; wire `source→build→validate` with `cilock prove-chain` inclusion proofs + `attestationsFrom`/`artifactsFrom` policy edges |
| Extended build (`-tags extended`, libsass/webp via CGO) not covered | The L1 recipe builds the pure-Go hugo; an extended release adds CGO toolchain provenance to the `build` stage |

---

## 5. How a consumer verifies the release (offline)

```bash
cilock verify dist/hugo \
  --policy   supply-chain/policy/build-gate.policy.signed.json \
  --publickey supply-chain/keys/release.pub \
  --attestations supply-chain/bundles/build.bundle.json \
  --platform-url ""        # exit 0 = trusted; non-zero = reject
```

Reproduce the whole chain end-to-end: `bash supply-chain/secure-release.sh`.
