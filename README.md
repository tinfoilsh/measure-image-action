# Tinfoil Private Inference Builder

## GitHub Actions Example

```yaml
name: Build and Attest

on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      packages: write
      id-token: write
      attestations: write

    steps:
      - uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8  # v6.0.1
      - uses: tinfoilsh/measure-image-action@768ada355b32b301839c983409304dc53bcc03ff  # v0.13.1
        with:
          config-file: ${{ github.workspace }}/tinfoil-config.yml
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

For a private repository, also install the Tinfoil freshness wrapper as
`.github/workflows/tinfoil-freshness.yml`. It is dispatched by the Tinfoil
GitHub App and calls the reusable workflow in
`tinfoilsh/freshness-witness/.github/workflows/private.yml@main`. The build and
freshness attestations stay in this repository's private GitHub attestation
store; no GitHub token is sent to an enclave or verifier.

## Measurement architecture

The container uses a small Go binary for config validation, artifact download
and verification, measurement-tool invocation, and output generation. The
measurement implementations remain independently pinned external tools:
`sev-snp-measure` for AMD SEV-SNP and `tdx-measure` for Intel TDX. This keeps
the measurement boundary and output format stable while making the action's
orchestration easier to inspect and test.

The shared strict workload validator applies to CVM image v0.11.0 and newer,
matching tinfoild's launch contract. Older CVM images retain their legacy YAML
surface and are parsed only for the fields required to reproduce measurement.
The emitted `vm_shape.disks` includes the three runtime disks plus one disk for
each top-level model and volume. The signed deployment carries the config bytes
verbatim, so `attested-keys` declarations, container `keys` grants and the
direct admin SSH opt-in (`cvm_admin` with `22:22` and `cvm-network.inbound-ports`
`[22]`) are measured exactly as written; they require CVM image v0.14.10 or
newer and are rejected on older images.

For v0.11.0 and newer, `cvm-source` in the config selects the repository whose
release carries the image manifest and the base URL serving its kernel and
initrd. Without it, and for older images, the action uses `tinfoilsh/cvmimage`
and `https://images.tinfoil.sh/cvm`.

## AMD firmware

The signed deployment records AMD OVMF's `type`, `version`, and `sha256`
under `firmware.sev_snp` (currently EDK2 v0.0.4). Upgrade `tinfoild` before
deploying these releases. TDX firmware selection is unchanged.

## Releasing a New Version

Push a `build-v*` tag to trigger the automated pipeline:

```bash
git tag build-v0.0.13
git push origin build-v0.0.13
```
