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
      - uses: tinfoilsh/measure-image-action@4498a00d0887fc8979de4a7eadc73590a12ebb12  # v0.12.1
        with:
          config-file: ${{ github.workspace }}/tinfoil-config.yml
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

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
each top-level model and volume.

For v0.11.0 and newer, `cvm-source` in the config selects the repository whose
release carries the image manifest and the base URL serving its kernel and
initrd. Without it, and for older images, the action uses `tinfoilsh/cvmimage`
and `https://images.tinfoil.sh/cvm`.

## Releasing a New Version

Push a `build-v*` tag to trigger the automated pipeline:

```bash
git tag build-v0.0.13
git push origin build-v0.0.13
```
