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
      - uses: tinfoilsh/measure-image-action@ca4cfa35773897455c9e51409d61c75b8e377c27  # v0.10.2
        with:
          config-file: ${{ github.workspace }}/tinfoil-config.yml
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

After publishing the release, the action uses the workflow's GitHub OIDC
identity to request an immediate freshness-witness refresh. The notification
is an acceleration only: failures are reported as warnings because the
controlplane's scheduled refresh remains authoritative. Calling workflows
should retain `id-token: write`, which is already required for attestation
signing. Alternate deployments can override both `freshness-report-url` and
the matching `freshness-report-audience`.

## Releasing a New Version

Push a `build-v*` tag to trigger the automated pipeline:

```bash
git tag build-v0.0.13
git push origin build-v0.0.13
```
