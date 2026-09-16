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

## AMD firmware and deployment compatibility

The builder measures AMD SEV-SNP with `tinfoilsh/edk2` **v0.0.4**. It verifies
the firmware's GitHub attestation against that repository using the
`https://tinfoil.sh/predicate/component-artifact/v1` predicate, rejects
attestations from self-hosted runners, and checks downloaded or cached
`OVMF.fd` against the pinned SHA-256 before measurement. Artifact caches are
scoped by the complete download URL, so different releases named `OVMF.fd`
cannot reuse each other's cache entry.

The signed `tinfoil-deployment.json` now includes:

```json
{
  "firmware": {
    "sev_snp": {
      "type": "ovmf",
      "version": "v0.0.4",
      "sha256": "78c890175928167a1bc095d4bf3bb4ad81de80cd7e4e9e683477fc359119c1c4"
    }
  }
}
```

`sha256` is lowercase hexadecimal, without a `sha256:` prefix, calculated from
the verified OVMF file passed to `sev-snp-measure`. This metadata is covered by
the same deployment digest and Sigstore attestation as the measurements.
`type` identifies the guest firmware implementation; this action emits only
`ovmf`. The existing SNP/TDX measurement field names and workload YAML are
unchanged; the SNP measurement changes with the firmware.
Missing firmware, failed attestation, and digest mismatches stop the build;
there is no fallback to another firmware release.

Roll out in this order:

1. Upgrade all AMD `tinfoild` hosts to support explicit firmware metadata before
   deploying these manifests. Older daemons continue using their global OVMF
   file and cannot launch the newly measured v0.0.4 deployments correctly.
   Retain the existing global OVMF file: new daemons still use that configured
   file for legacy manifests without `firmware` metadata, including custom
   legacy firmware paths.
2. Qualify v0.0.4 on AMD hardware against the predicted launch measurement,
   attestation verification, certificate issuance, secret release and normal
   application traffic. A successful download and unit tests do not establish
   hardware compatibility.
3. Release a container containing this builder and update the action's immutable
   container digest through the release workflow below. Source changes alone
   do not update the image invoked by `action.yaml`; its existing image digest
   remains a release prerequisite for this change.
4. Update workload workflow pins, create new measured and attested releases,
   publish their freshness endorsements, and deploy those releases. App images,
   model packs and CVM artifacts can be reused when their contents are unchanged.

## Releasing a New Version

After qualification, pushing a `build-v*` tag starts the publishing pipeline:

```bash
git tag build-v0.0.13
git push origin build-v0.0.13
```

That workflow publishes and attests the container, creates and merges an
`action.yaml` digest-update PR, then dispatches the release workflow. The release
workflow checks that digest before publishing the action tag. Choose an unused
version; the commands above are only an example. A source-only PR neither
publishes the container nor switches existing action users to it.
