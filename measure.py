import base64
import json
import subprocess
from pathlib import Path
from typing import Optional, Tuple

import yaml

from measure_amd import measure_amd
from measure_intel import measure_intel
from util import fetch, sha256sum


def verify_attestation_gh(file_path: str, repo: str) -> None:
    """Verify attestation using GitHub CLI, ensuring it was built on GitHub-hosted runners."""
    result = subprocess.run(
        [
            "gh",
            "attestation",
            "verify",
            file_path,
            "-R",
            repo,
            "--deny-self-hosted-runners",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Attestation verification failed for {file_path}: {result.stderr}"
        )


CACHE_DIR = "/cache"


def fetch_verified_artifact(url: str, repo: str) -> str:
    file_path = fetch(url, CACHE_DIR)
    verify_attestation_gh(file_path, repo)
    artifact_name = Path(file_path).name
    print(f"Attestation verified for {artifact_name} from {repo}")
    return file_path


def parse_pinned_name(value: str) -> Tuple[str, Optional[str]]:
    """Parse a ``NAME`` or ``NAME@sha256:HEX`` reference.

    Returns ``(name, digest)`` where ``digest`` is the lowercase hex SHA-256
    (without the ``sha256:`` prefix) when one is present, else ``None``.

    Used to parse the ``cvm-version`` and ``ovmf-version`` YAML config
    fields, both of which mirror the OCI image digest-pinning convention
    so a single string carries the human-readable version and an optional
    integrity pin.
    """
    if "@" not in value:
        return value, None
    name, digest = value.split("@", 1)
    if not digest.startswith("sha256:"):
        raise ValueError(
            f"unsupported digest algorithm in pinned reference: {value!r} "
            f"(expected '<name>@sha256:<hex>')"
        )
    hex_digest = digest[len("sha256:") :]
    if len(hex_digest) != 64 or not all(c in "0123456789abcdef" for c in hex_digest):
        raise ValueError(
            f"malformed sha256 digest in pinned reference: {value!r} "
            f"(expected 64 lowercase hex chars)"
        )
    return name, hex_digest


def verify_digest(file_path: str, expected_hex: str, label: str) -> None:
    """Hash ``file_path`` and raise if it does not match ``expected_hex``."""
    actual = sha256sum(file_path)
    if actual != expected_hex:
        raise ValueError(
            f"{label} digest mismatch: expected sha256:{expected_hex}, "
            f"got sha256:{actual}"
        )


config = yaml.safe_load(open("/config.yml", "r"))

CVM_VERSION, CVM_MANIFEST_DIGEST = parse_pinned_name(str(config["cvm-version"]))
CPUS = config["cpus"]
MEMORY = config["memory"]

CVMIMAGE_REPO = "tinfoilsh/cvmimage"

manifest_url = f"https://github.com/{CVMIMAGE_REPO}/releases/download/v{CVM_VERSION}/tinfoil-inference-v{CVM_VERSION}-manifest.json"
manifest_file = fetch_verified_artifact(manifest_url, CVMIMAGE_REPO)

if CVM_MANIFEST_DIGEST is not None:
    verify_digest(manifest_file, CVM_MANIFEST_DIGEST, "cvm manifest")
    print(f"Manifest digest matches pin: sha256:{CVM_MANIFEST_DIGEST}")

manifest = json.loads(open(manifest_file, "r").read())

kernel_file = fetch(
    f"https://images.tinfoil.sh/cvm/tinfoil-inference-v{CVM_VERSION}.vmlinuz", CACHE_DIR
)
initrd_file = fetch(
    f"https://images.tinfoil.sh/cvm/tinfoil-inference-v{CVM_VERSION}.initrd", CACHE_DIR
)

verify_digest(kernel_file, manifest["kernel"], "kernel")
verify_digest(initrd_file, manifest["initrd"], "initrd")

EDK2_REPO = "tinfoilsh/edk2"
DEFAULT_EDK2_VERSION = "v0.0.3"

ovmf_version_raw = config.get("ovmf-version")
if ovmf_version_raw is not None:
    print("::warning::The `ovmf-version` field is not currently supported by Tinfoil infrastructure and may cause an attestation error during deployment.")
    EDK2_VERSION, OVMF_DIGEST = parse_pinned_name(str(ovmf_version_raw))
else:
    EDK2_VERSION = DEFAULT_EDK2_VERSION
    OVMF_DIGEST = None

amd_ovmf = fetch(
    f"https://github.com/{EDK2_REPO}/releases/download/{EDK2_VERSION}/OVMF.fd",
    CACHE_DIR,
)
if OVMF_DIGEST is not None:
    verify_digest(amd_ovmf, OVMF_DIGEST, "ovmf")
    print(f"OVMF digest matches pin: sha256:{OVMF_DIGEST}")

cmdline = f"readonly=on pci=realloc,nocrs modprobe.blacklist=nouveau nouveau.modeset=0 root=/dev/mapper/root roothash={manifest['root']} tinfoil-config-hash={sha256sum('/config.yml')}"

print("Measuring...")

snp_measurement = measure_amd(CPUS, amd_ovmf, kernel_file, initrd_file, cmdline)
tdx_measurement = measure_intel(CPUS, MEMORY, kernel_file, initrd_file, cmdline)

deployment_cfg = {
    "snp_measurement": snp_measurement,
    "tdx_measurement": tdx_measurement,
    "cmdline": cmdline,
    "hashes": manifest,
    "config": base64.b64encode(open("/config.yml", "rb").read()).decode("utf-8"),
}

print(deployment_cfg)

md = f"""SEV-SNP Measurement: `{deployment_cfg["snp_measurement"]}`
TDX Measurement: `{deployment_cfg["tdx_measurement"]}`
Inference Image Version: [`{CVM_VERSION}`](https://github.com/tinfoilsh/cvmimage/releases/tag/v{CVM_VERSION})
"""

with open("/output/release.md", "w") as f:
    f.write(md)

with open("/output/tinfoil-deployment.json", "w") as f:
    f.write(json.dumps(deployment_cfg, indent=4))
