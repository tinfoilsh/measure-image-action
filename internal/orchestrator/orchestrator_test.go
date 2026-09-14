package orchestrator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	tinfoilconfig "github.com/tinfoilsh/tinfoil-config"
)

func TestParsePinnedName(t *testing.T) {
	digest := strings.Repeat("a", 64)
	tests := []struct {
		name       string
		value      string
		wantName   string
		wantDigest string
		wantError  string
	}{
		{name: "unpinned", value: "0.11.0", wantName: "0.11.0"},
		{name: "pinned", value: "0.11.0@sha256:" + digest, wantName: "0.11.0", wantDigest: digest},
		{name: "empty", value: "", wantError: "name is empty"},
		{name: "empty pinned name", value: "@sha256:" + digest, wantError: "name is empty"},
		{name: "wrong algorithm", value: "0.11.0@sha512:" + digest, wantError: "unsupported digest algorithm"},
		{name: "short digest", value: "0.11.0@sha256:abcd", wantError: "malformed sha256 digest"},
		{name: "uppercase digest", value: "0.11.0@sha256:" + strings.Repeat("A", 64), wantError: "malformed sha256 digest"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name, gotDigest, err := parsePinnedName(test.value)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want substring %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if name != test.wantName || gotDigest != test.wantDigest {
				t.Fatalf("parsePinnedName(%q) = (%q, %q), want (%q, %q)", test.value, name, gotDigest, test.wantName, test.wantDigest)
			}
		})
	}
}

func TestVersionAtLeastChecked(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		want      bool
		wantError bool
	}{
		{name: "legacy", version: "0.10.9"},
		{name: "boundary", version: "0.11.0", want: true},
		{name: "prerelease contains new guest code", version: "0.11.0-rc.1", want: true},
		{name: "digest pin", version: "0.11.0@sha256:" + strings.Repeat("a", 64), want: true},
		{name: "v prefix and build suffix", version: "v0.12.0+local", want: true},
		{name: "malformed", version: "local-build", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := versionAtLeastChecked(test.version, minCVMVersionStrictConfig)
			if test.wantError {
				if err == nil {
					t.Fatal("versionAtLeastChecked() accepted malformed version")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("versionAtLeastChecked(%q) = %t, want %t", test.version, got, test.want)
			}
		})
	}
}

func TestDecodeMeasurementConfigUsesCVMVersionBoundary(t *testing.T) {
	legacy := []byte(`cvm-version: 0.10.9
cpus: 8
memory: 16384
gpus: 1
shim-version: 0.3.4
models:
  - name: model
    legacy-field: accepted-by-the-guest
containers:
  - name: app
    image: example.com/app:latest
    models: [model]
`)
	config, err := decodeMeasurementConfig(legacy)
	if err != nil {
		t.Fatalf("legacy config rejected: %v", err)
	}
	wantLegacy := &measurementConfig{CVMVersion: "0.10.9", CPUs: 8, Memory: 16384, GPUs: 1, ModelCount: 1}
	if !reflect.DeepEqual(config, wantLegacy) {
		t.Fatalf("legacy config = %#v, want %#v", config, wantLegacy)
	}

	strictMutable := []byte(`cvm-version: 0.11.0
cpus: 8
memory: 16384
shim:
  upstream-port: 8080
containers:
  - name: app
    image: example.com/app:latest
`)
	if _, err := decodeMeasurementConfig(strictMutable); err == nil || !strings.Contains(err.Error(), "immutable digest") {
		t.Fatalf("strict mutable-image error = %v, want immutable-digest rejection", err)
	}

	strictValid := bytes.Replace(strictMutable, []byte("example.com/app:latest"), []byte("example.com/app@sha256:"+strings.Repeat("a", 64)), 1)
	config, err = decodeMeasurementConfig(strictValid)
	if err != nil {
		t.Fatalf("strict config rejected: %v", err)
	}
	wantStrict := &measurementConfig{CVMVersion: "0.11.0", CPUs: 8, Memory: 16384}
	if !reflect.DeepEqual(config, wantStrict) {
		t.Fatalf("strict config = %#v, want %#v", config, wantStrict)
	}
}

func TestDecodeMeasurementConfigRejectsMalformedVersionAndMultipleDocuments(t *testing.T) {
	if _, err := decodeMeasurementConfig([]byte("cvm-version: local-build\n")); err == nil || !strings.Contains(err.Error(), "invalid CVM version") {
		t.Fatalf("malformed-version error = %v", err)
	}
	legacyDocuments := []byte("cvm-version: 0.10.9\ncpus: 2\nmemory: 4096\n---\nextra: document\n")
	if _, err := decodeMeasurementConfig(legacyDocuments); err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("multiple-document error = %v", err)
	}
}

func TestDecodeMeasurementConfigRejectsInvalidMeasurementFields(t *testing.T) {
	base := `cvm-version: 0.10.9
cpus: 2
memory: 4096
`
	tests := []struct {
		name      string
		config    string
		wantError string
	}{
		{name: "missing cpus", config: "cvm-version: 0.10.9\nmemory: 4096\n", wantError: "cpus must be positive"},
		{name: "zero memory", config: strings.Replace(base, "memory: 4096", "memory: 0", 1), wantError: "memory must be positive"},
		{name: "negative GPUs", config: base + "gpus: -1\n", wantError: "gpus must be between 0 and 8"},
		{name: "too many GPUs", config: base + "gpus: 9\n", wantError: "gpus must be between 0 and 8"},
		{name: "too many model disks", config: base + "models:\n" + strings.Repeat("  - {}\n", tinfoilconfig.MaxModelDisks+1), wantError: "models must contain at most"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeMeasurementConfig([]byte(test.config)); err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("decodeMeasurementConfig() error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestRunPreservesMeasurementContract(t *testing.T) {
	temporaryDir := t.TempDir()
	cacheDir := filepath.Join(temporaryDir, "cache")
	outputDir := filepath.Join(temporaryDir, "output")
	configPath := filepath.Join(temporaryDir, "config.yml")
	ghArgumentsPath := filepath.Join(temporaryDir, "gh-args")
	snpArgumentsPath := filepath.Join(temporaryDir, "snp-args")
	tdxArgumentsPath := filepath.Join(temporaryDir, "tdx-args")
	tdxMetadataPath := filepath.Join(temporaryDir, "tdx-metadata")
	bootShimArgumentsPath := filepath.Join(temporaryDir, "boot-shim-args")

	kernel := []byte("kernel fixture")
	initrd := []byte("initrd fixture")
	manifestBytes := []byte(fmt.Sprintf(`{"version":"0.11.0","root":"root-hash","initrd":"%x","kernel":"%x","raw":"raw-hash"}`, sha256.Sum256(initrd), sha256.Sum256(kernel)))
	manifestDigest := sha256.Sum256(manifestBytes)
	configBytes := []byte(fmt.Sprintf(`cvm-version: 0.11.0@sha256:%x
cpus: 2
memory: 4096
gpus: 1
shim:
  upstream-port: 8080
containers:
  - name: app
    image: example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    runtime: nvidia
    gpus: all
`, manifestDigest))
	if err := os.WriteFile(configPath, configBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/cvm/v0.11.0/tinfoil-inference-v0.11.0-manifest.json":
			_, _ = writer.Write(manifestBytes)
		case "/images/tinfoil-inference-v0.11.0.vmlinuz":
			_, _ = writer.Write(kernel)
		case "/images/tinfoil-inference-v0.11.0.initrd":
			_, _ = writer.Write(initrd)
		case "/edk2/v0.0.3/OVMF.fd":
			_, _ = writer.Write([]byte("ovmf fixture"))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	ghPath := writeExecutable(t, temporaryDir, "gh", `#!/bin/sh
printf '%s\n' "$@" > "$GH_ARGUMENTS_PATH"
`)
	snpPath := writeExecutable(t, temporaryDir, "sev-snp-measure", `#!/bin/sh
printf '%s\n' "$@" > "$SNP_ARGUMENTS_PATH"
printf '%s\n' 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
`)
	tdxPath := writeExecutable(t, temporaryDir, "tdx-measure", `#!/bin/sh
printf '%s\n' "$@" > "$TDX_ARGUMENTS_PATH"
cp "$1" "$TDX_METADATA_PATH"
while [ "$#" -gt 0 ]; do
    if [ "$1" = "--json-file" ]; then
        shift
        printf '%s' '{"rtmr1":"1111","rtmr2":"2222"}' > "$1"
        exit 0
    fi
    shift
done
exit 1
`)
	// Echoes back the command line it was handed with the builder's own token
	// appended, as the real one does, so the checks on it are exercised.
	bootShimPath := writeExecutable(t, temporaryDir, "boot-shim", `#!/bin/sh
printf '%s\n' "$@" >> "$BOOT_SHIM_ARGUMENTS_PATH"
subcommand="$1"
given=""
prev=""
for a in "$@"; do
    if [ "$prev" = "--cmdline" ]; then given="$a"; fi
    prev="$a"
done
while [ "$#" -gt 0 ]; do
    if [ "$1" = "--output" ]; then
        shift
        : > "$1"
        if [ "$subcommand" = "build-snp" ]; then
            printf '{"format_version":2,"platform":"sev-snp","command_line":"%s no5lvl","launch":{"measurement":"bbbb","policy":"0x30133"}}' "$given" > "$1.manifest.json"
        else
            printf '{"format_version":2,"platform":"tdx","command_line":"%s no5lvl","launch":{"mrtd":"cccc","rtmr0":"00"}}' "$given" > "$1.manifest.json"
        fi
        exit 0
    fi
    shift
done
exit 1
`)
	t.Setenv("BOOT_SHIM_ARGUMENTS_PATH", bootShimArgumentsPath)
	t.Setenv("GH_ARGUMENTS_PATH", ghArgumentsPath)
	t.Setenv("SNP_ARGUMENTS_PATH", snpArgumentsPath)
	t.Setenv("TDX_ARGUMENTS_PATH", tdxArgumentsPath)
	t.Setenv("TDX_METADATA_PATH", tdxMetadataPath)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	runner := &Runner{
		ConfigPath:           configPath,
		CacheDir:             cacheDir,
		OutputDir:            outputDir,
		GHPath:               ghPath,
		SNPMeasurePath:       snpPath,
		TDXMeasurePath:       tdxPath,
		BootShimPath:         bootShimPath,
		CVMImageReleaseBase:  server.URL + "/cvm",
		CVMImageArtifactBase: server.URL + "/images",
		EDK2ReleaseBase:      server.URL + "/edk2",
		HTTPClient:           server.Client(),
		Stdout:               &stdout,
		Stderr:               &stderr,
	}
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error: %v\nstderr: %s", err, stderr.String())
	}

	assertLines(t, ghArgumentsPath, []string{
		"attestation", "verify", filepath.Join(cacheDir, "tinfoil-inference-v0.11.0-manifest.json"),
		"-R", "tinfoilsh/cvmimage", "--deny-self-hosted-runners",
	})
	cmdline := fmt.Sprintf("readonly=on pci=realloc,nocrs modprobe.blacklist=nouveau nouveau.modeset=0 root=/dev/mapper/root roothash=root-hash tinfoil-config-hash=%x", sha256.Sum256(configBytes))
	assertLines(t, snpArgumentsPath, []string{
		"--mode", "snp",
		"--vcpus", "2",
		"--vcpu-type", "EPYC-v4",
		"--vmm-type", "QEMU",
		"--ovmf", filepath.Join(cacheDir, "OVMF.fd"),
		"--kernel", filepath.Join(cacheDir, "tinfoil-inference-v0.11.0.vmlinuz"),
		"--initrd", filepath.Join(cacheDir, "tinfoil-inference-v0.11.0.initrd"),
		"--append", cmdline,
		"--guest-features", "0x1",
		"--output-format", "hex",
	})
	tdxArguments := readLines(t, tdxArgumentsPath)
	if len(tdxArguments) != 9 {
		t.Fatalf("TDX arguments = %#v, want 9 entries", tdxArguments)
	}
	if !strings.HasSuffix(tdxArguments[0], "/metadata.json") {
		t.Fatalf("TDX metadata argument = %q", tdxArguments[0])
	}
	wantTDXTail := []string{"--runtime-only", "--cpu", "2", "--memory", "4096G", "--direct-boot=true", "--json-file"}
	if !reflect.DeepEqual(tdxArguments[1:8], wantTDXTail) || !strings.HasSuffix(tdxArguments[8], "/measurement.json") {
		t.Fatalf("TDX arguments = %#v", tdxArguments)
	}

	metadataBytes, err := os.ReadFile(tdxMetadataPath)
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		BootInfo map[string]string `json:"boot_info"`
		Direct   map[string]string `json:"direct"`
	}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		t.Fatal(err)
	}
	wantBootKeys := []string{"acpi_tables", "bios", "boot_0000", "boot_0001", "boot_0006", "boot_0007", "boot_order", "rsdp", "table_loader"}
	gotBootKeys := make([]string, 0, len(metadata.BootInfo))
	for key := range metadata.BootInfo {
		gotBootKeys = append(gotBootKeys, key)
	}
	sort.Strings(gotBootKeys)
	if !reflect.DeepEqual(gotBootKeys, wantBootKeys) {
		t.Fatalf("boot_info keys = %#v", gotBootKeys)
	}
	wantDirect := map[string]string{
		"kernel":  filepath.Join(cacheDir, "tinfoil-inference-v0.11.0.vmlinuz"),
		"initrd":  filepath.Join(cacheDir, "tinfoil-inference-v0.11.0.initrd"),
		"cmdline": cmdline,
	}
	if !reflect.DeepEqual(metadata.Direct, wantDirect) {
		t.Fatalf("direct metadata = %#v, want %#v", metadata.Direct, wantDirect)
	}

	deploymentBytes, err := os.ReadFile(filepath.Join(outputDir, "tinfoil-deployment.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got deployment
	if err := json.Unmarshal(deploymentBytes, &got); err != nil {
		t.Fatal(err)
	}
	if got.SNPMeasurement != strings.Repeat("a", 96) {
		t.Fatalf("SNP measurement = %q", got.SNPMeasurement)
	}
	var gotTDX map[string]string
	if err := json.Unmarshal(got.TDXMeasurement, &gotTDX); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotTDX, map[string]string{"rtmr1": "1111", "rtmr2": "2222"}) {
		t.Fatalf("TDX measurement = %#v", gotTDX)
	}
	if got.VMShape != (vmShape{CPUs: 2, MemoryMB: 4096, GPUs: 1, Disks: 3}) {
		t.Fatalf("VM shape = %#v", got.VMShape)
	}
	if got.Cmdline != cmdline || got.Config != base64.StdEncoding.EncodeToString(configBytes) {
		t.Fatalf("deployment did not preserve cmdline/config")
	}
	deploymentInfo, err := os.Stat(filepath.Join(outputDir, "tinfoil-deployment.json"))
	if err != nil {
		t.Fatal(err)
	}
	if deploymentInfo.Mode().Perm() != 0o644 {
		t.Fatalf("deployment mode = %o, want 644", deploymentInfo.Mode().Perm())
	}
	var gotManifest map[string]string
	if err := json.Unmarshal(got.Hashes, &gotManifest); err != nil {
		t.Fatal(err)
	}
	if gotManifest["kernel"] != fmt.Sprintf("%x", sha256.Sum256(kernel)) {
		t.Fatalf("manifest = %#v", gotManifest)
	}

	// The builder measures a command line composed here, not the firmware one:
	// an IGVM guest needs different PCI options, and composing both in one
	// place keeps the measured line a published value rather than the result of
	// a rewrite somebody downstream has to reimplement.
	// Spelled out rather than derived, so a change to how it is composed has to
	// be made here too. The PCI options go last, where the launcher puts them.
	igvmCmdline := fmt.Sprintf("readonly=on modprobe.blacklist=nouveau nouveau.modeset=0 root=/dev/mapper/root roothash=root-hash tinfoil-config-hash=%x pci=noacpi pcie_ports=compat", sha256.Sum256(configBytes))
	if igvmCmdline == cmdline {
		t.Fatal("the firmware and IGVM command lines are identical")
	}
	bootShimArguments := readLines(t, bootShimArgumentsPath)
	wantSNPArguments := []string{
		"build-snp",
		"--kernel", filepath.Join(cacheDir, "tinfoil-inference-v0.11.0.vmlinuz"),
		"--initramfs", filepath.Join(cacheDir, "tinfoil-inference-v0.11.0.initrd"),
		"--ram", "4096M",
		"--cmdline", igvmCmdline,
		"--vcpus", "2",
		"--output",
	}
	if !reflect.DeepEqual(bootShimArguments[:len(wantSNPArguments)], wantSNPArguments) {
		t.Fatalf("boot-shim SNP arguments = %#v", bootShimArguments)
	}
	// TDX gets the same inputs; only the subcommand differs.
	wantTDXArguments := append([]string{"build-tdx"}, wantSNPArguments[1:]...)
	tdxStart := len(wantSNPArguments) + 1
	if !reflect.DeepEqual(bootShimArguments[tdxStart:tdxStart+len(wantTDXArguments)], wantTDXArguments) {
		t.Fatalf("boot-shim TDX arguments = %#v", bootShimArguments[tdxStart:])
	}
	if got.IGVM == nil {
		t.Fatal("deployment carries no boot-shim measurement")
	}
	if !reflect.DeepEqual(got.IGVM.SNPLaunch, map[string]string{"measurement": "bbbb", "policy": "0x30133"}) {
		t.Fatalf("boot-shim SNP launch = %#v", got.IGVM.SNPLaunch)
	}
	if !reflect.DeepEqual(got.IGVM.TDXLaunch, map[string]string{"mrtd": "cccc", "rtmr0": "00"}) {
		t.Fatalf("boot-shim TDX launch = %#v", got.IGVM.TDXLaunch)
	}
	// What the builder reported measuring, not what it was asked to measure.
	if got.IGVM.Cmdline != igvmCmdline+" no5lvl" {
		t.Fatalf("boot-shim cmdline = %q", got.IGVM.Cmdline)
	}
	// The digest is published once, inside the launch object.
	if !strings.Contains(string(deploymentBytes), `"snp_launch"`) || strings.Contains(string(deploymentBytes), `"tdx_mrtd"`) {
		t.Fatal("the igvm block does not have the shape consumers are told to read")
	}
	// The firmware command line keeps its own PCI options.
	if !strings.Contains(got.Cmdline, "pci=realloc,nocrs") {
		t.Fatalf("firmware cmdline lost its PCI options: %q", got.Cmdline)
	}

	releaseBytes, err := os.ReadFile(filepath.Join(outputDir, "release.md"))
	if err != nil {
		t.Fatal(err)
	}
	wantRelease := fmt.Sprintf("SEV-SNP Measurement: `%s`\nTDX Measurement: `{'rtmr1': '1111', 'rtmr2': '2222'}`\nInference Image Version: [`0.11.0`](https://github.com/tinfoilsh/cvmimage/releases/tag/v0.11.0)\n", strings.Repeat("a", 96))
	if string(releaseBytes) != wantRelease {
		t.Fatalf("release.md = %q, want %q", releaseBytes, wantRelease)
	}
	releaseInfo, err := os.Stat(filepath.Join(outputDir, "release.md"))
	if err != nil {
		t.Fatal(err)
	}
	if releaseInfo.Mode().Perm() != 0o644 {
		t.Fatalf("release.md mode = %o, want 644", releaseInfo.Mode().Perm())
	}
	if !strings.Contains(stdout.String(), "Manifest digest matches pin") {
		t.Fatalf("stdout did not report manifest pin verification: %s", stdout.String())
	}
}

// newRunnerForRun wires up a Run() that reaches the builder: the artifacts it
// fetches, and stub tools for everything measured before boot-shim.
func newRunnerForRun(t *testing.T) *Runner {
	t.Helper()
	dir := t.TempDir()
	kernel, initrd := []byte("kernel fixture"), []byte("initrd fixture")
	manifestBytes := []byte(fmt.Sprintf(`{"version":"0.11.0","root":"root-hash","initrd":"%x","kernel":"%x","raw":"raw-hash"}`, sha256.Sum256(initrd), sha256.Sum256(kernel)))
	configPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(`cvm-version: 0.11.0@sha256:%x
cpus: 2
memory: 4096
shim:
  upstream-port: 8080
containers:
  - name: app
    image: example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`, sha256.Sum256(manifestBytes))), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cvm/v0.11.0/tinfoil-inference-v0.11.0-manifest.json":
			_, _ = w.Write(manifestBytes)
		case "/images/tinfoil-inference-v0.11.0.vmlinuz":
			_, _ = w.Write(kernel)
		case "/images/tinfoil-inference-v0.11.0.initrd":
			_, _ = w.Write(initrd)
		case "/edk2/v0.0.3/OVMF.fd":
			_, _ = w.Write([]byte("ovmf fixture"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return &Runner{
		ConfigPath:     configPath,
		CacheDir:       filepath.Join(dir, "cache"),
		OutputDir:      filepath.Join(dir, "output"),
		GHPath:         writeExecutable(t, dir, "gh", "#!/bin/sh\nexit 0\n"),
		SNPMeasurePath: writeExecutable(t, dir, "sev-snp-measure", "#!/bin/sh\nprintf '%s\\n' '"+strings.Repeat("a", 96)+"'\n"),
		TDXMeasurePath: writeExecutable(t, dir, "tdx-measure", `#!/bin/sh
while [ "$#" -gt 0 ]; do
    if [ "$1" = "--json-file" ]; then shift; printf '%s' '{"rtmr1":"1111"}' > "$1"; exit 0; fi
    shift
done
exit 1
`),
		CVMImageReleaseBase:  server.URL + "/cvm",
		CVMImageArtifactBase: server.URL + "/images",
		EDK2ReleaseBase:      server.URL + "/edk2",
		HTTPClient:           server.Client(),
		Stdout:               io.Discard,
		Stderr:               io.Discard,
	}
}

// A measurement that quietly goes missing on some releases is worse than a
// release that stops, so the builder failing has to fail the run.
func TestRunFailsWhenTheBuilderDoes(t *testing.T) {
	for _, test := range []struct {
		name   string
		script string
		want   string
	}{
		{
			name:   "exits nonzero",
			script: "#!/bin/sh\nexit 2\n",
			want:   "boot-shim build-snp",
		},
		{
			name: "writes a manifest this code does not understand",
			script: `#!/bin/sh
while [ "$#" -gt 0 ]; do
    if [ "$1" = "--output" ]; then
        shift
        printf '{"format_version":99,"platform":"sev-snp","command_line":"x","launch":{"measurement":"bbbb"}}' > "$1.manifest.json"
        exit 0
    fi
    shift
done
exit 1
`,
			want: "format 99",
		},
		{
			name: "measured a different command line",
			script: `#!/bin/sh
while [ "$#" -gt 0 ]; do
    if [ "$1" = "--output" ]; then
        shift
        printf '{"format_version":2,"platform":"sev-snp","command_line":"something else","launch":{"measurement":"bbbb"}}' > "$1.manifest.json"
        exit 0
    fi
    shift
done
exit 1
`,
			want: "does not start with the command line",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := newRunnerForRun(t)
			runner.BootShimPath = writeExecutable(t, t.TempDir(), "boot-shim", test.script)
			err := runner.Run(context.Background())
			if err == nil {
				t.Fatal("Run() succeeded despite the builder failing")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Run() error = %v, want it to mention %q", err, test.want)
			}
		})
	}
}

func TestRunRejectsInvalidConfigBeforeNetworkOrTools(t *testing.T) {
	temporaryDir := t.TempDir()
	configPath := filepath.Join(temporaryDir, "config.yml")
	config := []byte(`cvm-version: 0.11.0
cpus: 2
memory: 4096
shim:
  upstream-port: 8080
containers:
  - name: app
    image: example.com/app:latest
`)
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	runner := DefaultRunner()
	runner.ConfigPath = configPath
	runner.CacheDir = filepath.Join(temporaryDir, "cache")
	runner.OutputDir = filepath.Join(temporaryDir, "output")
	err := runner.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "must include an immutable digest") {
		t.Fatalf("Run() error = %v", err)
	}
	if _, statErr := os.Stat(runner.CacheDir); !os.IsNotExist(statErr) {
		t.Fatalf("cache was touched before validation: %v", statErr)
	}
}

func writeExecutable(t *testing.T, directory, name, contents string) string {
	t.Helper()
	filePath := filepath.Join(directory, name)
	if err := os.WriteFile(filePath, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	return filePath
}

func assertLines(t *testing.T, filePath string, want []string) {
	t.Helper()
	got := readLines(t, filePath)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s lines = %#v, want %#v", filePath, got, want)
	}
}

func readLines(t *testing.T, filePath string) []string {
	t.Helper()
	contents, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n")
}
