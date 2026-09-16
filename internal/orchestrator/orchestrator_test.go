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
	"sync/atomic"
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
cvm-source:
  repo: example/cvmimage
  artifacts: https://images.example.com/cvm
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
	wantLegacy := &measurementConfig{CVMVersion: "0.10.9", Source: tinfoilconfig.DefaultCVMSource, CPUs: 8, Memory: 16384, GPUs: 1, ModelCount: 1}
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
	wantStrict := &measurementConfig{CVMVersion: "0.11.0", Source: tinfoilconfig.DefaultCVMSource, CPUs: 8, Memory: 16384}
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
		{name: "too many model disks", config: base + "models:\n" + strings.Repeat("  - {}\n", tinfoilconfig.MaxModelDisks+1), wantError: "models and volumes must declare at most"},
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
	measuredOVMFPath := filepath.Join(temporaryDir, "measured-ovmf")
	tdxArgumentsPath := filepath.Join(temporaryDir, "tdx-args")
	tdxMetadataPath := filepath.Join(temporaryDir, "tdx-metadata")

	kernel := []byte("kernel fixture")
	initrd := []byte("initrd fixture")
	ovmf := []byte("ovmf fixture\x00\xff")
	manifestBytes := []byte(fmt.Sprintf(`{"version":"0.11.0","root":"root-hash","initrd":"%x","kernel":"%x","raw":"raw-hash"}`, sha256.Sum256(initrd), sha256.Sum256(kernel)))
	manifestDigest := sha256.Sum256(manifestBytes)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/example/cvmimage/releases/download/v0.11.0/tinfoil-inference-v0.11.0-manifest.json":
			_, _ = writer.Write(manifestBytes)
		case "/images/tinfoil-inference-v0.11.0.vmlinuz":
			_, _ = writer.Write(kernel)
		case "/images/tinfoil-inference-v0.11.0.initrd":
			_, _ = writer.Write(initrd)
		case "/edk2/v0.0.4/OVMF.fd":
			_, _ = writer.Write(ovmf)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	configBytes := []byte(fmt.Sprintf(`cvm-version: 0.11.0@sha256:%x
cvm-source:
  repo: example/cvmimage
  artifacts: %s/images
cpus: 2
memory: 4096
gpus: 1
shim:
  upstream-port: 8080
models:
  - repo: example/model@revision
volumes:
  - name: workspace
containers:
  - name: app
    image: example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    runtime: nvidia
    gpus: all
    volumes: [workspace:/workspace]
`, manifestDigest, server.URL))
	if err := os.WriteFile(configPath, configBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	ghPath := writeExecutable(t, temporaryDir, "gh", `#!/bin/sh
printf '%s\n' "$@" >> "$GH_ARGUMENTS_PATH"
`)
	snpPath := writeExecutable(t, temporaryDir, "sev-snp-measure", `#!/bin/sh
printf '%s\n' "$@" > "$SNP_ARGUMENTS_PATH"
while [ "$#" -gt 0 ]; do
    if [ "$1" = "--ovmf" ]; then
        cp "$2" "$SNP_OVMF_PATH"
        break
    fi
    shift
done
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
	t.Setenv("GH_ARGUMENTS_PATH", ghArgumentsPath)
	t.Setenv("SNP_ARGUMENTS_PATH", snpArgumentsPath)
	t.Setenv("SNP_OVMF_PATH", measuredOVMFPath)
	t.Setenv("TDX_ARGUMENTS_PATH", tdxArgumentsPath)
	t.Setenv("TDX_METADATA_PATH", tdxMetadataPath)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	runner := &Runner{
		ConfigPath:      configPath,
		CacheDir:        cacheDir,
		OutputDir:       outputDir,
		GHPath:          ghPath,
		SNPMeasurePath:  snpPath,
		TDXMeasurePath:  tdxPath,
		GitHubBase:      server.URL,
		EDK2ReleaseBase: server.URL + "/edk2",
		EDK2SHA256:      fmt.Sprintf("%x", sha256.Sum256(ovmf)),
		HTTPClient:      server.Client(),
		Stdout:          &stdout,
		Stderr:          &stderr,
	}
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error: %v\nstderr: %s", err, stderr.String())
	}
	cachePath := func(relativeURL string) string {
		return filepath.Join(cacheDir, fmt.Sprintf("%x", sha256.Sum256([]byte(server.URL+relativeURL))), filepath.Base(relativeURL))
	}
	manifestPath := cachePath("/example/cvmimage/releases/download/v0.11.0/tinfoil-inference-v0.11.0-manifest.json")
	ovmfPath := cachePath("/edk2/v0.0.4/OVMF.fd")
	kernelPath := cachePath("/images/tinfoil-inference-v0.11.0.vmlinuz")
	initrdPath := cachePath("/images/tinfoil-inference-v0.11.0.initrd")

	assertLines(t, ghArgumentsPath, []string{
		"attestation", "verify", manifestPath,
		"-R", "example/cvmimage", "--deny-self-hosted-runners", "--predicate-type", "https://slsa.dev/provenance/v1",
		"attestation", "verify", ovmfPath,
		"-R", "tinfoilsh/edk2", "--deny-self-hosted-runners", "--predicate-type", "https://tinfoil.sh/predicate/component-artifact/v1",
	})
	cmdline := fmt.Sprintf("readonly=on pci=realloc,nocrs modprobe.blacklist=nouveau nouveau.modeset=0 root=/dev/mapper/root roothash=root-hash tinfoil-config-hash=%x", sha256.Sum256(configBytes))
	assertLines(t, snpArgumentsPath, []string{
		"--mode", "snp",
		"--vcpus", "2",
		"--vcpu-type", "EPYC-v4",
		"--vmm-type", "QEMU",
		"--ovmf", ovmfPath,
		"--kernel", kernelPath,
		"--initrd", initrdPath,
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
		"kernel":  kernelPath,
		"initrd":  initrdPath,
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
	// Decode the public wire keys independently of the emitter's Go types and
	// check the hash against the bytes actually received by the measurement tool.
	var wireMetadata struct {
		Firmware map[string]map[string]string `json:"firmware"`
	}
	if err := json.Unmarshal(deploymentBytes, &wireMetadata); err != nil {
		t.Fatal(err)
	}
	measuredOVMF, err := os.ReadFile(measuredOVMFPath)
	if err != nil {
		t.Fatal(err)
	}
	wantFirmware := map[string]map[string]string{"sev_snp": {
		"type": "ovmf", "version": "v0.0.4", "sha256": fmt.Sprintf("%x", sha256.Sum256(measuredOVMF)),
	}}
	if !reflect.DeepEqual(wireMetadata.Firmware, wantFirmware) {
		t.Fatalf("firmware metadata = %#v, want %#v", wireMetadata.Firmware, wantFirmware)
	}
	var gotTDX map[string]string
	if err := json.Unmarshal(got.TDXMeasurement, &gotTDX); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotTDX, map[string]string{"rtmr1": "1111", "rtmr2": "2222"}) {
		t.Fatalf("TDX measurement = %#v", gotTDX)
	}
	if got.VMShape != (vmShape{CPUs: 2, MemoryMB: 4096, GPUs: 1, Disks: 5}) {
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

	releaseBytes, err := os.ReadFile(filepath.Join(outputDir, "release.md"))
	if err != nil {
		t.Fatal(err)
	}
	wantRelease := fmt.Sprintf("SEV-SNP Measurement: `%s`\nTDX Measurement: `{'rtmr1': '1111', 'rtmr2': '2222'}`\nInference Image Version: [`0.11.0`](https://github.com/example/cvmimage/releases/tag/v0.11.0)\n", strings.Repeat("a", 96))
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

func TestRunRejectsUnverifiedFirmwareBeforeMeasurement(t *testing.T) {
	for _, test := range []struct {
		name         string
		missing      bool
		badSignature bool
		wrongDigest  bool
		corruptCache bool
		wantError    string
	}{
		{name: "unavailable release", missing: true, wantError: "HTTP 404"},
		{name: "failed attestation", badSignature: true, wantError: "attestation verification failed"},
		{name: "download differs from pin", wrongDigest: true, wantError: "SEV-SNP OVMF digest mismatch"},
		{name: "corrupt cached firmware", corruptCache: true, wantError: "SEV-SNP OVMF digest mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			temporaryDir := t.TempDir()
			kernel, initrd, ovmf := []byte("kernel"), []byte("initrd"), []byte("ovmf")
			manifestBytes := []byte(fmt.Sprintf(`{"root":"root","kernel":"%x","initrd":"%x"}`, sha256.Sum256(kernel), sha256.Sum256(initrd)))
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch filepath.Base(r.URL.Path) {
				case "tinfoil-inference-v0.11.0-manifest.json":
					_, _ = w.Write(manifestBytes)
				case "tinfoil-inference-v0.11.0.vmlinuz":
					_, _ = w.Write(kernel)
				case "tinfoil-inference-v0.11.0.initrd":
					_, _ = w.Write(initrd)
				case "OVMF.fd":
					if test.missing {
						http.NotFound(w, r)
						return
					}
					_, _ = w.Write(ovmf)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			config := fmt.Sprintf("cvm-version: 0.11.0\ncvm-source:\n  repo: example/cvmimage\n  artifacts: %s/images\ncpus: 2\nmemory: 4096\nshim:\n  upstream-port: 8080\ncontainers:\n  - name: app\n    image: example.com/app@sha256:%s\n", server.URL, strings.Repeat("a", 64))
			runner := DefaultRunner()
			runner.ConfigPath = filepath.Join(temporaryDir, "config.yml")
			if err := os.WriteFile(runner.ConfigPath, []byte(config), 0o600); err != nil {
				t.Fatal(err)
			}
			runner.CacheDir = filepath.Join(temporaryDir, "cache")
			runner.OutputDir = filepath.Join(temporaryDir, "output")
			runner.GitHubBase = server.URL
			runner.EDK2ReleaseBase = server.URL + "/edk2"
			runner.EDK2SHA256 = fmt.Sprintf("%x", sha256.Sum256(ovmf))
			runner.HTTPClient = server.Client()
			runner.Stdout, runner.Stderr = io.Discard, io.Discard
			ghScript := "#!/bin/sh\nexit 0\n"
			if test.badSignature {
				ghScript = "#!/bin/sh\ncase \"$3\" in */OVMF.fd) exit 1;; esac\n"
			}
			runner.GHPath = writeExecutable(t, temporaryDir, "gh", ghScript)
			toolMarker := filepath.Join(temporaryDir, "measurement-ran")
			t.Setenv("MEASUREMENT_MARKER", toolMarker)
			runner.SNPMeasurePath = writeExecutable(t, temporaryDir, "measure", "#!/bin/sh\ntouch \"$MEASUREMENT_MARKER\"\nexit 1\n")
			runner.TDXMeasurePath = runner.SNPMeasurePath
			if test.wrongDigest {
				runner.EDK2SHA256 = strings.Repeat("0", 64)
			}
			if test.corruptCache {
				firmwarePath, err := runner.fetch(context.Background(), runner.EDK2ReleaseBase+"/v0.0.4/OVMF.fd")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(firmwarePath, []byte("corrupt cached firmware"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := runner.Run(context.Background()); err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Run() error = %v, want %q", err, test.wantError)
			}
			for _, filePath := range []string{toolMarker, filepath.Join(runner.OutputDir, "tinfoil-deployment.json")} {
				if _, err := os.Stat(filePath); !os.IsNotExist(err) {
					t.Fatalf("unverified firmware reached measurement/output %s: %v", filePath, err)
				}
			}
		})
	}
}

func TestFetchSeparatesReleasesAndRepositoriesInCache(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, r.URL.RequestURI())
	}))
	defer server.Close()
	cacheDir := t.TempDir()
	// Ignore files left by the old basename-only cache as well.
	if err := os.WriteFile(filepath.Join(cacheDir, "OVMF.fd"), []byte("old unscoped firmware"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := DefaultRunner()
	runner.CacheDir = cacheDir
	runner.Stdout = io.Discard
	paths := map[string]bool{}
	for _, relativeURL := range []string{"/edk2/v0.0.3/OVMF.fd", "/edk2/v0.0.4/OVMF.fd", "/other/v0.0.4/OVMF.fd", "/edk2/v0.0.4/OVMF.fd?revision=2"} {
		for attempt := 0; attempt < 2; attempt++ {
			filePath, err := runner.fetch(context.Background(), server.URL+relativeURL)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filePath)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != relativeURL {
				t.Fatalf("fetch(%s) reused different artifact %q", relativeURL, data)
			}
			paths[filePath] = true
		}
	}
	if requests.Load() != 4 || len(paths) != 4 {
		t.Fatalf("cache produced %d requests and %d files, want 4 of each", requests.Load(), len(paths))
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
