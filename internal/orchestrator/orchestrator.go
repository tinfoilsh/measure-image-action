package orchestrator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	tinfoilconfig "github.com/tinfoilsh/tinfoil-config"
	"gopkg.in/yaml.v3"
)

const (
	defaultEDK2Version        = "v0.0.4"
	defaultEDK2SHA256         = "78c890175928167a1bc095d4bf3bb4ad81de80cd7e4e9e683477fc359119c1c4"
	componentArtifactType     = "https://tinfoil.sh/predicate/component-artifact/v1"
	buildProvenanceType       = "https://slsa.dev/provenance/v1"
	minCVMVersionStrictConfig = "0.11.0"
	baseDiskCount             = 3
	artifactFetchAttempts     = 4
)

// Runner contains the process and network boundaries used by the measurement
// orchestration. Measurement algorithms intentionally remain in their
// separately versioned command-line tools.
type Runner struct {
	ConfigPath     string
	CacheDir       string
	OutputDir      string
	GHPath         string
	SNPMeasurePath string
	TDXMeasurePath string

	GitHubBase      string
	EDK2ReleaseBase string
	EDK2SHA256      string

	HTTPClient *http.Client
	Stdout     io.Writer
	Stderr     io.Writer
}

func DefaultRunner() *Runner {
	return &Runner{
		ConfigPath:      "/config.yml",
		CacheDir:        "/cache",
		OutputDir:       "/output",
		GHPath:          "gh",
		SNPMeasurePath:  "/opt/venv/bin/sev-snp-measure",
		TDXMeasurePath:  "/app/tdx-measure",
		GitHubBase:      "https://github.com",
		EDK2ReleaseBase: "https://github.com/tinfoilsh/edk2/releases/download",
		EDK2SHA256:      defaultEDK2SHA256,
		HTTPClient:      http.DefaultClient,
		Stdout:          os.Stdout,
		Stderr:          os.Stderr,
	}
}

type manifest struct {
	Root   string `json:"root"`
	Initrd string `json:"initrd"`
	Kernel string `json:"kernel"`
}

type vmShape struct {
	CPUs     int `json:"cpus"`
	MemoryMB int `json:"memory_mb"`
	GPUs     int `json:"gpus"`
	Disks    int `json:"disks"`
}

type deployment struct {
	SNPMeasurement string          `json:"snp_measurement"`
	TDXMeasurement json.RawMessage `json:"tdx_measurement"`
	Firmware       firmware        `json:"firmware"`
	VMShape        vmShape         `json:"vm_shape"`
	Cmdline        string          `json:"cmdline"`
	Hashes         json.RawMessage `json:"hashes"`
	Config         string          `json:"config"`
}

type firmware struct {
	SEVSNP firmwareArtifact `json:"sev_snp"`
}

type firmwareArtifact struct {
	Type    string `json:"type"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// measurementConfig is the version-independent subset of workload config
// that contributes to image measurement and deployment metadata.
type measurementConfig struct {
	CVMVersion  string
	Source      tinfoilconfig.CVMSource
	CPUs        int
	Memory      int
	GPUs        int
	ModelCount  int
	VolumeCount int
}

type legacyMeasurementConfig struct {
	CVMVersion string      `yaml:"cvm-version"`
	CPUs       int         `yaml:"cpus"`
	Memory     int         `yaml:"memory"`
	GPUs       int         `yaml:"gpus"`
	Models     []yaml.Node `yaml:"models"`
}

func (r *Runner) Run(ctx context.Context) error {
	configBytes, err := os.ReadFile(r.ConfigPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	config, err := decodeMeasurementConfig(configBytes)
	if err != nil {
		return err
	}

	cvmVersion, manifestDigest, err := parsePinnedName(config.CVMVersion)
	if err != nil {
		return fmt.Errorf("parse cvm-version: %w", err)
	}
	manifestURL := fmt.Sprintf("%s/%s/releases/download/v%s/tinfoil-inference-v%s-manifest.json", strings.TrimRight(r.GitHubBase, "/"), config.Source.Repo, cvmVersion, cvmVersion)
	manifestPath, err := r.fetchVerifiedArtifact(ctx, manifestURL, config.Source.Repo, buildProvenanceType)
	if err != nil {
		return err
	}
	if manifestDigest != "" {
		if _, err := verifyDigest(manifestPath, manifestDigest, "cvm manifest"); err != nil {
			return err
		}
		fmt.Fprintf(r.Stdout, "Manifest digest matches pin: sha256:%s\n", manifestDigest)
	}

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read cvm manifest: %w", err)
	}
	var hashes manifest
	if err := json.Unmarshal(manifestBytes, &hashes); err != nil {
		return fmt.Errorf("parse cvm manifest: %w", err)
	}
	if hashes.Root == "" || hashes.Kernel == "" || hashes.Initrd == "" {
		return errors.New("parse cvm manifest: root, kernel, and initrd are required")
	}

	artifacts := strings.TrimRight(config.Source.Artifacts, "/")
	kernelURL := fmt.Sprintf("%s/tinfoil-inference-v%s.vmlinuz", artifacts, cvmVersion)
	kernelPath, err := r.fetch(ctx, kernelURL)
	if err != nil {
		return err
	}
	initrdURL := fmt.Sprintf("%s/tinfoil-inference-v%s.initrd", artifacts, cvmVersion)
	initrdPath, err := r.fetch(ctx, initrdURL)
	if err != nil {
		return err
	}
	if _, err := verifyDigest(kernelPath, hashes.Kernel, "kernel"); err != nil {
		return err
	}
	if _, err := verifyDigest(initrdPath, hashes.Initrd, "initrd"); err != nil {
		return err
	}

	ovmfURL := fmt.Sprintf("%s/%s/OVMF.fd", strings.TrimRight(r.EDK2ReleaseBase, "/"), defaultEDK2Version)
	ovmfPath, err := r.fetchVerifiedArtifact(ctx, ovmfURL, "tinfoilsh/edk2", componentArtifactType)
	if err != nil {
		return err
	}
	ovmfDigest, err := verifyDigest(ovmfPath, r.EDK2SHA256, "SEV-SNP OVMF")
	if err != nil {
		return err
	}

	configHash := sha256.Sum256(configBytes)
	cmdline := fmt.Sprintf("readonly=on pci=realloc,nocrs modprobe.blacklist=nouveau nouveau.modeset=0 root=/dev/mapper/root roothash=%s tinfoil-config-hash=%x", hashes.Root, configHash)
	fmt.Fprintln(r.Stdout, "Measuring...")

	snpMeasurement, err := r.measureSNP(ctx, config.CPUs, ovmfPath, kernelPath, initrdPath, cmdline)
	if err != nil {
		return err
	}
	tdxMeasurement, err := r.measureTDX(ctx, config.CPUs, config.Memory, kernelPath, initrdPath, cmdline)
	if err != nil {
		return err
	}

	result := deployment{
		SNPMeasurement: snpMeasurement,
		TDXMeasurement: tdxMeasurement,
		Firmware: firmware{SEVSNP: firmwareArtifact{
			Type:    "ovmf",
			Version: defaultEDK2Version,
			SHA256:  ovmfDigest,
		}},
		VMShape: vmShape{
			CPUs:     config.CPUs,
			MemoryMB: config.Memory,
			GPUs:     config.GPUs,
			Disks:    baseDiskCount + config.ModelCount + config.VolumeCount,
		},
		Cmdline: cmdline,
		Hashes:  json.RawMessage(manifestBytes),
		Config:  base64.StdEncoding.EncodeToString(configBytes),
	}
	deploymentBytes, err := json.MarshalIndent(result, "", "    ")
	if err != nil {
		return fmt.Errorf("encode deployment: %w", err)
	}
	fmt.Fprintln(r.Stdout, string(deploymentBytes))

	if err := os.MkdirAll(r.OutputDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	releaseNotes := fmt.Sprintf("SEV-SNP Measurement: `%s`\nTDX Measurement: `%s`\nInference Image Version: [`%s`](https://github.com/%s/releases/tag/v%s)\n", snpMeasurement, pythonObjectRepr(tdxMeasurement), cvmVersion, config.Source.Repo, cvmVersion)
	if err := writeFileAtomic(filepath.Join(r.OutputDir, "release.md"), []byte(releaseNotes)); err != nil {
		return fmt.Errorf("write release notes: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(r.OutputDir, "tinfoil-deployment.json"), deploymentBytes); err != nil {
		return fmt.Errorf("write deployment: %w", err)
	}
	return nil
}

// decodeMeasurementConfig applies the shared strict workload contract only to
// the v0.11+ image line that implements it. Older images retain their legacy
// YAML surface while still exposing the fields needed for measurement.
func decodeMeasurementConfig(configBytes []byte) (*measurementConfig, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(configBytes))
	var legacy legacyMeasurementConfig
	if err := decoder.Decode(&legacy); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, errors.New("parse config: multiple YAML documents")
		}
		return nil, fmt.Errorf("parse config: %w", err)
	}
	strict, err := versionAtLeastChecked(legacy.CVMVersion, minCVMVersionStrictConfig)
	if err != nil {
		return nil, fmt.Errorf("invalid CVM version %q: %w", legacy.CVMVersion, err)
	}
	if strict {
		config, err := tinfoilconfig.Decode(configBytes, tinfoilconfig.Options{})
		if err != nil {
			return nil, fmt.Errorf("validate config: %w", err)
		}
		measurement := &measurementConfig{
			CVMVersion:  config.CVMVersion,
			Source:      config.CVMSource.OrDefault(),
			CPUs:        config.CPUs,
			Memory:      config.Memory,
			GPUs:        config.GPUs,
			ModelCount:  len(config.Models),
			VolumeCount: len(config.Volumes),
		}
		if err := validateMeasurementConfig(measurement); err != nil {
			return nil, fmt.Errorf("validate config: %w", err)
		}
		return measurement, nil
	}

	measurement := &measurementConfig{
		CVMVersion: legacy.CVMVersion,
		Source:     tinfoilconfig.DefaultCVMSource,
		CPUs:       legacy.CPUs,
		Memory:     legacy.Memory,
		GPUs:       legacy.GPUs,
		ModelCount: len(legacy.Models),
	}
	if err := validateMeasurementConfig(measurement); err != nil {
		return nil, fmt.Errorf("validate legacy config: %w", err)
	}
	return measurement, nil
}

func validateMeasurementConfig(config *measurementConfig) error {
	if config.CPUs < 1 {
		return fmt.Errorf("cpus must be positive (got %d)", config.CPUs)
	}
	if config.Memory < 1 {
		return fmt.Errorf("memory must be positive (got %d)", config.Memory)
	}
	if config.GPUs < 0 || config.GPUs > 8 {
		return fmt.Errorf("gpus must be between 0 and 8 (got %d)", config.GPUs)
	}
	if disks := config.ModelCount + config.VolumeCount; disks > tinfoilconfig.MaxModelDisks {
		return fmt.Errorf("models and volumes must declare at most %d disks (got %d)", tinfoilconfig.MaxModelDisks, disks)
	}
	return nil
}

// parseVersion extracts feature compatibility from an image version.
// Prerelease, build, and digest suffixes do not change which guest code is
// present, matching tinfoild's launch-time compatibility gates.
func parseVersion(version string) (int, int, int, error) {
	original := version
	version = strings.TrimPrefix(version, "v")
	if index := strings.Index(version, "@"); index != -1 {
		version = version[:index]
	}
	if index := strings.IndexAny(version, "-+"); index != -1 {
		version = version[:index]
	}
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return 0, 0, 0, fmt.Errorf("invalid version: %s", original)
	}
	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(parts[1])
	patch, patchErr := strconv.Atoi(parts[2])
	if majorErr != nil || minorErr != nil || patchErr != nil || major < 0 || minor < 0 || patch < 0 {
		return 0, 0, 0, fmt.Errorf("invalid version: %s", original)
	}
	return major, minor, patch, nil
}

func versionAtLeastChecked(version, minimum string) (bool, error) {
	major, minor, patch, err := parseVersion(version)
	if err != nil {
		return false, err
	}
	minimumMajor, minimumMinor, minimumPatch, err := parseVersion(minimum)
	if err != nil {
		return false, fmt.Errorf("invalid minimum version %q: %w", minimum, err)
	}
	if major != minimumMajor {
		return major > minimumMajor, nil
	}
	if minor != minimumMinor {
		return minor > minimumMinor, nil
	}
	return patch >= minimumPatch, nil
}

func (r *Runner) fetchVerifiedArtifact(ctx context.Context, artifactURL, repository, predicateType string) (string, error) {
	filePath, err := r.fetch(ctx, artifactURL)
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, r.GHPath, "attestation", "verify", filePath, "-R", repository, "--deny-self-hosted-runners", "--predicate-type", predicateType)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("attestation verification failed for %s: %s: %w", filePath, strings.TrimSpace(string(output)), err)
	}
	fmt.Fprintf(r.Stdout, "Attestation verified for %s from %s\n", filepath.Base(filePath), repository)
	return filePath, nil
}

func (r *Runner) fetch(ctx context.Context, artifactURL string) (string, error) {
	parsed, err := url.Parse(artifactURL)
	if err != nil {
		return "", fmt.Errorf("parse artifact URL %q: %w", artifactURL, err)
	}
	name := path.Base(parsed.Path)
	if name == "." || name == "/" || name == "" {
		return "", fmt.Errorf("artifact URL has no file name: %q", artifactURL)
	}
	// Artifacts from different releases or repositories can have the same name
	// (notably OVMF.fd). A basename-only cache can measure the wrong firmware.
	cacheKey := sha256.Sum256([]byte(artifactURL))
	cacheDir := filepath.Join(r.CacheDir, hex.EncodeToString(cacheKey[:]))
	filePath := filepath.Join(cacheDir, name)
	if _, err := os.Stat(filePath); err == nil {
		fmt.Fprintf(r.Stdout, "Using cached file %s\n", filePath)
		return filePath, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect cached artifact %s: %w", filePath, err)
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", fmt.Errorf("create cache directory: %w", err)
	}
	fmt.Fprintf(r.Stdout, "Fetching %s...\n", artifactURL)

	client := r.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	var lastErr error
	for attempt := 0; attempt < artifactFetchAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, artifactURL, nil)
		if err != nil {
			return "", fmt.Errorf("create artifact request: %w", err)
		}
		response, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			lastErr = fmt.Errorf("HTTP %s", response.Status)
			if response.StatusCode < http.StatusInternalServerError && response.StatusCode != http.StatusTooManyRequests {
				break
			}
			continue
		}
		err = writeReaderAtomic(filePath, response.Body)
		closeErr := response.Body.Close()
		if err == nil && closeErr != nil {
			err = closeErr
		}
		if err != nil {
			return "", fmt.Errorf("store artifact %s: %w", filePath, err)
		}
		return filePath, nil
	}
	return "", fmt.Errorf("fetch %s: %w", artifactURL, lastErr)
}

func (r *Runner) measureSNP(ctx context.Context, cpus int, ovmfPath, kernelPath, initrdPath, cmdline string) (string, error) {
	args := []string{
		"--mode", "snp",
		"--vcpus", strconv.Itoa(cpus),
		"--vcpu-type", "EPYC-v4",
		"--vmm-type", "QEMU",
		"--ovmf", ovmfPath,
		"--kernel", kernelPath,
		"--initrd", initrdPath,
		"--append", cmdline,
		"--guest-features", "0x1",
		"--output-format", "hex",
	}
	cmd := exec.CommandContext(ctx, r.SNPMeasurePath, args...)
	cmd.Stderr = r.Stderr
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("measure SEV-SNP launch digest: %w", err)
	}
	measurement := strings.TrimSpace(string(output))
	decoded, err := hex.DecodeString(measurement)
	if err != nil || len(decoded) != 48 {
		return "", fmt.Errorf("measure SEV-SNP launch digest: expected 48-byte hexadecimal output, got %q", measurement)
	}
	return measurement, nil
}

func (r *Runner) measureTDX(ctx context.Context, cpus, memory int, kernelPath, initrdPath, cmdline string) (json.RawMessage, error) {
	workDir, err := os.MkdirTemp("", "tdx-measure-")
	if err != nil {
		return nil, fmt.Errorf("create TDX work directory: %w", err)
	}
	defer os.RemoveAll(workDir)

	metadataPath := filepath.Join(workDir, "metadata.json")
	measurementPath := filepath.Join(workDir, "measurement.json")
	metadata := struct {
		BootInfo map[string]string `json:"boot_info"`
		Direct   struct {
			Kernel  string `json:"kernel"`
			Initrd  string `json:"initrd"`
			Cmdline string `json:"cmdline"`
		} `json:"direct"`
	}{
		BootInfo: map[string]string{
			"bios": "", "acpi_tables": "", "rsdp": "", "table_loader": "", "boot_order": "",
			"boot_0000": "", "boot_0001": "", "boot_0006": "", "boot_0007": "",
		},
	}
	metadata.Direct.Kernel = kernelPath
	metadata.Direct.Initrd = initrdPath
	metadata.Direct.Cmdline = cmdline
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("encode TDX metadata: %w", err)
	}
	if err := os.WriteFile(metadataPath, metadataBytes, 0o600); err != nil {
		return nil, fmt.Errorf("write TDX metadata: %w", err)
	}

	// Preserve the historical command line exactly. tdx-measure has always
	// received the config's MiB value with a G suffix; changing that would alter
	// measurements and is deliberately outside this orchestration-only migration.
	args := []string{
		metadataPath,
		"--runtime-only",
		"--cpu", strconv.Itoa(cpus),
		"--memory", fmt.Sprintf("%dG", memory),
		"--direct-boot=true",
		"--json-file", measurementPath,
	}
	fmt.Fprintln(r.Stdout, strings.Join(append([]string{r.TDXMeasurePath}, args...), " "))
	cmd := exec.CommandContext(ctx, r.TDXMeasurePath, args...)
	cmd.Stdout = r.Stdout
	cmd.Stderr = r.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("measure TDX launch digest: %w", err)
	}
	measurement, err := os.ReadFile(measurementPath)
	if err != nil {
		return nil, fmt.Errorf("read TDX measurement: %w", err)
	}
	if !json.Valid(measurement) {
		return nil, errors.New("read TDX measurement: tool produced invalid JSON")
	}
	return json.RawMessage(measurement), nil
}

func parsePinnedName(value string) (string, string, error) {
	name, digest, pinned := strings.Cut(value, "@")
	if !pinned {
		if name == "" {
			return "", "", errors.New("name is empty")
		}
		return name, "", nil
	}
	if name == "" {
		return "", "", errors.New("name is empty")
	}
	if !strings.HasPrefix(digest, "sha256:") {
		return "", "", fmt.Errorf("unsupported digest algorithm in pinned reference %q (expected '<name>@sha256:<hex>')", value)
	}
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	if len(hexDigest) != 64 {
		return "", "", fmt.Errorf("malformed sha256 digest in pinned reference %q (expected 64 lowercase hex chars)", value)
	}
	for _, character := range hexDigest {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return "", "", fmt.Errorf("malformed sha256 digest in pinned reference %q (expected 64 lowercase hex chars)", value)
		}
	}
	return name, hexDigest, nil
}

func verifyDigest(filePath, expected, label string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("hash %s: %w", label, err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash %s: %w", label, err)
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != expected {
		return "", fmt.Errorf("%s digest mismatch: expected sha256:%s, got sha256:%s", label, expected, actual)
	}
	return actual, nil
}

func writeReaderAtomic(filePath string, source io.Reader) error {
	temporary, err := os.CreateTemp(filepath.Dir(filePath), ".download-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := io.Copy(temporary, source); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, filePath)
}

func writeFileAtomic(filePath string, contents []byte) error {
	return writeReaderAtomic(filePath, bytes.NewReader(contents))
}

func pythonObjectRepr(raw json.RawMessage) string {
	var object map[string]interface{}
	if err := json.Unmarshal(raw, &object); err != nil {
		return string(raw)
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		value, ok := object[key].(string)
		if !ok {
			return string(raw)
		}
		parts = append(parts, fmt.Sprintf("'%s': '%s'", key, value))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}
