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
)

const (
	cvmImageRepository    = "tinfoilsh/cvmimage"
	defaultEDK2Version    = "v0.0.3"
	baseDiskCount         = 3
	artifactFetchAttempts = 4
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

	CVMImageReleaseBase  string
	CVMImageArtifactBase string
	EDK2ReleaseBase      string

	HTTPClient *http.Client
	Stdout     io.Writer
	Stderr     io.Writer
}

func DefaultRunner() *Runner {
	return &Runner{
		ConfigPath:           "/config.yml",
		CacheDir:             "/cache",
		OutputDir:            "/output",
		GHPath:               "gh",
		SNPMeasurePath:       "/opt/venv/bin/sev-snp-measure",
		TDXMeasurePath:       "/app/tdx-measure",
		CVMImageReleaseBase:  "https://github.com/tinfoilsh/cvmimage/releases/download",
		CVMImageArtifactBase: "https://images.tinfoil.sh/cvm",
		EDK2ReleaseBase:      "https://github.com/tinfoilsh/edk2/releases/download",
		HTTPClient:           http.DefaultClient,
		Stdout:               os.Stdout,
		Stderr:               os.Stderr,
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
	VMShape        vmShape         `json:"vm_shape"`
	Cmdline        string          `json:"cmdline"`
	Hashes         json.RawMessage `json:"hashes"`
	Config         string          `json:"config"`
}

func (r *Runner) Run(ctx context.Context) error {
	configBytes, err := os.ReadFile(r.ConfigPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	config, err := tinfoilconfig.Decode(configBytes, tinfoilconfig.Options{})
	if err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	cvmVersion, manifestDigest, err := parsePinnedName(config.CVMVersion)
	if err != nil {
		return fmt.Errorf("parse cvm-version: %w", err)
	}
	manifestURL := fmt.Sprintf("%s/v%s/tinfoil-inference-v%s-manifest.json", strings.TrimRight(r.CVMImageReleaseBase, "/"), cvmVersion, cvmVersion)
	manifestPath, err := r.fetchVerifiedArtifact(ctx, manifestURL, cvmImageRepository)
	if err != nil {
		return err
	}
	if manifestDigest != "" {
		if err := verifyDigest(manifestPath, manifestDigest, "cvm manifest"); err != nil {
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

	kernelURL := fmt.Sprintf("%s/tinfoil-inference-v%s.vmlinuz", strings.TrimRight(r.CVMImageArtifactBase, "/"), cvmVersion)
	kernelPath, err := r.fetch(ctx, kernelURL)
	if err != nil {
		return err
	}
	initrdURL := fmt.Sprintf("%s/tinfoil-inference-v%s.initrd", strings.TrimRight(r.CVMImageArtifactBase, "/"), cvmVersion)
	initrdPath, err := r.fetch(ctx, initrdURL)
	if err != nil {
		return err
	}
	if err := verifyDigest(kernelPath, hashes.Kernel, "kernel"); err != nil {
		return err
	}
	if err := verifyDigest(initrdPath, hashes.Initrd, "initrd"); err != nil {
		return err
	}

	ovmfURL := fmt.Sprintf("%s/%s/OVMF.fd", strings.TrimRight(r.EDK2ReleaseBase, "/"), defaultEDK2Version)
	ovmfPath, err := r.fetch(ctx, ovmfURL)
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
		VMShape: vmShape{
			CPUs:     config.CPUs,
			MemoryMB: config.Memory,
			GPUs:     config.GPUs,
			Disks:    baseDiskCount + len(config.Models),
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
	releaseNotes := fmt.Sprintf("SEV-SNP Measurement: `%s`\nTDX Measurement: `%s`\nInference Image Version: [`%s`](https://github.com/tinfoilsh/cvmimage/releases/tag/v%s)\n", snpMeasurement, pythonObjectRepr(tdxMeasurement), cvmVersion, cvmVersion)
	if err := writeFileAtomic(filepath.Join(r.OutputDir, "release.md"), []byte(releaseNotes)); err != nil {
		return fmt.Errorf("write release notes: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(r.OutputDir, "tinfoil-deployment.json"), deploymentBytes); err != nil {
		return fmt.Errorf("write deployment: %w", err)
	}
	return nil
}

func (r *Runner) fetchVerifiedArtifact(ctx context.Context, artifactURL, repository string) (string, error) {
	filePath, err := r.fetch(ctx, artifactURL)
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, r.GHPath, "attestation", "verify", filePath, "-R", repository, "--deny-self-hosted-runners")
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
	filePath := filepath.Join(r.CacheDir, name)
	if _, err := os.Stat(filePath); err == nil {
		fmt.Fprintf(r.Stdout, "Using cached file %s\n", filePath)
		return filePath, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect cached artifact %s: %w", filePath, err)
	}
	if err := os.MkdirAll(r.CacheDir, 0o755); err != nil {
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

func verifyDigest(filePath, expected, label string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("hash %s: %w", label, err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("hash %s: %w", label, err)
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != expected {
		return fmt.Errorf("%s digest mismatch: expected sha256:%s, got sha256:%s", label, expected, actual)
	}
	return nil
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
