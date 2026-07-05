package certificate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Config represents the certificate entity input.
type Config struct {
	Provider        string            `json:"provider" yaml:"provider"`
	Domains         []string          `json:"domains" yaml:"domains"`
	ACME            *ACMEConfig       `json:"acme,omitempty" yaml:"acme,omitempty"`
	SelfSigned      *SelfSignedConfig `json:"self_signed,omitempty" yaml:"self_signed,omitempty"`
	CertPath        string            `json:"cert_path,omitempty" yaml:"cert_path,omitempty"`
	KeyPath         string            `json:"key_path,omitempty" yaml:"key_path,omitempty"`
	ChainPath       string            `json:"chain_path,omitempty" yaml:"chain_path,omitempty"`
	FullchainPath   string            `json:"fullchain_path,omitempty" yaml:"fullchain_path,omitempty"`
	KeyMode         string            `json:"key_mode,omitempty" yaml:"key_mode,omitempty"`
	RenewBeforeDays int               `json:"renew_before_days,omitempty" yaml:"renew_before_days,omitempty"`
	Notify          string            `json:"notify,omitempty" yaml:"notify,omitempty"`
}

// ACMEConfig holds ACME provider settings.
type ACMEConfig struct {
	Server      string `json:"server,omitempty" yaml:"server,omitempty"`
	Email       string `json:"email" yaml:"email"`
	Challenge   string `json:"challenge,omitempty" yaml:"challenge,omitempty"`
	DNSProvider string `json:"dns_provider,omitempty" yaml:"dns_provider,omitempty"`
}

// SelfSignedConfig holds self-signed certificate settings.
type SelfSignedConfig struct {
	ValidityDays int            `json:"validity_days,omitempty" yaml:"validity_days,omitempty"`
	KeySize      int            `json:"key_size,omitempty" yaml:"key_size,omitempty"`
	KeyType      string         `json:"key_type,omitempty" yaml:"key_type,omitempty"`
	Subject      *SubjectConfig `json:"subject,omitempty" yaml:"subject,omitempty"`
}

// SubjectConfig holds certificate subject fields.
type SubjectConfig struct {
	CN string `json:"cn,omitempty" yaml:"cn,omitempty"`
	O  string `json:"o,omitempty" yaml:"o,omitempty"`
	OU string `json:"ou,omitempty" yaml:"ou,omitempty"`
	C  string `json:"c,omitempty" yaml:"c,omitempty"`
	ST string `json:"st,omitempty" yaml:"st,omitempty"`
	L  string `json:"l,omitempty" yaml:"l,omitempty"`
}

// Result represents the outcome of an apply or validate operation.
type Result struct {
	Success bool           `json:"success"`
	Status  string         `json:"status"`
	Changes []ChangeDetail `json:"changes,omitempty"`
	Errors  []string       `json:"errors,omitempty"`
}

// ChangeDetail describes a single change made or planned.
type ChangeDetail struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Name     string `json:"name"`
	Detail   string `json:"detail,omitempty"`
}

var (
	execCommand = exec.Command
	osWriteFile = os.WriteFile
	osMkdirAll  = os.MkdirAll
	osStat      = os.Stat
)

// Apply provisions or verifies certificates based on provider type.
func Apply(cfg *Config) *Result {
	result := &Result{Success: true, Status: "applied"}

	if errs := validateConfig(cfg); len(errs) > 0 {
		return &Result{
			Success: false,
			Status:  "failed",
			Errors:  errs,
		}
	}

	applyDefaults(cfg)

	switch cfg.Provider {
	case "self-signed":
		if err := applySelfSigned(cfg, result); err != nil {
			result.Errors = append(result.Errors, err.Error())
			result.Success = false
			result.Status = "failed"
		}
	case "acme":
		if err := applyACME(cfg, result); err != nil {
			result.Errors = append(result.Errors, err.Error())
			result.Success = false
			result.Status = "failed"
		}
	case "manual":
		if err := applyManual(cfg, result); err != nil {
			result.Errors = append(result.Errors, err.Error())
			result.Success = false
			result.Status = "failed"
		}
	}

	if result.Success && cfg.Notify != "" {
		if err := runNotify(cfg.Notify); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("notify command failed: %v", err))
			result.Success = false
			result.Status = "failed"
		}
	}

	return result
}

// Validate checks the configuration and reports planned changes without making changes.
func Validate(cfg *Config) *Result {
	result := &Result{Success: true, Status: "valid"}

	if errs := validateConfig(cfg); len(errs) > 0 {
		return &Result{
			Success: false,
			Status:  "invalid",
			Errors:  errs,
		}
	}

	applyDefaults(cfg)

	switch cfg.Provider {
	case "self-signed":
		result.Changes = append(result.Changes, ChangeDetail{
			Action:   "create",
			Resource: "certificate",
			Name:     cfg.Domains[0],
			Detail:   fmt.Sprintf("self-signed certificate for %s", strings.Join(cfg.Domains, ", ")),
		})
	case "acme":
		result.Changes = append(result.Changes, ChangeDetail{
			Action:   "create",
			Resource: "certificate",
			Name:     cfg.Domains[0],
			Detail:   fmt.Sprintf("ACME certificate via %s for %s", cfg.ACME.Server, strings.Join(cfg.Domains, ", ")),
		})
	case "manual":
		result.Changes = append(result.Changes, ChangeDetail{
			Action:   "verify",
			Resource: "certificate",
			Name:     cfg.Domains[0],
			Detail:   "verify manually placed certificate files exist",
		})
	}

	if cfg.KeyPath != "" {
		result.Changes = append(result.Changes, ChangeDetail{
			Action:   "chmod",
			Resource: "key",
			Name:     cfg.KeyPath,
			Detail:   fmt.Sprintf("set permissions to %s", cfg.KeyMode),
		})
	}

	return result
}

func validateConfig(cfg *Config) []string {
	var errs []string

	if cfg.Provider == "" {
		errs = append(errs, "provider is required")
	} else if cfg.Provider != "acme" && cfg.Provider != "self-signed" && cfg.Provider != "manual" {
		errs = append(errs, fmt.Sprintf("invalid provider %q: must be acme, self-signed, or manual", cfg.Provider))
	}

	if len(cfg.Domains) == 0 {
		errs = append(errs, "domains is required and must not be empty")
	}

	if cfg.Provider == "acme" {
		if cfg.ACME == nil {
			errs = append(errs, "acme configuration is required when provider is acme")
		} else if cfg.ACME.Email == "" {
			errs = append(errs, "acme.email is required")
		}
	}

	return errs
}

func applyDefaults(cfg *Config) {
	if cfg.KeyMode == "" {
		cfg.KeyMode = "0600"
	}
	if cfg.RenewBeforeDays == 0 {
		cfg.RenewBeforeDays = 30
	}
	if cfg.Provider == "self-signed" && cfg.SelfSigned == nil {
		cfg.SelfSigned = &SelfSignedConfig{}
	}
	if cfg.SelfSigned != nil {
		if cfg.SelfSigned.ValidityDays == 0 {
			cfg.SelfSigned.ValidityDays = 365
		}
		if cfg.SelfSigned.KeySize == 0 {
			cfg.SelfSigned.KeySize = 2048
		}
		if cfg.SelfSigned.KeyType == "" {
			cfg.SelfSigned.KeyType = "rsa"
		}
	}
	if cfg.Provider == "acme" && cfg.ACME != nil {
		if cfg.ACME.Server == "" {
			cfg.ACME.Server = "https://acme-v02.api.letsencrypt.org/directory"
		}
		if cfg.ACME.Challenge == "" {
			cfg.ACME.Challenge = "http-01"
		}
	}
}

func applySelfSigned(cfg *Config, result *Result) error {
	certPath := cfg.CertPath
	keyPath := cfg.KeyPath
	if certPath == "" {
		certPath = fmt.Sprintf("/etc/ssl/certs/%s.crt", cfg.Domains[0])
	}
	if keyPath == "" {
		keyPath = fmt.Sprintf("/etc/ssl/private/%s.key", cfg.Domains[0])
	}

	// Ensure directories exist
	if err := osMkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}
	if err := osMkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	// Build subject string
	subject := fmt.Sprintf("/CN=%s", cfg.Domains[0])
	if cfg.SelfSigned.Subject != nil {
		s := cfg.SelfSigned.Subject
		if s.CN != "" {
			subject = fmt.Sprintf("/CN=%s", s.CN)
		}
		if s.O != "" {
			subject += fmt.Sprintf("/O=%s", s.O)
		}
		if s.OU != "" {
			subject += fmt.Sprintf("/OU=%s", s.OU)
		}
		if s.C != "" {
			subject += fmt.Sprintf("/C=%s", s.C)
		}
		if s.ST != "" {
			subject += fmt.Sprintf("/ST=%s", s.ST)
		}
		if s.L != "" {
			subject += fmt.Sprintf("/L=%s", s.L)
		}
	}

	// Build SAN extension for multiple domains
	var sanArgs []string
	if len(cfg.Domains) > 1 {
		var sans []string
		for _, d := range cfg.Domains {
			sans = append(sans, fmt.Sprintf("DNS:%s", d))
		}
		sanArgs = []string{"-addext", fmt.Sprintf("subjectAltName=%s", strings.Join(sans, ","))}
	}

	args := []string{
		"req", "-x509", "-newkey",
		fmt.Sprintf("%s:%d", cfg.SelfSigned.KeyType, cfg.SelfSigned.KeySize),
		"-keyout", keyPath,
		"-out", certPath,
		"-days", fmt.Sprintf("%d", cfg.SelfSigned.ValidityDays),
		"-nodes",
		"-subj", subject,
	}
	args = append(args, sanArgs...)

	cmd := execCommand("openssl", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("openssl failed: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Set key permissions
	if err := chmodKey(keyPath, cfg.KeyMode); err != nil {
		return err
	}

	result.Changes = append(result.Changes, ChangeDetail{
		Action:   "created",
		Resource: "certificate",
		Name:     cfg.Domains[0],
		Detail:   fmt.Sprintf("self-signed cert at %s, key at %s", certPath, keyPath),
	})

	return nil
}

func applyACME(cfg *Config, result *Result) error {
	args := []string{
		"certonly", "--non-interactive", "--agree-tos",
		"--email", cfg.ACME.Email,
	}

	switch cfg.ACME.Challenge {
	case "dns-01":
		if cfg.ACME.DNSProvider != "" {
			args = append(args, "--preferred-challenges", "dns",
				"--dns-"+cfg.ACME.DNSProvider)
		} else {
			args = append(args, "--preferred-challenges", "dns", "--manual")
		}
	case "tls-alpn-01":
		args = append(args, "--preferred-challenges", "tls-alpn")
	default:
		args = append(args, "--standalone")
	}

	if cfg.ACME.Server != "" {
		args = append(args, "--server", cfg.ACME.Server)
	}

	for _, d := range cfg.Domains {
		args = append(args, "-d", d)
	}

	cmd := execCommand("certbot", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("certbot failed: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Set key permissions if custom key path provided
	if cfg.KeyPath != "" {
		if err := chmodKey(cfg.KeyPath, cfg.KeyMode); err != nil {
			return err
		}
	}

	result.Changes = append(result.Changes, ChangeDetail{
		Action:   "created",
		Resource: "certificate",
		Name:     cfg.Domains[0],
		Detail:   fmt.Sprintf("ACME certificate via %s", cfg.ACME.Server),
	})

	return nil
}

func applyManual(cfg *Config, result *Result) error {
	if cfg.CertPath == "" || cfg.KeyPath == "" {
		return fmt.Errorf("cert_path and key_path are required for manual provider")
	}

	if _, err := osStat(cfg.CertPath); err != nil {
		return fmt.Errorf("certificate file not found at %s: %w", cfg.CertPath, err)
	}
	if _, err := osStat(cfg.KeyPath); err != nil {
		return fmt.Errorf("key file not found at %s: %w", cfg.KeyPath, err)
	}

	// Set key permissions
	if err := chmodKey(cfg.KeyPath, cfg.KeyMode); err != nil {
		return err
	}

	result.Changes = append(result.Changes, ChangeDetail{
		Action:   "verified",
		Resource: "certificate",
		Name:     cfg.Domains[0],
		Detail:   fmt.Sprintf("manual cert at %s, key at %s", cfg.CertPath, cfg.KeyPath),
	})

	return nil
}

func chmodKey(keyPath, mode string) error {
	modeInt, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		return fmt.Errorf("invalid key_mode %q: %w", mode, err)
	}
	cmd := execCommand("chmod", fmt.Sprintf("%o", modeInt), keyPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chmod failed: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func runNotify(command string) error {
	cmd := execCommand("sh", "-c", command)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}
