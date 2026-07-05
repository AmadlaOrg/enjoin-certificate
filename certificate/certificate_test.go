package certificate

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidate_ValidSelfSigned(t *testing.T) {
	cfg := &Config{
		Provider: "self-signed",
		Domains:  []string{"example.com", "www.example.com"},
		SelfSigned: &SelfSignedConfig{
			ValidityDays: 365,
			KeySize:      2048,
			KeyType:      "rsa",
		},
	}

	result := Validate(cfg)
	assert.True(t, result.Success)
	assert.Equal(t, "valid", result.Status)
	assert.NotEmpty(t, result.Changes)
	assert.Equal(t, "create", result.Changes[0].Action)
	assert.Equal(t, "certificate", result.Changes[0].Resource)
	assert.Equal(t, "example.com", result.Changes[0].Name)
}

func TestValidate_ValidACME(t *testing.T) {
	cfg := &Config{
		Provider: "acme",
		Domains:  []string{"example.com"},
		ACME: &ACMEConfig{
			Email:     "admin@example.com",
			Challenge: "http-01",
		},
		KeyPath: "/etc/ssl/private/example.com.key",
	}

	result := Validate(cfg)
	assert.True(t, result.Success)
	assert.Equal(t, "valid", result.Status)
	assert.Len(t, result.Changes, 2) // create + chmod
	assert.Equal(t, "create", result.Changes[0].Action)
	assert.Equal(t, "chmod", result.Changes[1].Action)
}

func TestValidate_MissingProvider(t *testing.T) {
	cfg := &Config{
		Domains: []string{"example.com"},
	}

	result := Validate(cfg)
	assert.False(t, result.Success)
	assert.Equal(t, "invalid", result.Status)
	assert.Contains(t, result.Errors, "provider is required")
}

func TestValidate_InvalidProvider(t *testing.T) {
	cfg := &Config{
		Provider: "unknown",
		Domains:  []string{"example.com"},
	}

	result := Validate(cfg)
	assert.False(t, result.Success)
	assert.Equal(t, "invalid", result.Status)
	assert.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0], "invalid provider")
}

func TestValidate_MissingDomains(t *testing.T) {
	cfg := &Config{
		Provider: "self-signed",
	}

	result := Validate(cfg)
	assert.False(t, result.Success)
	assert.Equal(t, "invalid", result.Status)
	assert.Contains(t, result.Errors, "domains is required and must not be empty")
}

func TestValidate_ACMEMissingEmail(t *testing.T) {
	cfg := &Config{
		Provider: "acme",
		Domains:  []string{"example.com"},
		ACME:     &ACMEConfig{},
	}

	result := Validate(cfg)
	assert.False(t, result.Success)
	assert.Equal(t, "invalid", result.Status)
	assert.Contains(t, result.Errors, "acme.email is required")
}

func TestValidate_ACMEMissingConfig(t *testing.T) {
	cfg := &Config{
		Provider: "acme",
		Domains:  []string{"example.com"},
	}

	result := Validate(cfg)
	assert.False(t, result.Success)
	assert.Equal(t, "invalid", result.Status)
	assert.Contains(t, result.Errors, "acme configuration is required when provider is acme")
}

func TestApply_SelfSigned(t *testing.T) {
	origCmd := execCommand
	defer func() { execCommand = origCmd }()
	execCommand = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("echo", "ok")
	}

	origMkdir := osMkdirAll
	defer func() { osMkdirAll = origMkdir }()
	osMkdirAll = func(path string, perm os.FileMode) error {
		return nil
	}

	cfg := &Config{
		Provider: "self-signed",
		Domains:  []string{"example.com", "www.example.com"},
		CertPath: "/tmp/test.crt",
		KeyPath:  "/tmp/test.key",
		SelfSigned: &SelfSignedConfig{
			ValidityDays: 365,
			KeySize:      2048,
			KeyType:      "rsa",
			Subject: &SubjectConfig{
				CN: "example.com",
				O:  "Test Org",
				C:  "US",
			},
		},
	}

	result := Apply(cfg)
	assert.True(t, result.Success)
	assert.Equal(t, "applied", result.Status)
	assert.Len(t, result.Changes, 1)
	assert.Equal(t, "created", result.Changes[0].Action)
	assert.Equal(t, "certificate", result.Changes[0].Resource)
	assert.Equal(t, "example.com", result.Changes[0].Name)
}

func TestApply_ACME(t *testing.T) {
	origCmd := execCommand
	defer func() { execCommand = origCmd }()
	execCommand = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("echo", "ok")
	}

	cfg := &Config{
		Provider: "acme",
		Domains:  []string{"example.com"},
		ACME: &ACMEConfig{
			Email:     "admin@example.com",
			Challenge: "http-01",
		},
	}

	result := Apply(cfg)
	assert.True(t, result.Success)
	assert.Equal(t, "applied", result.Status)
	assert.Len(t, result.Changes, 1)
	assert.Equal(t, "created", result.Changes[0].Action)
	assert.Equal(t, "certificate", result.Changes[0].Resource)
}

func TestApply_Manual(t *testing.T) {
	origCmd := execCommand
	defer func() { execCommand = origCmd }()
	execCommand = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("echo", "ok")
	}

	origStat := osStat
	defer func() { osStat = origStat }()
	osStat = func(name string) (os.FileInfo, error) {
		return nil, nil
	}

	cfg := &Config{
		Provider: "manual",
		Domains:  []string{"example.com"},
		CertPath: "/etc/ssl/certs/example.com.crt",
		KeyPath:  "/etc/ssl/private/example.com.key",
	}

	result := Apply(cfg)
	assert.True(t, result.Success)
	assert.Equal(t, "applied", result.Status)
	assert.Len(t, result.Changes, 1)
	assert.Equal(t, "verified", result.Changes[0].Action)
	assert.Equal(t, "certificate", result.Changes[0].Resource)
}

func TestApply_ManualMissingPaths(t *testing.T) {
	cfg := &Config{
		Provider: "manual",
		Domains:  []string{"example.com"},
	}

	result := Apply(cfg)
	assert.False(t, result.Success)
	assert.Equal(t, "failed", result.Status)
	assert.NotEmpty(t, result.Errors)
}

func TestApply_ManualFileNotFound(t *testing.T) {
	origStat := osStat
	defer func() { osStat = origStat }()
	osStat = func(name string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}

	cfg := &Config{
		Provider: "manual",
		Domains:  []string{"example.com"},
		CertPath: "/nonexistent/cert.crt",
		KeyPath:  "/nonexistent/key.key",
	}

	result := Apply(cfg)
	assert.False(t, result.Success)
	assert.Equal(t, "failed", result.Status)
}

func TestApply_ValidationErrors(t *testing.T) {
	cfg := &Config{}

	result := Apply(cfg)
	assert.False(t, result.Success)
	assert.Equal(t, "failed", result.Status)
	assert.NotEmpty(t, result.Errors)
}

func TestApplyDefaults(t *testing.T) {
	cfg := &Config{
		Provider: "self-signed",
		Domains:  []string{"example.com"},
	}
	applyDefaults(cfg)

	assert.Equal(t, "0600", cfg.KeyMode)
	assert.Equal(t, 30, cfg.RenewBeforeDays)
	assert.NotNil(t, cfg.SelfSigned)
	assert.Equal(t, 365, cfg.SelfSigned.ValidityDays)
	assert.Equal(t, 2048, cfg.SelfSigned.KeySize)
	assert.Equal(t, "rsa", cfg.SelfSigned.KeyType)
}

func TestApplyDefaults_ACME(t *testing.T) {
	cfg := &Config{
		Provider: "acme",
		Domains:  []string{"example.com"},
		ACME:     &ACMEConfig{Email: "test@example.com"},
	}
	applyDefaults(cfg)

	assert.Equal(t, "https://acme-v02.api.letsencrypt.org/directory", cfg.ACME.Server)
	assert.Equal(t, "http-01", cfg.ACME.Challenge)
}
