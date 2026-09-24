package engine

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/abulhanifah/serverfingerprint/internal/collector"
	"github.com/abulhanifah/serverfingerprint/internal/utils"
)

// FingerprintEngine adalah engine utama untuk menghasilkan fingerprint server
type FingerprintEngine struct {
	secretKey   string
	identity    *collector.Identity
	environment *collector.Environment
}

// NewFingerprintEngine membuat instance baru dari FingerprintEngine
func NewFingerprintEngine(secretKey string) *FingerprintEngine {
	return &FingerprintEngine{
		secretKey: secretKey,
	}
}

// Collect mengumpulkan identitas server dan environment
func (e *FingerprintEngine) Collect() error {
	// Collect identity
	identityCollector := collector.NewIdentityCollector()
	identity, err := identityCollector.Collect()
	if err != nil {
		return err
	}
	e.identity = identity

	// Detect environment
	envDetector := collector.NewEnvironmentDetector()
	environment, err := envDetector.Detect()
	if err != nil {
		return err
	}
	e.environment = environment

	return nil
}

// Generate menghasilkan fingerprint server
func (e *FingerprintEngine) Generate() (string, error) {
	if e.identity == nil || e.environment == nil {
		if err := e.Collect(); err != nil {
			return "", err
		}
	}

	// Normalize dan canonicalize data
	normalizedData := utils.NormalizeData(e.identity, e.environment)
	canonicalizedData := utils.Canonicalize(normalizedData)

	// Generate HMAC-SHA256
	mac := hmac.New(sha256.New, []byte(e.secretKey))
	mac.Write([]byte(canonicalizedData))
	fingerprint := hex.EncodeToString(mac.Sum(nil))

	return fingerprint, nil
}

// GetIdentity mengembalikan data identitas yang telah dikumpulkan
func (e *FingerprintEngine) GetIdentity() *collector.Identity {
	return e.identity
}

// GetEnvironment mengembalikan data environment yang telah dideteksi
func (e *FingerprintEngine) GetEnvironment() *collector.Environment {
	return e.environment
}

// ReGenerate menghasilkan fingerprint dengan secret key baru
func (e *FingerprintEngine) ReGenerate(secretKey string) (string, error) {
	e.secretKey = secretKey
	return e.Generate()
}
