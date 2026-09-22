package pkg

import (
	"serverfingerprint/internal/collector"
	"serverfingerprint/internal/engine"
)

// ServerFingerprint adalah wrapper yang lebih mudah digunakan
type ServerFingerprint struct {
	engine *engine.FingerprintEngine
}

// NewServerFingerprint membuat instance baru dari ServerFingerprint
func NewServerFingerprint(secretKey string) *ServerFingerprint {
	return &ServerFingerprint{
		engine: engine.NewFingerprintEngine(secretKey),
	}
}

// GenerateFingerprint menghasilkan fingerprint server
func (f *ServerFingerprint) GenerateFingerprint() (string, error) {
	return f.engine.Generate()
}

// GetIdentity mengembalikan data identitas server
func (f *ServerFingerprint) GetIdentity() *collector.Identity {
	return f.engine.GetIdentity()
}

// GetEnvironment mengembalikan data environment server
func (f *ServerFingerprint) GetEnvironment() *collector.Environment {
	return f.engine.GetEnvironment()
}

// ReGenerateFingerprint menghasilkan fingerprint dengan secret key baru
func (f *ServerFingerprint) ReGenerateFingerprint(secretKey string) (string, error) {
	return f.engine.ReGenerate(secretKey)
}

// GetRawIdentity mengembalikan identitas dalam bentuk map
func (f *ServerFingerprint) GetRawIdentity() map[string]string {
	identity := f.engine.GetIdentity()
	return map[string]string{
		"cpu_id":        identity.CPUID,
		"mac_address":   identity.MACAddress,
		"instance_id":   identity.InstanceID,
		"hostname":      identity.Hostname,
		"system_uuid":   identity.SystemUUID,
	}
}

// GetRawEnvironment mengembalikan environment dalam bentuk map
func (f *ServerFingerprint) GetRawEnvironment() map[string]interface{} {
	environment := f.engine.GetEnvironment()
	return map[string]interface{}{
		"type":        environment.Type,
		"provider":    environment.Provider,
		"is_virtual":  environment.IsVirtual,
		"is_cloud":    environment.IsCloud,
	}
}
