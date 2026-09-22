package utils

import (
	"encoding/json"
	"sort"
	"strings"

	"serverfingerprint/internal/collector"
)

// NormalizeData menormalkan data identitas dan environment
func NormalizeData(identity *collector.Identity, environment *collector.Environment) map[string]interface{} {
	normalized := make(map[string]interface{})

	// Normalize identity fields
	normalized["cpu_id"] = normalizeString(identity.CPUID)
	normalized["mac_address"] = normalizeMAC(identity.MACAddress)
	normalized["instance_id"] = normalizeString(identity.InstanceID)
	normalized["hostname"] = normalizeString(identity.Hostname)
	normalized["system_uuid"] = normalizeString(identity.SystemUUID)

	// Normalize environment fields
	normalized["env_type"] = normalizeString(environment.Type)
	normalized["provider"] = normalizeString(environment.Provider)
	normalized["is_virtual"] = environment.IsVirtual
	normalized["is_cloud"] = environment.IsCloud

	return normalized
}

// normalizeString menormalkan string dengan menghapus whitespace berlebih
func normalizeString(s string) string {
	return strings.TrimSpace(s)
}

// normalizeMAC menormalkan MAC address ke format standar
func normalizeMAC(mac string) string {
	mac = strings.ToLower(strings.TrimSpace(mac))
	// Remove common separators
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, "-", "")
	mac = strings.ReplaceAll(mac, ".", "")
	return mac
}

// Canonicalize mengkonversi data yang dinormalisasi menjadi string canonical
func Canonicalize(data map[string]interface{}) string {
	// Sort keys untuk konsistensi
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build canonical string
	var parts []string
	for _, key := range keys {
		value := data[key]
		jsonValue, _ := json.Marshal(value)
		parts = append(parts, key+string(jsonValue))
	}

	return strings.Join(parts, "|")
}

// MarshalJSONCanonical men-marshal map ke JSON string canonical
func MarshalJSONCanonical(data map[string]interface{}) (string, error) {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	result := make(map[string]interface{})
	for _, key := range keys {
		result[key] = data[key]
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}
