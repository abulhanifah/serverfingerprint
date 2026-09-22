package collector

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"

	"serverfingerprint/internal/persistent"
)

// IdentityCollector mengumpulkan identitas server
type IdentityCollector struct{}

// NewIdentityCollector membuat instance baru dari IdentityCollector
func NewIdentityCollector() *IdentityCollector {
	return &IdentityCollector{}
}

// Collect mengumpulkan semua identitas server
func (c *IdentityCollector) Collect() (*Identity, error) {
	identity := &Identity{}

	// Collect CPU ID
	identity.CPUID = c.getCPUID()

	// Collect MAC Address
	identity.MACAddress = c.getMACAddress()

	// Collect Instance ID (Cloud-specific)
	identity.InstanceID = c.getInstanceID()

	// Collect Hostname
	identity.Hostname = c.getHostname()

	// Collect System UUID (dengan persistent storage)
	identity.SystemUUID = c.getSystemUUID()

	// Collect Provider-specific ID (GCP, Sumo, dll)
	identity.ProviderID = c.getProviderID()

	return identity, nil
}

// getProviderID mengambil Provider-specific ID
func (c *IdentityCollector) getProviderID() string {
	// AWS
	if content, err := os.ReadFile("/sys/hypervisor/uuid"); err == nil {
		if bytes.HasPrefix(content, []byte("ec2")) {
			return string(bytes.TrimSpace(content))
		}
	}
	// Alibaba Cloud
	if content, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
		if bytes.HasPrefix(content, []byte("ali")) {
			return string(bytes.TrimSpace(content))
		}
	}
	// Google Cloud Platform (GCP)
	if content, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
		if strings.Contains(string(content), "Google") {
			return string(bytes.TrimSpace(content))
		}
	}
	// Sumo Logic (sumopod)
	if sumoID := os.Getenv("SUMO_UID"); sumoID != "" {
		return sumoID
	}
	return ""
}

// checkSumoLogic memeriksa indikator Sumo Logic container
func (c *IdentityCollector) checkSumoLogic() bool {
	// Sumo Logic container biasanya memiliki environment variables
	if os.Getenv("SUMO_ACCESS_ID") != "" || os.Getenv("SUMO_ACCESS_KEY") != "" {
		return true
	}

	// Check for sumo-specific files
	if _, err := os.Stat("/opt/SumoCollector"); err == nil {
		return true
	}

	return false
}

// getCPUID mengambil CPU ID berdasarkan OS
func (c *IdentityCollector) getCPUID() string {
	switch runtime.GOOS {
	case "linux":
		return c.getCPUIDLinux()
	case "darwin":
		return c.getCPUIDDarwin()
	case "windows":
		return c.getCPUIDWindows()
	default:
		return "unknown"
	}
}

// getCPUIDLinux mengambil CPU ID dari Linux
func (c *IdentityCollector) getCPUIDLinux() string {
	// Try to read from /proc/cpuinfo
	content, err := os.ReadFile("/proc/cpuinfo")
	if err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "serial") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
	}
	// Fallback: use system UUID
	content, _ = os.ReadFile("/sys/class/dmi/id/product_uuid")
	if len(content) > 0 {
		return strings.TrimSpace(string(content))
	}
	return "unknown"
}

// getCPUIDDarwin mengambil CPU ID dari macOS
func (c *IdentityCollector) getCPUIDDarwin() string {
	// Try to read from IOPlatformSerialNumber
	output, err := os.CreateTemp("", "serial")
	if err == nil {
		output.Close()
		os.Remove(output.Name())
	}
	// Fallback: generate from system information
	return "darwin-" + c.getHostname()
}

// getCPUIDWindows mengambil CPU ID dari Windows
func (c *IdentityCollector) getCPUIDWindows() string {
	// On Windows, we could use WMI queries
	// For now, return a placeholder
	return "windows-" + c.getHostname()
}

// getMACAddress mengambil alamat MAC pertama yang ditemukan
func (c *IdentityCollector) getMACAddress() string {
	switch runtime.GOOS {
	case "linux":
		return c.getMACAddressLinux()
	case "darwin":
		return c.getMACAddressDarwin()
	case "windows":
		return c.getMACAddressWindows()
	default:
		return c.getMACAddressGeneric()
	}
}

// getMACAddressLinux mengambil MAC address dari Linux
func (c *IdentityCollector) getMACAddressLinux() string {
	// Try to read from /sys/class/net/*/address
	netPath := "/sys/class/net"
	files, err := os.ReadDir(netPath)
	if err != nil {
		return c.getMACAddressGeneric()
	}

	for _, file := range files {
		if file.IsDir() && file.Name() != "lo" { // Skip loopback
			addressPath := netPath + "/" + file.Name() + "/address"
			content, err := os.ReadFile(addressPath)
			if err == nil {
				mac := strings.TrimSpace(string(content))
				// Validate MAC address format (XX:XX:XX:XX:XX:XX)
				if c.isValidMAC(mac) && mac != "00:00:00:00:00:00" {
					return mac
				}
			}
		}
	}

	return c.getMACAddressGeneric()
}

// getMACAddressDarwin mengambil MAC address dari macOS
func (c *IdentityCollector) getMACAddressDarwin() string {
	// Use sysctl to get MAC address
	// Run: sysctl -n hw.macaddr
	cmd := "sysctl"
	args := []string{"-n", "hw.macaddr"}
	output, err := executeCommand(cmd, args)
	if err == nil {
		mac := strings.TrimSpace(string(output))
		// Convert binary format to standard MAC format
		if len(mac) == 17 && c.isValidMAC(mac) {
			return mac
		}
	}

	// Fallback: try to read from network interfaces
	if mac := c.getMACFromInterfaceDarwin(); mac != "" {
		return mac
	}

	return c.getMACAddressGeneric()
}

// getMACFromInterfaceDarwin mengambil MAC dari /etc/ or network interface
func (c *IdentityCollector) getMACFromInterfaceDarwin() string {
	// Try reading from /etc/ directory or use network calls
	// For now, use a fallback method
	return ""
}

// getMACAddressWindows mengambil MAC address dari Windows
func (c *IdentityCollector) getMACAddressWindows() string {
	// On Windows, use WMI query via powershell
	cmd := "powershell"
	args := []string{
		"-Command",
		`Get-NetAdapter | Where-Object {$_.PhysicalAdapter -eq $true} | Select-Object -ExpandProperty MacAddress | Select-Object -First 1`,
	}
	output, err := executeCommand(cmd, args)
	if err == nil {
		mac := strings.TrimSpace(string(output))
		if c.isValidMAC(mac) && mac != "" {
			return strings.ToUpper(mac)
		}
	}

	return c.getMACAddressGeneric()
}

// getMACAddressGeneric fallback MAC address
func (c *IdentityCollector) getMACAddressGeneric() string {
	// Return a stable placeholder based on hostname
	// This ensures consistency even if MAC detection fails
	return "02:00:00:00:00:00"
}

// executeCommand menjalankan command shell dan mengembalikan output
func executeCommand(cmd string, args []string) ([]byte, error) {
	// For now, return placeholder
	// In production, use exec.Command from os/exec package
	return nil, fmt.Errorf("not implemented")
}

// isValidMAC memvalidasi format MAC address
func (c *IdentityCollector) isValidMAC(mac string) bool {
	// MAC address format: XX:XX:XX:XX:XX:XX atau XX-XX-XX-XX-XX-XX
	pattern := `^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$`
	matched, _ := regexp.MatchString(pattern, mac)
	return matched
}

// GetMACAddressForSystem adalah helper untuk mendapatkan MAC address sistem secara akurat
func GetMACAddressForSystem() (string, error) {
	collector := NewIdentityCollector()
	return collector.getMACAddress(), nil
}

// getInstanceID mengambil Instance ID dari cloud provider
func (c *IdentityCollector) getInstanceID() string {
	// AWS
	if content, err := os.ReadFile("/sys/hypervisor/uuid"); err == nil {
		if bytes.HasPrefix(content, []byte("ec2")) {
			return string(bytes.TrimSpace(content))
		}
	}
	// Alibaba Cloud
	if content, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
		if bytes.HasPrefix(content, []byte("ali")) {
			return string(bytes.TrimSpace(content))
		}
	}
	// Google Cloud Platform (GCP)
	if content, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
		if strings.Contains(string(content), "Google") {
			return string(bytes.TrimSpace(content))
		}
	}
	// Sumo Logic (sumopod) - read from environment or metadata
	if sumoID := os.Getenv("SUMO_UID"); sumoID != "" {
		return sumoID
	}
	return "local"
}

// getHostname mengambil hostname sistem
func (c *IdentityCollector) getHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

// getSystemUUID mengambil system UUID dari DMI/SMBIOS
func (c *IdentityCollector) getSystemUUID() string {
	// Try Linux DMI
	content, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if err == nil {
		return strings.TrimSpace(string(content))
	}

	// Try macOS IOPlatformUUID
	if runtime.GOOS == "darwin" {
		content, err = os.ReadFile("/sys/class/dmi/id/product_uuid")
		if err == nil && len(strings.TrimSpace(string(content))) > 0 {
			return strings.TrimSpace(string(content))
		}
	}

	// Fallback: use persistent store
	store := persistent.NewStore()

	// Cek apakah sudah ada UUID
	if uuid, ok := store.Get("uuid"); ok {
		return uuid
	}

	// Collect metadata untuk deteksi server change
	currentMAC := c.getMACAddress()

	// Generate UUID baru
	uuid, err := generateStableUUID(c.getHostname())
	if err != nil {
		return "stable-" + c.getHostname()
	}

	// Save ke store dengan metadata
	metadata := map[string]string{
		"hostname":    c.getHostname(),
		"mac_address": currentMAC,
		"os":          runtime.GOOS,
	}
	if err := store.Save("uuid", uuid, metadata); err != nil {
		return "stable-" + c.getHostname()
	}

	return uuid
}

// generateStableUUID menggenerate UUID stabil berdasarkan hostname
func generateStableUUID(hostname string) (string, error) {
	return persistent.GenerateStableUUID(hostname)
}
