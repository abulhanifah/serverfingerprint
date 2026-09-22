package collector

import (
	"bytes"
	"os"
	"strings"
)

// EnvironmentDetector mendeteksi lingkungan server
type EnvironmentDetector struct{}

// NewEnvironmentDetector membuat instance baru dari EnvironmentDetector
func NewEnvironmentDetector() *EnvironmentDetector {
	return &EnvironmentDetector{}
}

// Detect mendeteksi environment server
func (d *EnvironmentDetector) Detect() (*Environment, error) {
	environment := &Environment{}

	// Detect environment type
	environment.Type = d.detectEnvironmentType()

	// Detect provider
	environment.Provider = d.detectProvider()

	// Set virtual/cloud flags
	environment.IsVirtual = d.isVirtualMachine()
	environment.IsCloud = d.isCloudEnvironment()

	return environment, nil
}

// detectEnvironmentType mendeteksi tipe environment (PC, VM, Cloud VM)
func (d *EnvironmentDetector) detectEnvironmentType() string {
	if d.isCloudEnvironment() {
		return "CloudVM"
	}
	if d.isVirtualMachine() {
		return "VM"
	}
	return "PC"
}

// detectProvider mendeteksi cloud provider jika ada
func (d *EnvironmentDetector) detectProvider() string {
	// AWS
	if content, err := os.ReadFile("/sys/hypervisor/uuid"); err == nil {
		if bytes.HasPrefix(content, []byte("ec2")) {
			return "AWS"
		}
	}

	// Alibaba Cloud
	if content, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
		if bytes.HasPrefix(content, []byte("ali")) {
			return "AlibabaCloud"
		}
	}

	// Google Cloud Platform (GCP)
	if d.checkGCPMetadata() {
		return "GCP"
	}

	// Sumo Logic (sumopod) - Check for sumo-specific indicators
	if d.checkSumoLogic() {
		return "SumoLogic"
	}

	// Check for other cloud providers
	if d.checkVMIndicator("vmware") {
		return "VMware"
	}
	if d.checkVMIndicator("virtualbox") {
		return "VirtualBox"
	}
	if d.checkVMIndicator("qemu") {
		return "QEMU"
	}

	return "Generic"
}

// checkGCPMetadata memeriksa metadata GCP
func (d *EnvironmentDetector) checkGCPMetadata() bool {
	// GCP metadata server
	if content, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		if strings.Contains(string(content), "Google") || strings.Contains(string(content), "Google Compute Engine") {
			return true
		}
	}

	// Check GCP instance ID file
	if content, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
		if strings.Contains(string(content), "Google") {
			return true
		}
	}

	return false
}

// checkSumoLogic memeriksa indikator Sumo Logic container
func (d *EnvironmentDetector) checkSumoLogic() bool {
	// Check for sumo-specific files or environment variables
	_, err := os.Stat("/.sumologic")
	if err == nil {
		return true
	}

	// Check environment variables
	if os.Getenv("SUMO_LOGIC") != "" || os.Getenv("SUMO_UID") != "" {
		return true
	}

	return false
}

// checkVMIndicator memeriksa indikator VM tertentu
func (d *EnvironmentDetector) checkVMIndicator(productName string) bool {
	content, err := os.ReadFile("/sys/class/dmi/id/product_name")
	if err == nil {
		return strings.Contains(strings.ToLower(string(content)), productName)
	}
	return false
}

// isVirtualMachine mendeteksi apakah ini adalah VM
func (d *EnvironmentDetector) isVirtualMachine() bool {
	// Check for virtualization indicators
	if d.checkVMIndicator("virtualbox") ||
		d.checkVMIndicator("vmware") ||
		d.checkVMIndicator("qemu") ||
		d.checkVMIndicator("kvm") {
		return true
	}

	// Check hypervisor
	content, err := os.ReadFile("/sys/hypervisor/type")
	if err == nil && strings.TrimSpace(string(content)) != "" {
		return true
	}

	return false
}

// isCloudEnvironment mendeteksi apakah ini adalah cloud environment
func (d *EnvironmentDetector) isCloudEnvironment() bool {
	// AWS
	if content, err := os.ReadFile("/sys/hypervisor/uuid"); err == nil {
		if bytes.HasPrefix(content, []byte("ec2")) {
			return true
		}
	}

	// Alibaba Cloud
	if content, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
		if bytes.HasPrefix(content, []byte("ali")) {
			return true
		}
	}

	// Google Cloud Platform (GCP)
	if d.checkGCPMetadata() {
		return true
	}

	// Sumo Logic (sumopod)
	if d.checkSumoLogic() {
		return true
	}

	return false
}

// GetMACAddress adalah helper untuk mendapatkan MAC address
// untuk penggunaan di luar collector
func GetMACAddress() string {
	collector := NewIdentityCollector()
	return collector.getMACAddress()
}
