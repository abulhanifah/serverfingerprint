package collector

// Environment represents detected server environment
type Environment struct {
	Type      string `json:"type"`      // PC, CloudVM, VM
	Provider  string `json:"provider"`  // AWS, GCP, Alibaba, SumoLogic, VMware, VirtualBox, Generic
	IsVirtual bool   `json:"isVirtual"` // Whether it's a virtual machine
	IsCloud   bool   `json:"isCloud"`   // Whether it's running in cloud
}

// Identity represents server identity data
type Identity struct {
	CPUID      string `json:"cpu_id"`
	MACAddress string `json:"mac_address"`
	InstanceID string `json:"instance_id"`
	Hostname   string `json:"hostname"`
	SystemUUID string `json:"system_uuid"`
	ProviderID string `json:"provider_id"` // Cloud-specific instance ID
}
