# Server Fingerprint Library

Library Golang untuk menghasilkan fingerprint server yang unik berdasarkan identitas perangkat dan environment.

## Features

- Deteksi environment (PC, Cloud VM, VirtualBox, VMware, GCP, SumoLogic)
- Collect identitas: CPU ID, MAC Address, Instance ID, Hostname, Provider ID
- Normalisasi dan canonicalisasi data
- HMAC-SHA256 untuk keamanan
- Support untuk multiple cloud provider: AWS, GCP, Alibaba Cloud, SumoLogic
- Persistent UUID storage dengan enkripsi XOR
- Server change detection
- Client-Provider validation via HTTP API

## Installation

```bash
go get serverfingerprint
```

## Usage

### Basic Usage

```go
package main

import (
    "fmt"
    "log"

    "serverfingerprint/pkg"
)

func main() {
    // Create new fingerprint engine with a secret key
    fingerprint := pkg.NewServerFingerprint("your-secret-key-here")

    // Generate fingerprint
    fp, err := fingerprint.GenerateFingerprint()
    if err != nil {
        log.Fatal("Failed to generate fingerprint:", err)
    }

    fmt.Println("Server Fingerprint:", fp)

    // Get identity information
    identity := fingerprint.GetIdentity()
    fmt.Printf("Hostname: %s\n", identity.Hostname)
    fmt.Printf("Provider ID: %s\n", identity.ProviderID)

    // Get environment information
    environment := fingerprint.GetEnvironment()
    fmt.Printf("Environment Type: %s\n", environment.Type)
    fmt.Printf("Provider: %s\n", environment.Provider)
}
```

### Advanced Usage - Client-Provider Validation

**Server Klien:**
```go
client := validation.NewClient("http://provider.example.com", "server-001", "secret-key")
isValid, err := client.ValidateServer()
if !isValid {
    // Block application
    log.Fatal("Invalid server")
}
```

**Server Provider:**
```go
provider := validation.NewProvider()
provider.StartServer("8080")
```

## Supported Cloud Providers

| Provider | Environment Type | Detection Method |
|----------|------------------|------------------|
| AWS | CloudVM | `/sys/hypervisor/uuid` (ec2 prefix) |
| GCP | CloudVM | `/sys/class/dmi/id/product_uuid` (Google) |
| Alibaba Cloud | CloudVM | `/sys/class/dmi/id/product_uuid` (ali prefix) |
| SumoLogic | CloudVM | Environment variables (`SUMO_UID`) |
| VMware | VM | DMI product name |
| VirtualBox | VM | DMI product name |
| Generic | PC | Physical machine |

## Project Structure

```
serverfingerprint/
├── internal/
│   ├── engine/      # Main fingerprint engine
│   ├── collector/   # Data collectors
│   ├── persistent/  # Persistent storage
│   └── utils/       # Utilities for normalization
├── pkg/             # Public API
└── examples/        # Example usage
    ├── basic/       # Basic usage
    ├── advanced/    # Advanced usage
    └── validation/  # Client-Provider validation
```

## Environment Detection

| Type | Provider | Description |
|------|----------|-------------|
| PC | Generic | Physical computer |
| VM | VMware/VirtualBox | Virtual machine |
| CloudVM | AWS | Amazon EC2 instance |
| CloudVM | GCP | Google Compute Engine |
| CloudVM | AlibabaCloud | Alibaba ECS instance |
| CloudVM | SumoLogic | Sumo Logic container |

## Cloud Provider References

### AWS EC2
- [Instance Identity Documents](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html)
- [Instance Metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
- Detection: `/sys/hypervisor/uuid` contains "ec2" prefix

### Google Cloud Platform (GCP)
- [Instance Metadata](https://cloud.google.com/compute/docs/metadata/default-metadata-values)
- [Instance Identity](https://cloud.google.com/compute/docs/instances/verifying-instance-identity)
- Detection: `/sys/class/dmi/id/product_uuid` contains "Google"

### Alibaba Cloud ECS
- [Instance Information](https://help.aliyun.com/document_detail/54152.html)
- Detection: `/sys/class/dmi/id/product_uuid` contains "ali" prefix

### Sumo Logic
- [Collector Docker Image](https://github.com/SumoLogic/sumologic-collector-docker)
- [Collector Configuration](https://help.sumologic.com/docs/send-data/installed-collectors/)
- Detection: Environment variable `SUMO_UID` or file `/opt/SumoCollector`

### VMware
- Detection: `/sys/class/dmi/id/product_name` contains "VMware"

### VirtualBox
- Detection: `/sys/class/dmi/id/product_name` contains "VirtualBox"

## API Reference

### ServerFingerprint

- `NewServerFingerprint(secretKey string)` - Create new fingerprint instance
- `GenerateFingerprint() (string, error)` - Generate server fingerprint
- `GetIdentity() *collector.Identity` - Get collected identity
- `GetEnvironment() *collector.Environment` - Get detected environment
- `ReGenerateFingerprint(secretKey string) (string, error)` - Regenerate with new key

### Identity

- `CPUID` - CPU identifier
- `MACAddress` - MAC address of network interface
- `InstanceID` - Cloud instance identifier
- `Hostname` - System hostname
- `SystemUUID` - System UUID (persistent)
- `ProviderID` - Provider-specific instance ID (GCP, Sumo, etc.)

### Environment

- `Type` - Environment type (PC/VM/CloudVM)
- `Provider` - Cloud provider or vendor
- `IsVirtual` - Whether running in VM
- `IsCloud` - Whether running in cloud

## Persistent Storage

UUID disimpan di file tersembunyi di home directory:
- macOS/Linux: `~/.sf_xxx`
- File permissions: `0600`
- Data terenkripsi dengan XOR cipher

## Server Change Detection

Sistem mendeteksi perubahan server berdasarkan:
- **Hostname** berubah
- **MAC Address** berubah
- **OS** berubah

```go
store := persistent.NewStore()
changed, details := store.DetectServerChange(currentHostname, currentMAC)
if changed {
    // Server changed - generate new UUID
}
```

## Security Notes

- Secret key harus disimpan dengan aman
- Fingerprint dapat di-regenerate dengan secret key baru
- Data identitas tidak disimpan secara permanen di client

## License

MIT
