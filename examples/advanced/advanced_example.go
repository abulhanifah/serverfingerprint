package main

import (
	"fmt"
	"log"

	"serverfingerprint/internal/engine"
)

func main() {
	// Create new fingerprint engine directly
	fingerprintEngine := engine.NewFingerprintEngine("your-secret-key-here")

	// Collect and generate fingerprint
	fp, err := fingerprintEngine.Generate()
	if err != nil {
		log.Fatal("Failed to generate fingerprint:", err)
	}

	fmt.Println("Server Fingerprint:", fp)

	// Get collected data
	identity := fingerprintEngine.GetIdentity()
	environment := fingerprintEngine.GetEnvironment()

	// Display identity
	fmt.Println("\nIdentity:")
	fmt.Printf("  CPU ID: %s\n", identity.CPUID)
	fmt.Printf("  MAC Address: %s\n", identity.MACAddress)
	fmt.Printf("  Instance ID: %s\n", identity.InstanceID)
	fmt.Printf("  Hostname: %s\n", identity.Hostname)

	// Display environment
	fmt.Println("\nEnvironment:")
	fmt.Printf("  Type: %s\n", environment.Type)
	fmt.Printf("  Provider: %s\n", environment.Provider)
	fmt.Printf("  Is Virtual: %v\n", environment.IsVirtual)
	fmt.Printf("  Is Cloud: %v\n", environment.IsCloud)

	// Test with different secret key
	fmt.Println("\n--- Testing with different secret key ---")
	newFP, err := fingerprintEngine.ReGenerate("new-secret-key")
	if err != nil {
		log.Fatal("Failed to regenerate:", err)
	}
	fmt.Println("New Fingerprint:", newFP)
}
