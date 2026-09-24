package main

import (
	"fmt"
	"log"

	"github.com/abulhanifah/serverfingerprint/internal/persistent"
	"github.com/abulhanifah/serverfingerprint/pkg"
)

func main() {
	// Option 1: Dengan persistent storage (default)
	fmt.Println("=== Dengan Persistent Storage ===")
	fingerprint := pkg.NewServerFingerprint("your-secret-key-here")

	// Generate fingerprint
	fp, err := fingerprint.GenerateFingerprint()
	if err != nil {
		log.Fatal("Failed to generate fingerprint:", err)
	}

	fmt.Println("Server Fingerprint:", fp)

	// Get identity information
	identity := fingerprint.GetIdentity()
	fmt.Printf("CPU ID: %s\n", identity.CPUID)
	fmt.Printf("MAC Address: %s\n", identity.MACAddress)
	fmt.Printf("Instance ID: %s\n", identity.InstanceID)
	fmt.Printf("Hostname: %s\n", identity.Hostname)
	fmt.Printf("System UUID: %s\n", identity.SystemUUID)

	// Get environment information
	environment := fingerprint.GetEnvironment()
	fmt.Printf("Environment Type: %s\n", environment.Type)
	fmt.Printf("Provider: %s\n", environment.Provider)
	fmt.Printf("Is Virtual: %v\n", environment.IsVirtual)
	fmt.Printf("Is Cloud: %v\n", environment.IsCloud)

	// Check server change detection
	fmt.Println("\n=== Server Change Detection ===")
	store := persistent.NewStore()
	changed, details := store.DetectServerChange(identity.Hostname, identity.MACAddress)
	if changed {
		fmt.Println("Server changed detected!")
		fmt.Printf("Details: %+v\n", details)
		fmt.Println("\nRecommendation: Generate new UUID for this server")
	} else {
		fmt.Println("Same server - UUID valid")
	}

	// Show persistent storage location (for debugging)
	fmt.Printf("\nPersistent storage location: %s\n", store.GetFilePath())
}
