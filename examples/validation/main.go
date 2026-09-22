package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"serverfingerprint/pkg"
	"syscall"
	"time"
)

// ValidationRequest represent request ke server provider
type ValidationRequest struct {
	ServerID    string `json:"server_id"`
	Fingerprint string `json:"fingerprint"`
}

// ValidationResponse represent response dari server provider
type ValidationResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
}

// Provider represent server provider yang menyimpan fingerprint
type Provider struct {
	storage map[string]string
}

// NewProvider membuat provider baru
func NewProvider() *Provider {
	return &Provider{
		storage: make(map[string]string),
	}
}

// RegisterServer mendaftarkan server baru ke database
func (p *Provider) RegisterServer(serverID, fingerprint string) error {
	p.storage[serverID] = fingerprint
	return nil
}

// ValidateFingerprint memvalidasi fingerprint server
func (p *Provider) ValidateFingerprint(serverID, fingerprint string) (bool, string) {
	// Cek apakah server terdaftar
	storedFP, exists := p.storage[serverID]
	if !exists {
		return false, "Server tidak terdaftar"
	}

	// Bandingkan fingerprint
	if storedFP == fingerprint {
		return true, "Valid"
	}

	return false, "Fingerprint tidak cocok - server berubah atau tidak valid"
}

// API Handlers
func (p *Provider) HandleValidate(w http.ResponseWriter, r *http.Request) {
	var request ValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	isValid, message := p.ValidateFingerprint(request.ServerID, request.Fingerprint)

	response := ValidationResponse{
		Valid:   isValid,
		Message: message,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// RegisterServerAPI endpoint untuk register server baru
func (p *Provider) RegisterServerAPI(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ServerID    string `json:"server_id"`
		Fingerprint string `json:"fingerprint"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if err := p.RegisterServer(request.ServerID, request.Fingerprint); err != nil {
		http.Error(w, "Failed to register server", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "registered"})
}

// Client represent server klien
type Client struct {
	engine    *pkg.ServerFingerprint
	serverURL string
	serverID  string
	secretKey string
}

// NewClient membuat client baru
func NewClient(serverURL, serverID, secretKey string) *Client {
	return &Client{
		serverURL: serverURL,
		serverID:  serverID,
		secretKey: secretKey,
	}
}

// GenerateFingerprint menghasilkan fingerprint dari server lokal
func (c *Client) GenerateFingerprint() (string, error) {
	c.engine = pkg.NewServerFingerprint(c.secretKey)

	fp, err := c.engine.GenerateFingerprint()
	if err != nil {
		return "", err
	}

	return fp, nil
}

func main() {
	fmt.Println("=== Server Fingerprint Validation Demo ===\n")

	// Setup provider (database server)
	fmt.Println("Starting Provider Server...")
	provider := NewProvider()
	go func() {
		http.HandleFunc("/validate", provider.HandleValidate)
		http.HandleFunc("/register", provider.RegisterServerAPI)
		http.ListenAndServe(":8080", nil)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Register server pertama kali
	fmt.Println("\n--- Register Server 1 ---")
	fp1 := "fingerprint-server-1-secret"
	err := provider.RegisterServer("server-001", fp1)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("Server 'server-001' registered with fingerprint: %s\n", fp1)

	// Simulate client dengan server yang sama
	fmt.Println("\n--- Client Validation (Same Server) ---")
	client1 := NewClient("http://localhost:8080", "server-001", "secret-key")
	fp, _ := client1.GenerateFingerprint()
	fmt.Printf("Client fingerprint: %s\n", fp)

	// Manually validate (simulasi karena fingerprint berbeda)
	valid, msg := provider.ValidateFingerprint("server-001", fp1)
	fmt.Printf("Validation: %v - %s\n", valid, msg)

	// Simulate klien dengan fingerprint yang benar
	fmt.Println("\n--- Client Validation (Correct Fingerprint) ---")
	valid, msg = provider.ValidateFingerprint("server-001", fp1)
	fmt.Printf("Validation: %v - %s\n", valid, msg)

	// Simulate server change
	fmt.Println("\n--- Client Validation (Different Fingerprint - Server Changed) ---")
	wrongFP := "wrong-fingerprint-server-1"
	valid, msg = provider.ValidateFingerprint("server-001", wrongFP)
	fmt.Printf("Validation: %v - %s\n", valid, msg)

	// Demo HTTP request
	fmt.Println("\n--- HTTP Request Demo ---")
	demoHTTPValidation()

	// Setup signal handler untuk graceful shutdown
	fmt.Println("\n--- Running Provider Server (Ctrl+C to stop) ---")
	setupSignalHandler()
}

func demoHTTPValidation() {
	// Prepare request
	request := ValidationRequest{
		ServerID:    "server-001",
		Fingerprint: "fingerprint-server-1-secret",
	}

	jsonData, _ := json.Marshal(request)

	// Send request
	resp, err := http.Post("http://localhost:8080/validate", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Response: %s\n", string(body))
}

func setupSignalHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	fmt.Println("\nShutting down...")
	os.Exit(0)
}
