package persistent

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/crypto/sha3"
)

// PersistentStore menyimpan UUID secara persisten
type PersistentStore struct {
	filePath    string
	enabled     bool
	data        map[string]interface{}
	mu          sync.RWMutex
	initialized bool
}

// StoreData represent data yang disimpan
type StoreData struct {
	UUID      string `json:"uuid"`
	CreatedAt string `json:"created_at"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	MAC       string `json:"mac_address"`
}

var (
	_instance *PersistentStore
	_once     sync.Once
)

// Option func untuk konfigurasi
type Option func(*PersistentStore)

// WithEnabled mengaktifkan persistent storage (default)
func WithEnabled() Option {
	return func(s *PersistentStore) {
		s.enabled = true
	}
}

// WithDisabled menonaktifkan persistent storage
func WithDisabled() Option {
	return func(s *PersistentStore) {
		s.enabled = false
	}
}

// NewStore membuat instance baru dengan opsi konfigurasi
func NewStore(opts ...Option) *PersistentStore {
	_once.Do(func() {
		_instance = &PersistentStore{
			filePath: getStorePath(),
			enabled:  true, // default enabled
			data:     make(map[string]interface{}),
		}

		for _, opt := range opts {
			opt(_instance)
		}

		if _instance.enabled {
			_instance.load()
		}
	})
	return _instance
}

// getStorePath mendapatkan path file tersembunyi
func getStorePath() string {
	home, _ := os.UserHomeDir()

	// Generate nama file random yang sulit ditebak
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	fileName := ".sf_" + base64.URLEncoding.EncodeToString(randBytes)[:20]

	return filepath.Join(home, fileName)
}

// load memuat data dari file
func (s *PersistentStore) load() {
	if !s.initialized {
		s.mu.Lock()
		defer s.mu.Unlock()

		if s.initialized {
			return
		}

		content, err := os.ReadFile(s.filePath)
		if err != nil {
			s.initialized = true
			return
		}

		// Decrypt content
		encrypted := strings.TrimSpace(string(content))
		decrypted, err := s.xorDecrypt(encrypted)
		if err != nil {
			s.initialized = true
			return
		}

		json.Unmarshal([]byte(decrypted), &s.data)
		s.initialized = true
	}
}

// DetectServerChange mendeteksi apakah server berubah
func (s *PersistentStore) DetectServerChange(currentHostname, currentMAC string) (bool, map[string]interface{}) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.data == nil {
		return false, nil
	}

	changed := false
	details := make(map[string]interface{})

	// Check hostname
	if storedHostname, ok := s.data["hostname"].(string); ok && storedHostname != currentHostname {
		changed = true
		details["changed_field"] = "hostname"
		details["old_hostname"] = storedHostname
		details["new_hostname"] = currentHostname
	}

	// Check MAC
	if storedMAC, ok := s.data["mac_address"].(string); ok && storedMAC != currentMAC {
		changed = true
		details["changed_field"] = "mac_address"
		details["old_mac"] = storedMAC
		details["new_mac"] = currentMAC
	}

	// Check OS
	if storedOS, ok := s.data["os"].(string); ok && storedOS != runtime.GOOS {
		changed = true
		details["changed_field"] = "os"
		details["old_os"] = storedOS
		details["new_os"] = runtime.GOOS
	}

	return changed, details
}

// Save menyimpan UUID ke file
func (s *PersistentStore) Save(key, value string, extraData ...map[string]string) error {
	if !s.enabled {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.data == nil {
		s.data = make(map[string]interface{})
	}

	s.data[key] = value

	// Add metadata untuk deteksi perubahan server
	if s.data["created_at"] == nil {
		s.data["created_at"] = getCurrentTimestamp()
	}
	if len(extraData) > 0 && extraData[0] != nil {
		for k, v := range extraData[0] {
			s.data[k] = v
		}
	} else {
		// Auto-fill metadata
		s.data["hostname"] = getCurrentHostname()
		s.data["mac_address"] = "unknown"
		s.data["os"] = runtime.GOOS
	}

	// Encrypt dan simpan
	jsonData, _ := json.Marshal(s.data)
	encrypted := s.xorEncrypt(string(jsonData))

	return os.WriteFile(s.filePath, []byte(encrypted), 0600)
}

// getCurrentHostname adalah helper untuk mendapatkan hostname
func getCurrentHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

// getCurrentTimestamp adalah helper untuk mendapatkan timestamp saat ini
func getCurrentTimestamp() string {
	return "2026-09-22T00:00:00Z" // Placeholder
}

// Get mendapatkan nilai dari store
func (s *PersistentStore) Get(key string) (string, bool) {
	if !s.enabled {
		return "", false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.data == nil {
		return "", false
	}

	val, ok := s.data[key].(string)
	return val, ok
}

// GetAsMap mendapatkan semua data sebagai map
func (s *PersistentStore) GetAsMap() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.data == nil {
		return nil
	}

	result := make(map[string]interface{})
	for k, v := range s.data {
		result[k] = v
	}
	return result
}

// xorEncrypt menggunakan XOR cipher sederhana (bukan untuk keamanan tinggi)
func (s *PersistentStore) xorEncrypt(data string) string {
	if len(data) == 0 {
		return ""
	}

	// Simple XOR dengan key yang derived dari hostname
	key := []byte("server_fingerprint_key_v1")
	result := make([]byte, len(data))

	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key[i%len(key)]
	}

	return base64.StdEncoding.EncodeToString(result)
}

// xorDecrypt untuk dekripsi XOR
func (s *PersistentStore) xorDecrypt(encrypted string) (string, error) {
	if len(encrypted) == 0 {
		return "", nil
	}

	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	key := []byte("server_fingerprint_key_v1")
	result := make([]byte, len(data))

	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key[i%len(key)]
	}

	return string(result), nil
}

// GenerateOrLoadUUID mengenerate UUID baru atau load yang sudah ada
func (s *PersistentStore) GenerateOrLoad() (string, error) {
	hostname, _ := os.Hostname()

	// Cek apakah sudah ada UUID
	if uuid, ok := s.Get("uuid"); ok {
		return uuid, nil
	}

	// Generate UUID baru
	uuid, err := generateStableUUID(hostname)
	if err != nil {
		return "", err
	}

	// Save ke store
	if err := s.Save("uuid", uuid); err != nil {
		return "", err
	}

	return uuid, nil
}

// generateStableUUID menggenerate UUID stabil berdasarkan hostname
func generateStableUUID(hostname string) (string, error) {
	// Use hostname untuk uniqueness
	data := hostname

	// SHA3-256 hash
	hash := sha3.Sum256([]byte(data))

	// Format sebagai UUID (v4-like)
	return formatAsUUID(hash[:]), nil
}

// GenerateStableUUID adalah exported version untuk digunakan di luar package
func GenerateStableUUID(hostname string) (string, error) {
	data := hostname

	// SHA3-256 hash
	hash := sha3.Sum256([]byte(data))

	// Format sebagai UUID (v4-like)
	return formatAsUUID(hash[:]), nil
}

// formatAsUUID memformat hash sebagai UUID
func formatAsUUID(hash []byte) string {
	// Format hash sebagai UUID v4-like
	uuid := make([]byte, 36)
	copy(uuid, hash[:8])
	uuid[8] = '-'
	copy(uuid[9:], hash[8:12])
	uuid[13] = '-'
	copy(uuid[14:], hash[12:16])
	uuid[17] = '-'
	copy(uuid[18:], hash[16:20])
	uuid[21] = '-'
	copy(uuid[22:], hash[20:32])

	return string(uuid)
}

// Disable menonaktifkan persistent storage secara runtime
func (s *PersistentStore) Disable() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = false
}

// Enable mengaktifkan persistent storage secara runtime
func (s *PersistentStore) Enable() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = true
}

// IsEnabled mengecek apakah persistent storage aktif
func (s *PersistentStore) IsEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}

// GetFilePath mendapatkan path file persistent (untuk debugging/visibility)
func (s *PersistentStore) GetFilePath() string {
	return s.filePath
}
