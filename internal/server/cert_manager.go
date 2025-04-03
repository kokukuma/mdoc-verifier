package server

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// CertManager manages root certificates
type CertManager struct {
	mu       sync.RWMutex
	pemsDir  string
	certPool *x509.CertPool
}

// CertInfo contains information about a certificate
type CertInfo struct {
	Filename    string `json:"filename"`
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	ValidFrom   string `json:"valid_from"`
	ValidTo     string `json:"valid_to"`
	Fingerprint string `json:"fingerprint"`
}

// NewCertManager creates a new certificate manager
func NewCertManager(pemsDir string) (*CertManager, error) {
	cm := &CertManager{
		pemsDir: pemsDir,
	}
	
	// Initialize certificate pool
	err := cm.ReloadCertificates()
	if err != nil {
		return nil, err
	}
	
	return cm, nil
}

// GetCertPool returns the current certificate pool
func (cm *CertManager) GetCertPool() *x509.CertPool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.certPool
}

// ReloadCertificates reloads all certificates from the pems directory
func (cm *CertManager) ReloadCertificates() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	return cm.reloadCertificatesNoLock()
}

// reloadCertificatesNoLock reloads all certificates without acquiring the lock
// This should only be called when the lock is already held
func (cm *CertManager) reloadCertificatesNoLock() error {
	// Create a new cert pool
	certPool := x509.NewCertPool()
	
	// Read all .pem files from the directory
	files, err := os.ReadDir(cm.pemsDir)
	if err != nil {
		return fmt.Errorf("failed to read certificates directory: %w", err)
	}
	
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".pem") {
			continue
		}
		
		filePath := filepath.Join(cm.pemsDir, file.Name())
		pemData, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("Failed to read certificate file %s: %v", filePath, err)
			continue
		}
		
		if ok := certPool.AppendCertsFromPEM(pemData); !ok {
			log.Printf("Failed to load certificate from %s", filePath)
		} else {
			log.Printf("Successfully loaded certificate from %s", filePath)
		}
	}
	
	// Update the cert pool
	cm.certPool = certPool
	return nil
}

// ListCertificates returns information about all certificates
func (cm *CertManager) ListCertificates() ([]CertInfo, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	var certs []CertInfo
	
	files, err := os.ReadDir(cm.pemsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificates directory: %w", err)
	}
	
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".pem") {
			continue
		}
		
		filePath := filepath.Join(cm.pemsDir, file.Name())
		pemData, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("Failed to read certificate file %s: %v", filePath, err)
			continue
		}
		
		// Parse certificate to extract information
		block, _ := pem.Decode(pemData)
		if block == nil || block.Type != "CERTIFICATE" {
			log.Printf("Failed to decode PEM data from %s", filePath)
			continue
		}
		
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Printf("Failed to parse certificate from %s: %v", filePath, err)
			continue
		}
		
		// Create fingerprint (SHA-256 hash)
		fingerprint := fmt.Sprintf("%X", cert.SubjectKeyId)
		
		certs = append(certs, CertInfo{
			Filename:    file.Name(),
			Subject:     cert.Subject.String(),
			Issuer:      cert.Issuer.String(),
			ValidFrom:   cert.NotBefore.Format("2006-01-02"),
			ValidTo:     cert.NotAfter.Format("2006-01-02"),
			Fingerprint: fingerprint,
		})
	}
	
	return certs, nil
}

// AddCertificate adds a new certificate
func (cm *CertManager) AddCertificate(filename string, certData []byte) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	// Validate PEM data
	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("invalid certificate data")
	}
	
	// Validate certificate can be parsed
	_, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("invalid certificate: %w", err)
	}
	
	// Ensure filename has .pem extension
	if !strings.HasSuffix(filename, ".pem") {
		filename = filename + ".pem"
	}
	
	// Write certificate to file
	filePath := filepath.Join(cm.pemsDir, filename)
	err = os.WriteFile(filePath, certData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}
	
	// Reload certificates without acquiring the lock again
	return cm.reloadCertificatesNoLock()
}

// DeleteCertificate deletes a certificate
func (cm *CertManager) DeleteCertificate(filename string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	// Ensure filename has .pem extension
	if !strings.HasSuffix(filename, ".pem") {
		filename = filename + ".pem"
	}
	
	// Delete the file
	filePath := filepath.Join(cm.pemsDir, filename)
	err := os.Remove(filePath)
	if err != nil {
		return fmt.Errorf("failed to delete certificate file: %w", err)
	}
	
	// Reload certificates without acquiring the lock again
	return cm.reloadCertificatesNoLock()
}

// GetCertificate returns a specific certificate
func (cm *CertManager) GetCertificate(filename string) (*CertInfo, []byte, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	// Ensure filename has .pem extension
	if !strings.HasSuffix(filename, ".pem") {
		filename = filename + ".pem"
	}
	
	filePath := filepath.Join(cm.pemsDir, filename)
	pemData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	
	// Parse certificate to extract information
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("failed to decode PEM data")
	}
	
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	
	// Create fingerprint
	fingerprint := fmt.Sprintf("%X", cert.SubjectKeyId)
	
	info := &CertInfo{
		Filename:    filename,
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		ValidFrom:   cert.NotBefore.Format("2006-01-02"),
		ValidTo:     cert.NotAfter.Format("2006-01-02"),
		Fingerprint: fingerprint,
	}
	
	return info, pemData, nil
}