package mdoc

import (
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/davecgh/go-spew/spew"
)

func GetRootCertificates(path string) (*x509.CertPool, error) {
	spew.Dump(path)
	pems, err := loadCertificatesFromDirectory(path)
	if err != nil {
		return nil, err
	}

	roots := x509.NewCertPool()

	for name, pem := range pems {
		if ok := roots.AppendCertsFromPEM(pem); !ok {
			fmt.Println("failed to load pem: " + name)
		}
	}
	return roots, nil
}

func loadCertificatesFromDirectory(dirPath string) (map[string][]byte, error) {
	pems := map[string][]byte{}

	// Read files in directory
	files, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	// Iterate over files
	for _, file := range files {
		if file.IsDir() {
			continue // skip directories
		}
		if strings.HasSuffix(file.Name(), ".pem") {
			filePath := filepath.Join(dirPath, file.Name())
			data, err := os.ReadFile(filePath)
			if err != nil {
				log.Printf("Failed to read file: %s, err: %v", filePath, err)
				continue // continue with other files even if one fails
			}
			pems[file.Name()] = data
		}
	}
	return pems, nil
}
