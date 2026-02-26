package cryptoroot

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"hash"
	"log"
	"os"
)

const (
	criptRootDir = "internal/cryptoroot/pem"

	// Environment variable names for overriding Root CA paths
	envRootCAKeyPath  = "ROOT_CA_KEY_PATH"
	envRootCACertPath = "ROOT_CA_CERT_PATH"
)

var (
	defaultRootKeyPath  = fmt.Sprintf("%s/rootKey.pem", criptRootDir)
	defaultRootCertPath = fmt.Sprintf("%s/rootCert.pem", criptRootDir)
)

// getRootCAPaths returns the paths for Root CA key and certificate.
// If environment variables are set, they take precedence over defaults.
func getRootCAPaths() (keyPath, certPath string) {
	keyPath = os.Getenv(envRootCAKeyPath)
	if keyPath == "" {
		keyPath = defaultRootKeyPath
	}

	certPath = os.Getenv(envRootCACertPath)
	if certPath == "" {
		certPath = defaultRootCertPath
	}

	return keyPath, certPath
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil
}

func GenECDSAKeys() (*ecdsa.PrivateKey, []string, error) {
	var rootKey *ecdsa.PrivateKey
	var rootCert *x509.Certificate
	var rootDerBytes []byte
	var err error

	// Get Root CA paths (from environment variables or defaults)
	rootKeyPath, rootCertPath := getRootCAPaths()

	// Check if custom paths were provided via environment variables
	customPathsProvided := os.Getenv(envRootCAKeyPath) != "" || os.Getenv(envRootCACertPath) != ""

	if customPathsProvided {
		log.Printf("Using custom certificate paths: key=%s, cert=%s", rootKeyPath, rootCertPath)

		// When custom paths are provided, use the certificate directly as end-entity
		// (e.g., Apple-issued certificates should be used directly, not as Root CA)
		if fileExists(rootKeyPath) && fileExists(rootCertPath) {
			eeKey, err := readPEMFile(rootKeyPath)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read key from %s: %w", rootKeyPath, err)
			}
			eeCert, err := readCertificatePEM(rootCertPath)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read cert from %s: %w", rootCertPath, err)
			}

			// Use the certificate directly in x5chain (no Root CA needed for externally-issued certs)
			x5c := []string{
				base64.StdEncoding.EncodeToString(eeCert.Raw),
			}

			log.Printf("Using external certificate directly: subject=%s, issuer=%s", eeCert.Subject, eeCert.Issuer)
			return eeKey, x5c, nil
		}
		return nil, nil, fmt.Errorf("custom certificate paths specified but files not found: key=%s, cert=%s", rootKeyPath, rootCertPath)
	}

	// Default behavior: use internal Root CA and generate end-entity certificate
	if fileExists(rootKeyPath) && fileExists(rootCertPath) {
		log.Printf("Loading existing Root CA from: key=%s, cert=%s", rootKeyPath, rootCertPath)
		rootKey, err = readPEMFile(rootKeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read Root CA key from %s: %w", rootKeyPath, err)
		}
		rootCert, err = readCertificatePEM(rootCertPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read Root CA cert from %s: %w", rootCertPath, err)
		}
		rootDerBytes = rootCert.Raw
	} else {
		// Generate new root key and certificate (only when using default paths)
		log.Printf("Generating new Root CA at: key=%s, cert=%s", rootKeyPath, rootCertPath)
		rootKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		if err := writePEMFile(rootKey, rootKeyPath); err != nil {
			return nil, nil, err
		}

		rootCert, rootDerBytes, err = createRootCertificate(rootKey)
		if err != nil {
			return nil, nil, err
		}
		if err := writeCertificatePEM(rootCert, rootCertPath); err != nil {
			return nil, nil, err
		}
	}

	// generate endentity key and certificate
	eeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	_, eeDerBytes, err := createEndEntityCertificate(eeKey, rootCert, rootKey)
	if err != nil {
		return nil, nil, err
	}

	x5c := []string{
		base64.StdEncoding.EncodeToString(eeDerBytes),
		base64.StdEncoding.EncodeToString(rootDerBytes),
	}

	return eeKey, x5c, nil
}

func CalcKID(pub *ecdsa.PublicKey, hashAlgo string) []byte {
	b := elliptic.Marshal(pub.Curve, pub.X, pub.Y)

	var h hash.Hash
	switch hashAlgo {
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	default:
		h = sha256.New()
	}

	h.Write(b)
	return h.Sum(nil)
}
