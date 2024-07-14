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
	"os"
)

const (
	criptRootDir = "internal/cryptoroot/pem"
)

var (
	rootKeyPath  = fmt.Sprintf("%s/rootKey.pem", criptRootDir)
	rootCertPath = fmt.Sprintf("%s/rootCert.pem", criptRootDir)
)

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

	// generate root key and certificate
	if fileExists(rootKeyPath) && fileExists(rootCertPath) {
		rootKey, err = readPEMFile(rootKeyPath)
		if err != nil {
			return nil, nil, err
		}
		rootCert, err = readCertificatePEM(rootCertPath)
		if err != nil {
			return nil, nil, err
		}
		rootDerBytes = rootCert.Raw

		// generate root key and certificate
	} else {
		rootKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		if err := writePEMFile(rootKey, rootKeyPath); err != nil {
			return nil, nil, err
		}

		rootCert, rootDerBytes, err = createRootCertificate(rootKey)
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
