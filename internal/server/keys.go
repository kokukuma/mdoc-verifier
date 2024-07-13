package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func createRootCertificate(key *ecdsa.PrivateKey) (*x509.Certificate, []byte, error) {
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA kokukuma"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // Valid for 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SubjectKeyId:          generateKIDSha1(&key.PublicKey),
		CRLDistributionPoints: []string{"https://preprod.pki.eudiw.dev/crl/pid_CA_UT_01.crl"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, derBytes, nil
}

func createEndEntityCertificate(key *ecdsa.PrivateKey, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, []byte, error) {
	objectId := asn1.ObjectIdentifier([]int{1, 0, 18013, 5, 1, 6})
	template := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "End-Entity Certificate kokukuma"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // Valid for 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  false,
		DNSNames:              []string{"fido-kokukuma.jp.ngrok.io"},
		SubjectKeyId:          generateKIDSha1(&key.PublicKey),
		AuthorityKeyId:        generateKIDSha1(&parentKey.PublicKey),
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{objectId},
		CRLDistributionPoints: []string{"https://preprod.pki.eudiw.dev/crl/pid_CA_UT_01.crl"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, derBytes, nil
}

func printPEM(certDER []byte) {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	fmt.Println(string(certPEM))
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil
}

func initKeys() (*ecdsa.PrivateKey, *ecdsa.PublicKey, []string, error) {
	var rootKey *ecdsa.PrivateKey
	var rootCert *x509.Certificate
	var rootDerBytes []byte
	var err error

	if fileExists("internal/server/root/rootKey.pem") &&
		fileExists("internal/server/root/rootCert.pem") {
		rootKey, err = readPEMFile("internal/server/root/rootKey.pem")
		if err != nil {
			return nil, nil, nil, err
		}
		rootCert, err = readCertificatePEM("internal/server/root/rootCert.pem")
		if err != nil {
			return nil, nil, nil, err
		}
		rootDerBytes = rootCert.Raw
	} else {
		rootKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		writePEMFile(rootKey, "internal/server/root/rootKey.pem")

		rootCert, rootDerBytes, err = createRootCertificate(rootKey)
		writeCertificatePEM(rootCert, "internal/server/root/rootCert.pem")
	}

	printPEM(rootDerBytes)

	eeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	_, eeDerBytes, err := createEndEntityCertificate(eeKey, rootCert, rootKey)
	if err != nil {
		return nil, nil, nil, err
	}

	x5c := []string{
		base64.StdEncoding.EncodeToString(eeDerBytes),
		base64.StdEncoding.EncodeToString(rootDerBytes),
	}

	return eeKey, &eeKey.PublicKey, x5c, nil
}
