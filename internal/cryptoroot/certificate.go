package cryptoroot

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"time"
)

var (
	// Just specify something
	CRLPoint = "https://preprod.pki.eudiw.dev/crl/pid_CA_UT_01.crl"
	DNSName  = os.Getenv("SERVER_DOMAIN")
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
		SubjectKeyId:          CalcKID(&key.PublicKey, "sha1"),
		CRLDistributionPoints: []string{CRLPoint},
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
		DNSNames:              []string{DNSName},
		SubjectKeyId:          CalcKID(&key.PublicKey, "sha1"),
		AuthorityKeyId:        CalcKID(&parentKey.PublicKey, "sha1"),
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{objectId},
		CRLDistributionPoints: []string{CRLPoint},
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
