package mdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"log"
	"math/big"

	"github.com/fxamacker/cbor/v2"
	"github.com/kokukuma/identity-credential-api-demo/internal/protocol"
	"github.com/veraison/go-cose"
)

func VerifyDeviceSigned(mso *MobileSecurityObject, doc Document, sessionTranscript []byte) error {
	deviceAuthentication := []interface{}{
		"DeviceAuthentication",
		cbor.RawMessage(sessionTranscript),
		doc.DocType,
		cbor.Tag{Number: 24, Content: doc.DeviceSigned.NameSpaces},
	}
	da, err := cbor.Marshal(deviceAuthentication)
	if err != nil {
		return fmt.Errorf("error encoding transcript: %v", err)
	}
	deviceAuthenticationByte, err := cbor.Marshal(cbor.Tag{Number: 24, Content: da})
	if err != nil {
		return fmt.Errorf("failed to Marshal cbor %w", err)
	}

	alg, err := doc.DeviceSigned.DeviceAuth.DeviceSignature.Headers.Protected.Algorithm()
	if err != nil {
		return fmt.Errorf("failed to get alg %w", err)
	}

	// TODO: algによって変えたほうが.
	pubKey, err := parseECDSA(mso.DeviceKeyInfo.DeviceKey)
	if err != nil {
		return fmt.Errorf("failed to get alg %w", err)
	}

	verifier, err := cose.NewVerifier(alg, pubKey)
	if err != nil {
		return fmt.Errorf("Failed to create NewVerifier: %v", err)
	}

	doc.DeviceSigned.DeviceAuth.DeviceSignature.Payload = deviceAuthenticationByte

	return doc.DeviceSigned.DeviceAuth.DeviceSignature.Verify(nil, verifier)
}

func parseECDSA(coseKey COSEKey) (*ecdsa.PublicKey, error) {
	// Extract the curve
	var crv int
	if err := cbor.Unmarshal(coseKey.CrvOrNOrK, &crv); err != nil {
		return nil, err
	}

	// Extract the X coordinate
	var xBytes []byte
	if err := cbor.Unmarshal(coseKey.XOrE, &xBytes); err != nil {
		return nil, err
	}

	// Extract the Y coordinate
	var yBytes []byte
	if err := cbor.Unmarshal(coseKey.Y, &yBytes); err != nil {
		return nil, err
	}

	// Convert to ecdsa.PublicKey
	var pubKey ecdsa.PublicKey
	switch crv {
	case 1: // Assuming 1 means P-256 curve
		pubKey.Curve = elliptic.P256()
	case 2: // Assuming 2 means P-384 curve
		pubKey.Curve = elliptic.P384()
	case 3: // Assuming 3 means P-521 curve
		pubKey.Curve = elliptic.P521()
	default:
		log.Fatalf("Unsupported curve: %v", crv)
	}

	pubKey.X = new(big.Int).SetBytes(xBytes)
	pubKey.Y = new(big.Int).SetBytes(yBytes)

	return &pubKey, nil
}

func VerifiedElements(namespaces IssuerNameSpaces, mso *MobileSecurityObject) (map[NameSpace][]IssuerSignedItem, error) {
	items := map[NameSpace][]IssuerSignedItem{}

	for ns, vals := range namespaces {
		digestIDs, ok := mso.ValueDigests[ns]
		if !ok {
			return nil, fmt.Errorf("failed to get ValueDigests of %s", ns)
		}

		for _, val := range vals {
			v, err := cbor.Marshal(cbor.Tag{
				Number:  24,
				Content: val,
			})
			if err != nil {
				return nil, err
			}

			var item IssuerSignedItem
			if err := cbor.Unmarshal(val, &item); err != nil {
				return nil, err
			}
			digest, ok := digestIDs[DigestID(item.DigestID)]
			if !ok {
				return nil, fmt.Errorf("failed to get ValueDigests of %s", ns)
			}

			if !bytes.Equal(digest, protocol.Digest(v, mso.DigestAlgorithm)) {
				return nil, fmt.Errorf("digest unmatched digestID:%v", item.DigestID)
			}

			items[ns] = append(items[ns], item)
		}
	}

	return items, nil
}

func VerifyIssuerAuth(issuerAuth cose.UntaggedSign1Message, roots *x509.CertPool, allowSelfCert bool) error {
	alg, err := issuerAuth.Headers.Protected.Algorithm()
	if err != nil {
		return fmt.Errorf("failed to get alg %w", err)
	}

	rawX5Chain, ok := issuerAuth.Headers.Unprotected[cose.HeaderLabelX5Chain]
	if !ok {
		return fmt.Errorf("failed to get x5chain")
	}

	rawX5ChainBytes, ok := rawX5Chain.([][]byte)
	if !ok {
		rawX5ChainByte, ok := rawX5Chain.([]byte)
		if !ok {
			return fmt.Errorf("failed to get x5chain")
		}
		rawX5ChainBytes = append(rawX5ChainBytes, rawX5ChainByte)
	}

	certificates, err := parseCertificates(rawX5ChainBytes, roots, allowSelfCert)
	if err != nil {
		return fmt.Errorf("Failed to parseCertificates: %v", err)
	}

	documentSigningKey, ok := certificates[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("Failed to parseCertificates: %v", err)
	}

	verifier, err := cose.NewVerifier(alg, documentSigningKey)
	if err != nil {
		return fmt.Errorf("Failed to create NewVerifier: %v", err)
	}

	return issuerAuth.Verify(nil, verifier)
}

func parseCertificates(rawCerts [][]byte, roots *x509.CertPool, allowSelfCert bool) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, certData := range rawCerts {
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, fmt.Errorf("error parsing certificate: %v", err)
		}
		if allowSelfCert {
			roots.AddCert(cert)
		}
		certs = append(certs, cert)
	}

	// veirfy
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	// Perform the verification
	_, err := certs[0].Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to verify certificate chain: %v", err)
	}

	return certs, nil
}
