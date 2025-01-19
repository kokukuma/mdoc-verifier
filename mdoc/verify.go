package mdoc

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/veraison/go-cose"
)

type VerifierOption func(*Verifier)

func WithSignCurrentTime(date time.Time) VerifierOption {
	return func(s *Verifier) {
		s.signCurrenTime = date
	}
}

func WithCertCurrentTime(date time.Time) VerifierOption {
	return func(s *Verifier) {
		s.certCurrentTime = date
	}
}

func WithSkipVerifyCertificate() VerifierOption {
	return func(s *Verifier) {
		s.skipVerifyCertificate = true
	}
}

func WithSkipVerifyDeviceSigned() VerifierOption {
	return func(s *Verifier) {
		s.skipVerifyDeviceSigned = true
	}
}

func WithSkipVerifyIssuerAuth() VerifierOption {
	return func(s *Verifier) {
		s.skipVerifyIssuerAuth = true
	}
}

func WithSkipSignedDateValidation() VerifierOption {
	return func(s *Verifier) {
		s.skipSignedDateValidation = true
	}
}

type Verifier struct {
	roots                    *x509.CertPool
	skipVerifyDeviceSigned   bool
	skipVerifyCertificate    bool
	skipVerifyIssuerAuth     bool
	skipSignedDateValidation bool
	signCurrenTime           time.Time
	certCurrentTime          time.Time
}

func NewVerifier(roots *x509.CertPool, opts ...VerifierOption) *Verifier {
	server := &Verifier{
		roots:           roots,
		signCurrenTime:  time.Now(),
		certCurrentTime: time.Now(),
	}

	for _, opt := range opts {
		opt(server)
	}
	return server
}

func (v *Verifier) Verify(doc *Document, sessTrans []byte) error {

	mso, err := doc.IssuerSigned.MobileSecurityObject()
	if err != nil {
		return fmt.Errorf("failed to parse MSO: %w", err)

	}

	// 9.3.1 Inspection procedure for issuer data authentication
	// 1. Validate the certificate included in the MSO header according to 9.3.3.
	if err := v.verifyIssuerCertificate(doc.IssuerSigned, mso); err != nil {
		return fmt.Errorf("certificate validation failed: %w", err)

	}

	// 2. Verify the digital signature of the IssuerAuth structure (see 9.1.2.4) using the working_public_
	//    key, working_public_key_parameters, and working_public_key_algorithm from the certificate
	//    validation procedure of step 1.
	if err := v.verifyIssuerAuth(doc.IssuerSigned); err != nil {
		return fmt.Errorf("issuer signature verification failed: %w", err)
	}

	// 3. Calculate the digest value for every IssuerSignedItem returned in the DeviceResponse structure
	//    according to 9.1.2.5 and verify that these calculated digests equal the corresponding digest values
	//    in the MSO.
	if err := v.verifyDigests(doc.IssuerSigned, mso); err != nil {
		return fmt.Errorf("digest verification failed: %w", err)
	}

	// 4. Verify that the DocType in the MSO matches the relevant DocType in the Documents structure.
	if doc.DocType != mso.DocType {
		return fmt.Errorf("document type mismatch: expected %s, got %s", mso.DocType, doc.DocType)
	}

	// 5. Validate the elements in the ValidityInfo structure, i.e. verify that:
	// — the 'signed' date is within the validity period of the certificate in the MSO header,
	// — the current timestamp shall be equal or later than the ‘validFrom’ element,
	// — the 'validUntil' element shall be equal or later than the current timestamp.
	//
	// It includes in verifyIssuerCertificate.

	// 9.1.3 mdoc authentication
	if err := v.verifyMDocAuthentication(mso, doc, sessTrans); err != nil {
		return fmt.Errorf("mdoc authentication failed: %w", err)
	}

	return nil
}

func (v *Verifier) verifyMDocAuthentication(mso *MobileSecurityObject, doc *Document, sessionTranscript []byte) error {
	if v.skipVerifyDeviceSigned {
		return nil
	}

	authBytes, err := doc.DeviceSigned.DeviceAuthenticationBytes(doc.DocType, sessionTranscript)
	if err != nil {
		return fmt.Errorf("failed to generate device authentication bytes: %w", err)
	}

	// verify KeyAuthorizations
	deviceNameSpaces, err := doc.DeviceSigned.DeviceNameSpaces()
	if err != nil {
		return fmt.Errorf("deviceNameSpace cannot obtained: %w", err)
	}
	if err := v.verifyKeyAuthorizations(mso, deviceNameSpaces); err != nil {
		return fmt.Errorf("key authorization verification failed: %w", err)
	}

	// veirfy DeviceMAC or DeviceSignature
	switch {
	case doc.DeviceSigned.DeviceAuth.DeviceMac != nil:
		return v.verifyDeviceMAC()
	case doc.DeviceSigned.DeviceAuth.DeviceSignature != nil:
		return v.verifyDeviceSignature(mso, doc, authBytes)
	default:
		return fmt.Errorf("neither DeviceMAC nor DeviceSignature is present")
	}

}

func (v *Verifier) verifyKeyAuthorizations(mso *MobileSecurityObject, deviceSignedNameSpaces DeviceNameSpaces) error {
	if mso.DeviceKeyInfo.KeyAuthorizations == nil {
		return nil
	}

	keyAuth := mso.DeviceKeyInfo.KeyAuthorizations

	if len(deviceSignedNameSpaces) == 0 {
		return nil
	}

	for namespace, items := range deviceSignedNameSpaces {
		if keyAuth.NameSpaces != nil {
			isNamespaceAuthorized := false
			for _, authorizedNS := range keyAuth.NameSpaces {
				if namespace == authorizedNS {
					isNamespaceAuthorized = true
					break
				}
			}
			if isNamespaceAuthorized {
				continue
			}
		}

		if keyAuth.DataElements == nil {
			return fmt.Errorf("namespace %s not authorized", namespace)
		}

		authorizedElements, exists := keyAuth.DataElements[namespace]
		if !exists {
			return fmt.Errorf("namespace %s not found in authorized data elements", namespace)
		}

		for elementID := range items {
			isAuthorized := false
			for _, authorizedID := range authorizedElements {
				if elementID == authorizedID {
					isAuthorized = true
					break
				}
			}
			if !isAuthorized {
				return fmt.Errorf("data element %s in namespace %s not authorized", elementID, namespace)
			}
		}
	}

	return nil
}

func (v *Verifier) verifyDeviceSignature(mso *MobileSecurityObject, doc *Document, authBytes []byte) error {
	alg, err := doc.DeviceSigned.Alg()
	if err != nil {
		return fmt.Errorf("failed to get signature algorithm: %w", err)
	}

	pubKey, err := mso.DeviceKey()
	if err != nil {
		return fmt.Errorf("failed to get device public key: %w", err)
	}

	verifier, err := cose.NewVerifier(alg, pubKey)
	if err != nil {
		return fmt.Errorf("failed to create signature verifier: %w", err)
	}

	sig := doc.DeviceSigned.DeviceAuth.DeviceSignature
	sig.Payload = authBytes

	return sig.Verify(nil, verifier)
}

func (v *Verifier) verifyDeviceMAC() error {
	return fmt.Errorf("not implemented yet")
}

func (v *Verifier) verifyDigests(issuerSigned IssuerSigned, mso *MobileSecurityObject) error {
	for namespace, issuerSignedItems := range issuerSigned.NameSpaces {
		digestIDs, ok := mso.ValueDigests[namespace]
		if !ok {
			return fmt.Errorf("namespace %s not found in MSO ValueDigests", namespace)
		}

		for _, itemBytes := range issuerSignedItems {
			item, err := itemBytes.IssuerSignedItem()
			if err != nil {
				return fmt.Errorf("failed to parse IssuerSignedItem: %w", err)
			}

			expectedDigest, ok := digestIDs[DigestID(item.DigestID)]
			if !ok {
				return fmt.Errorf("digest ID %d not found in namespace %s", item.DigestID, namespace)
			}

			actualDigest, err := itemBytes.Digest(mso.DigestAlgorithm)
			if err != nil {
				return fmt.Errorf("failed to calculate digest: %w", err)
			}

			if !bytes.Equal(expectedDigest, actualDigest) {
				return fmt.Errorf("digest mismatch for ID %d in namespace %s", item.DigestID, namespace)
			}
		}
	}
	return nil
}

func (v *Verifier) verifyIssuerAuth(issuerSigned IssuerSigned) error {
	if v.skipVerifyIssuerAuth {
		return nil
	}

	algorithm, err := issuerSigned.Alg()
	if err != nil {
		return fmt.Errorf("failed to get signature algorithm: %w", err)
	}

	dsPubKey, err := issuerSigned.DocumentSigningKey()
	if err != nil {
		return fmt.Errorf("failed to get document signing key: %w", err)
	}

	verifier, err := cose.NewVerifier(algorithm, dsPubKey)
	if err != nil {
		return fmt.Errorf("failed to create signature verifier: %w", err)
	}

	if err := issuerSigned.IssuerAuth.Verify(nil, verifier); err != nil {
		return fmt.Errorf("failed to verify issuer signature: %w", err)
	}

	return nil
}

func (v *Verifier) verifyIssuerCertificate(issuerSigned IssuerSigned, mso *MobileSecurityObject) error {
	if v.skipVerifyCertificate {
		return nil
	}

	certs, err := issuerSigned.DSCertificateChain()
	if err != nil {
		return fmt.Errorf("Failed to get X5CertificateChain: %v", err)
	}

	opts := x509.VerifyOptions{
		Roots:       v.roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: v.certCurrentTime,
	}

	certificate := certs[0] // End entity certificate

	// 1. 証明書チェーンの検証
	if _, err := certificate.Verify(opts); err != nil {
		return fmt.Errorf("failed to verify certificate chain: %v", err)
	}

	// 2. MSO署名日時の検証
	if !v.skipSignedDateValidation {
		if mso.ValidityInfo.Signed.Before(certificate.NotBefore) || mso.ValidityInfo.Signed.After(certificate.NotAfter) {
			return fmt.Errorf("MSO signed date outside certificate validity period: signed=%v, notBefore=%v, notAfter=%v",
				mso.ValidityInfo.Signed, certificate.NotBefore, certificate.NotAfter)
		}
	}

	// 3. MSO有効期間の検証
	if v.signCurrenTime.Before(mso.ValidityInfo.ValidFrom) || v.signCurrenTime.After(mso.ValidityInfo.ValidUntil) {
		return fmt.Errorf("current time outside MSO validity period: current=%v, validFrom=%v, validUntil=%v",
			v.signCurrenTime, mso.ValidityInfo.ValidFrom, mso.ValidityInfo.ValidUntil)
	}

	// 4. issuing_countryの検証 (7.2.1参照)
	// TODO: issuing_countryとcertificateのcountryNameの一致確認を追加

	// 5. issuing_jurisdictionの検証 (7.2.1参照)
	// TODO: 存在する場合、issuing_jurisdictionとcertificateのstateOrProvinceNameの一致確認を追加

	return nil
}
