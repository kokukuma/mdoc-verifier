package mdoc

import (
	"bytes"
	"crypto/ecdsa"
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

	dsCert, err := doc.IssuerSigned.DocumentSigningCertificate()
	if err != nil {
		return fmt.Errorf("failed to get X5CertificateChain: %w", err)
	}

	// 9.3.1 Inspection procedure for issuer data authentication
	// 1. Validate the certificate included in the MSO header according to 9.3.3.
	if err := v.verifyDSCertificate(dsCert); err != nil {
		return fmt.Errorf("certificate validation failed: %w", err)
	}

	// 2. Verify the digital signature of the IssuerAuth structure (see 9.1.2.4) using the working_public_
	//    key, working_public_key_parameters, and working_public_key_algorithm from the certificate
	//    validation procedure of step 1.
	if err := v.verifyIssuerAuthSignature(&doc.IssuerSigned); err != nil {
		return fmt.Errorf("issuer signature verification failed: %w", err)
	}

	// 3. Calculate the digest value for every IssuerSignedItem returned in the DeviceResponse structure
	//    according to 9.1.2.5 and verify that these calculated digests equal the corresponding digest values
	//    in the MSO.
	if err := v.verifyDigests(&doc.IssuerSigned, mso); err != nil {
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
	if err := v.verifyMSOValidity(dsCert, mso); err != nil {
		return fmt.Errorf("mso verification failed: %w", err)
	}

	// 9.1.3 mdoc authentication
	if err := v.verifyMDocAuthentication(mso, &doc.DeviceSigned, sessTrans); err != nil {
		return fmt.Errorf("mdoc authentication failed: %w", err)
	}

	return nil
}

type IssuerSigneder interface {
	Alg() (cose.Algorithm, error)
	DocumentSigningKey() (*ecdsa.PublicKey, error)
	GetIssuerAuth() cose.UntaggedSign1Message
	GetNameSpaces() []NameSpace
	GetIssuerSignedItems(NameSpace) ([]IssuerSignedItem, error)
}

type MSOer interface {
	DeviceKey() (*ecdsa.PublicKey, error)
	GetDigest(NameSpace, DigestID) (Digest, error)
	GetDocType() DocType
	DigestAlg() string
	GetValidityInfo() ValidityInfo
	KeyAuthorizations() (*KeyAuthorizations, error)
}

type DeviceSigneder interface {
	Alg() (cose.Algorithm, error)
	DeviceAuthMac() *UntaggedSign1Message
	DeviceAuthSignature() *UntaggedSign1Message
	DeviceAuthenticationBytes(DocType, []byte) ([]byte, error)
	DeviceNameSpaces() (DeviceNameSpaces, error)
}

func (v *Verifier) verifyDSCertificate(dsCert *x509.Certificate) error {
	if v.skipVerifyCertificate {
		return nil
	}

	opts := x509.VerifyOptions{
		Roots:       v.roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: v.certCurrentTime,
	}

	if _, err := dsCert.Verify(opts); err != nil {
		return fmt.Errorf("failed to verify dsCert chain: %v", err)
	}

	// TODO: revocation checking.

	// issuing_countryの検証 (7.2.1参照)
	// TODO: issuing_countryとdsCertのcountryNameの一致確認を追加

	// issuing_jurisdictionの検証 (7.2.1参照)
	// TODO: 存在する場合、issuing_jurisdictionとdsCertのstateOrProvinceNameの一致確認を追加

	return nil
}

func (v *Verifier) verifyMSOValidity(dsCert *x509.Certificate, mso MSOer) error {

	validityInfo := mso.GetValidityInfo()

	// — the 'signed' date is within the validity period of the certificate in the MSO header,
	if !v.skipSignedDateValidation {
		if validityInfo.Signed.Before(dsCert.NotBefore) || validityInfo.Signed.After(dsCert.NotAfter) {
			return fmt.Errorf("MSO signed date outside dsCert validity period: signed=%v, notBefore=%v, notAfter=%v",
				validityInfo.Signed, dsCert.NotBefore, dsCert.NotAfter)
		}
	}

	// — the current timestamp shall be equal or later than the ‘validFrom’ element,
	// — the 'validUntil' element shall be equal or later than the current timestamp.
	if v.signCurrenTime.Before(validityInfo.ValidFrom) || v.signCurrenTime.After(validityInfo.ValidUntil) {
		return fmt.Errorf("current time outside MSO validity period: current=%v, validFrom=%v, validUntil=%v",
			v.signCurrenTime, validityInfo.ValidFrom, validityInfo.ValidUntil)
	}

	return nil
}

func (v *Verifier) verifyMDocAuthentication(mso MSOer, deviceSigned DeviceSigneder, sessionTranscript []byte) error {
	if v.skipVerifyDeviceSigned {
		return nil
	}

	// verify KeyAuthorizations
	if err := v.verifyKeyAuthorizations(mso, deviceSigned); err != nil {
		return fmt.Errorf("key authorization verification failed: %w", err)
	}

	// veirfy DeviceMAC or DeviceSignature
	switch {
	case deviceSigned.DeviceAuthMac() != nil:
		return v.verifyDeviceMAC()
	case deviceSigned.DeviceAuthSignature() != nil:
		return v.verifyDeviceSignature(mso, deviceSigned, sessionTranscript)
	default:
		return fmt.Errorf("neither DeviceMAC nor DeviceSignature is present")
	}
}

func (v *Verifier) verifyKeyAuthorizations(mso MSOer, deviceSigned DeviceSigneder) error {
	keyAuth, err := mso.KeyAuthorizations()
	if err != nil {
		// No KeyAuthorizations means no need to check
		return nil
	}

	deviceNameSpaces, err := deviceSigned.DeviceNameSpaces()
	if err != nil {
		return fmt.Errorf("deviceNameSpace cannot obtained: %w", err)
	}

	if len(deviceNameSpaces) == 0 {
		return nil
	}

	for namespace, items := range deviceNameSpaces {
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

func (v *Verifier) verifyDeviceSignature(mso MSOer, deviceSigned DeviceSigneder, sessionTranscript []byte) error {
	alg, err := deviceSigned.Alg()
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

	authBytes, err := deviceSigned.DeviceAuthenticationBytes(mso.GetDocType(), sessionTranscript)
	if err != nil {
		return fmt.Errorf("failed to generate device authentication bytes: %w", err)
	}

	sig := deviceSigned.DeviceAuthSignature()
	sig.Payload = authBytes

	return sig.Verify(nil, verifier)
}

func (v *Verifier) verifyDeviceMAC() error {
	return fmt.Errorf("not implemented yet")
}

func (v *Verifier) verifyDigests(issuerSigned IssuerSigneder, mso MSOer) error {

	for _, namespace := range issuerSigned.GetNameSpaces() {

		issuerSignedItems, err := issuerSigned.GetIssuerSignedItems(namespace)
		if err != nil {
			return fmt.Errorf("namespace %s not found in MSO ValueDigests", namespace)
		}

		for _, item := range issuerSignedItems {

			expectedDigest, err := mso.GetDigest(namespace, item.DigestID)
			if err != nil {
				return fmt.Errorf("digest ID %d not found in namespace %s", item.DigestID, namespace)
			}

			actualDigest, err := item.Digest(mso.DigestAlg())
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

func (v *Verifier) verifyIssuerAuthSignature(issuerSigned IssuerSigneder) error {
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

	issuerAuth := issuerSigned.GetIssuerAuth()

	if err := issuerAuth.Verify(nil, verifier); err != nil {
		return fmt.Errorf("failed to verify issuer signature: %w", err)
	}

	return nil
}
