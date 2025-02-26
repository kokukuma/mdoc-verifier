// Package mdoc provides functionality for verifying mobile documents according to
// the ISO/IEC 18013-5:2021 standard. This file contains the verification logic
// for validating mobile documents against the standard's requirements.
package mdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"time"

	"github.com/veraison/go-cose"
)

// VerifierOption defines a functional option for configuring a Verifier instance.
// This follows the functional options pattern for a clean and flexible API.
type VerifierOption func(*Verifier)

// WithSignCurrentTime sets a custom time to use for signature validity checks.
// This is useful for testing or for validating historical documents with a specific timestamp.
//
// Parameters:
//   - date: The time to use as the current time for signature validity checks
func WithSignCurrentTime(date time.Time) VerifierOption {
	return func(s *Verifier) {
		s.signCurrenTime = date
	}
}

// WithCertCurrentTime sets a custom time to use for certificate validity checks.
// This is useful for testing or for validating certificates with a specific timestamp.
//
// Parameters:
//   - date: The time to use as the current time for certificate validity checks
func WithCertCurrentTime(date time.Time) VerifierOption {
	return func(s *Verifier) {
		s.certCurrentTime = date
	}
}

// WithSkipVerifyCertificate disables certificate verification.
// This can be useful for testing or when certificates cannot be verified
// against the local trust store but other verifications should still be performed.
//
// WARNING: Skipping certificate verification in production environments reduces security.
func WithSkipVerifyCertificate() VerifierOption {
	return func(s *Verifier) {
		s.skipVerifyCertificate = true
	}
}

// WithSkipVerifyDeviceSigned disables verification of device-signed data.
// This can be useful when only issuer-signed data is relevant or when
// device authentication is handled by another component.
//
// WARNING: Skipping device signature verification reduces security.
func WithSkipVerifyDeviceSigned() VerifierOption {
	return func(s *Verifier) {
		s.skipVerifyDeviceSigned = true
	}
}

// WithSkipVerifyIssuerAuth disables verification of the issuer's signature.
// This can be useful for testing or when the issuer's signature is verified
// by another component.
//
// WARNING: Skipping issuer signature verification reduces security.
func WithSkipVerifyIssuerAuth() VerifierOption {
	return func(s *Verifier) {
		s.skipVerifyIssuerAuth = true
	}
}

// WithSkipSignedDateValidation disables validation of the signed date against certificate validity.
// This is useful when dealing with documents where the signed date might not align
// perfectly with the certificate validity period.
func WithSkipSignedDateValidation() VerifierOption {
	return func(s *Verifier) {
		s.skipSignedDateValidation = true
	}
}

// Verifier handles the verification of mobile documents according to ISO/IEC 18013-5:2021.
// It implements the verification procedures described in section 9.3 of the standard,
// including certificate validation, signature verification, and digest validation.
type Verifier struct {
	// roots is the certificate pool containing trusted root certificates
	roots *x509.CertPool

	// skipVerifyDeviceSigned controls whether to skip device signature verification
	skipVerifyDeviceSigned bool

	// skipVerifyCertificate controls whether to skip certificate verification
	skipVerifyCertificate bool

	// skipVerifyIssuerAuth controls whether to skip issuer signature verification
	skipVerifyIssuerAuth bool

	// skipSignedDateValidation controls whether to skip validation of the signed date
	skipSignedDateValidation bool

	// signCurrenTime is the time to use for signature validity checks
	signCurrenTime time.Time

	// certCurrentTime is the time to use for certificate validity checks
	certCurrentTime time.Time
}

// NewVerifier creates a new Verifier instance with the specified root certificates and options.
// The Verifier is used to validate mobile documents according to ISO/IEC 18013-5:2021.
//
// Parameters:
//   - roots: Certificate pool containing trusted root certificates for certificate validation
//   - opts: Optional functional options to customize the verifier's behavior
//
// Returns:
//   - *Verifier: A configured verifier instance
//
// Example:
//
//	// Create a verifier with default settings
//	roots := x509.NewCertPool()
//	roots.AppendCertsFromPEM(rootCertPEM)
//	verifier := NewVerifier(roots)
//
//	// Create a verifier with custom options
//	verifier := NewVerifier(roots,
//	    WithCertCurrentTime(specificTime),
//	    WithSkipVerifyDeviceSigned())
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

// Verify performs the complete verification of a mobile document according to
// ISO/IEC 18013-5:2021 section 9.3. This includes:
//  1. Validating the document signing certificate (DSC)
//  2. Verifying the issuer's signature (IssuerAuth)
//  3. Validating the digests of all data elements
//  4. Checking document types match
//  5. Validating the MSO validity information
//  6. Verifying device authentication (if not skipped)
//
// Parameters:
//   - doc: The Document to verify
//   - sessTrans: The session transcript bytes (used for device authentication)
//
// Returns:
//   - error: If any verification step fails, an error describing the failure
//
// Example:
//
//	err := verifier.Verify(document, sessionTranscript)
//	if err != nil {
//	    // Handle verification failure
//	    fmt.Printf("Verification failed: %v\n", err)
//	} else {
//	    // Document verification successful
//	}
func (v *Verifier) Verify(doc *Document, sessTrans []byte) error {
	// Get the Mobile Security Object (MSO) from the document
	mso, err := doc.IssuerSigned.MobileSecurityObject()
	if err != nil {
		return NewWrappedCategoryError(ErrCategoryDocument, err, "failed to parse MSO")
	}

	dsCert, err := doc.IssuerSigned.DocumentSigningCertificate()
	if err != nil {
		return NewWrappedCategoryError(ErrCategoryCertificate, err, "failed to get document signing certificate")
	}

	// 9.3.1 Inspection procedure for issuer data authentication
	// 1. Validate the certificate included in the MSO header according to 9.3.3.
	if err := v.verifyDSCertificate(dsCert); err != nil {
		return NewWrappedCategoryError(ErrCategoryVerification, err, "certificate validation failed")
	}

	// 2. Verify the digital signature of the IssuerAuth structure (see 9.1.2.4) using the working_public_
	//    key, working_public_key_parameters, and working_public_key_algorithm from the certificate
	//    validation procedure of step 1.
	if err := v.verifyIssuerAuthSignature(&doc.IssuerSigned); err != nil {
		return NewWrappedCategoryError(ErrCategoryVerification, err, "issuer signature verification failed")
	}

	// 3. Calculate the digest value for every IssuerSignedItem returned in the DeviceResponse structure
	//    according to 9.1.2.5 and verify that these calculated digests equal the corresponding digest values
	//    in the MSO.
	if err := v.verifyDigests(&doc.IssuerSigned, mso); err != nil {
		return NewWrappedCategoryError(ErrCategoryDigest, err, "digest verification failed")
	}

	// 4. Verify that the DocType in the MSO matches the relevant DocType in the Documents structure.
	if doc.DocType != mso.DocType {
		return NewCategoryError(ErrCategoryDocument, "document type mismatch: expected %s, got %s", mso.DocType, doc.DocType)
	}

	// 5. Validate the elements in the ValidityInfo structure, i.e. verify that:
	// — the 'signed' date is within the validity period of the certificate in the MSO header,
	// — the current timestamp shall be equal or later than the 'validFrom' element,
	// — the 'validUntil' element shall be equal or later than the current timestamp.
	if err := v.verifyMSOValidity(dsCert, mso); err != nil {
		return NewWrappedCategoryError(ErrCategoryVerification, err, "MSO validity verification failed")
	}

	// 9.1.3 mdoc authentication
	if err := v.verifyMDocAuthentication(mso, &doc.DeviceSigned, sessTrans); err != nil {
		return NewWrappedCategoryError(ErrCategoryDevice, err, "device authentication failed")
	}

	return nil
}

// IssuerSigneder defines the interface for types that provide access to issuer-signed data.
// This interface abstracts the functionality needed to verify issuer signatures,
// allowing the verifier to work with different implementations.
type IssuerSigneder interface {
	// Alg returns the cryptographic algorithm used for the issuer's signature
	Alg() (cose.Algorithm, error)

	// DocumentSigningKey returns the public key from the document signing certificate
	DocumentSigningKey() (*ecdsa.PublicKey, error)

	// GetIssuerAuth returns the issuer's COSE_Sign1 structure
	GetIssuerAuth() cose.UntaggedSign1Message

	// GetNameSpaces returns a list of all namespaces in the issuer-signed data
	GetNameSpaces() []NameSpace

	// GetIssuerSignedItems retrieves all issuer-signed items from a namespace
	GetIssuerSignedItems(NameSpace) ([]IssuerSignedItem, error)
}

// MSOer defines the interface for types that provide access to Mobile Security Object data.
// This interface abstracts the functionality needed to work with the MSO,
// allowing the verifier to access MSO information without depending on specific implementations.
type MSOer interface {
	// DeviceKey returns the device's public key from the MSO
	DeviceKey() (*ecdsa.PublicKey, error)

	// GetDigest retrieves a specific digest value from the MSO
	GetDigest(NameSpace, DigestID) (Digest, error)

	// GetDocType returns the document type identifier from the MSO
	GetDocType() DocType

	// DigestAlg returns the digest algorithm identifier from the MSO
	DigestAlg() string

	// GetValidityInfo returns the validity information from the MSO
	GetValidityInfo() ValidityInfo

	// KeyAuthorizations returns the key authorizations structure from the MSO
	KeyAuthorizations() (*KeyAuthorizations, error)
}

// DeviceSigneder defines the interface for types that provide access to device-signed data.
// This interface abstracts the functionality needed to verify device signatures,
// allowing the verifier to work with different implementations.
type DeviceSigneder interface {
	// Alg returns the cryptographic algorithm used for the device's signature
	Alg() (cose.Algorithm, error)

	// DeviceAuthMac returns the MAC structure used for device authentication, if present
	DeviceAuthMac() *UntaggedSign1Message

	// DeviceAuthSignature returns the signature structure used for device authentication, if present
	DeviceAuthSignature() *UntaggedSign1Message

	// DeviceAuthenticationBytes generates the byte array used for device authentication
	DeviceAuthenticationBytes(DocType, []byte) ([]byte, error)

	// DeviceNameSpaces parses and returns the device-signed namespaces
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
		return NewWrappedCategoryError(ErrCategoryCertificate, err, "failed to verify certificate chain")
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
			return NewCategoryError(ErrCategoryVerification,
				"MSO signed date outside certificate validity period: signed=%v, notBefore=%v, notAfter=%v",
				validityInfo.Signed, dsCert.NotBefore, dsCert.NotAfter)
		}
	}

	// — the current timestamp shall be equal or later than the 'validFrom' element,
	// — the 'validUntil' element shall be equal or later than the current timestamp.
	if v.signCurrenTime.Before(validityInfo.ValidFrom) || v.signCurrenTime.After(validityInfo.ValidUntil) {
		return NewCategoryError(ErrCategoryVerification,
			"current time outside MSO validity period: current=%v, validFrom=%v, validUntil=%v",
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
		return NewWrappedCategoryError(ErrCategoryDevice, err, "key authorization verification failed")
	}

	// veirfy DeviceMAC or DeviceSignature
	switch {
	case deviceSigned.DeviceAuthMac() != nil:
		return v.verifyDeviceMAC()
	case deviceSigned.DeviceAuthSignature() != nil:
		return v.verifyDeviceSignature(mso, deviceSigned, sessionTranscript)
	default:
		return NewCategoryError(ErrCategoryDevice, "neither DeviceMAC nor DeviceSignature is present")
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
		return NewWrappedCategoryError(ErrCategoryDevice, err, "failed to obtain device namespaces")
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
			return NewCategoryError(ErrCategoryDevice, "namespace %s not authorized", namespace)
		}

		authorizedElements, exists := keyAuth.DataElements[namespace]
		if !exists {
			return NewCategoryError(ErrCategoryDevice, "namespace %s not found in authorized data elements", namespace)
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
				return NewCategoryError(ErrCategoryDevice, "data element %s in namespace %s not authorized",
					elementID, namespace)
			}
		}
	}

	return nil
}

func (v *Verifier) verifyDeviceSignature(mso MSOer, deviceSigned DeviceSigneder, sessionTranscript []byte) error {
	alg, err := deviceSigned.Alg()
	if err != nil {
		return NewWrappedCategoryError(ErrCategoryDevice, err, "failed to get signature algorithm")
	}

	pubKey, err := mso.DeviceKey()
	if err != nil {
		return NewWrappedCategoryError(ErrCategoryDevice, err, "failed to get device public key")
	}

	verifier, err := cose.NewVerifier(alg, pubKey)
	if err != nil {
		return NewWrappedCategoryError(ErrCategoryDevice, err, "failed to create signature verifier")
	}

	authBytes, err := deviceSigned.DeviceAuthenticationBytes(mso.GetDocType(), sessionTranscript)
	if err != nil {
		return NewWrappedCategoryError(ErrCategoryDevice, err, "failed to generate device authentication bytes")
	}

	sig := deviceSigned.DeviceAuthSignature()
	sig.Payload = authBytes

	if err := sig.Verify(nil, verifier); err != nil {
		return NewWrappedCategoryError(ErrCategoryDevice, err, "device signature verification failed")
	}

	return nil
}

func (v *Verifier) verifyDeviceMAC() error {
	return NewCategoryError(ErrCategoryDevice, "DeviceMAC verification not implemented yet")
}

func (v *Verifier) verifyDigests(issuerSigned IssuerSigneder, mso MSOer) error {
	for _, namespace := range issuerSigned.GetNameSpaces() {
		issuerSignedItems, err := issuerSigned.GetIssuerSignedItems(namespace)
		if err != nil {
			return NewCategoryError(ErrCategoryDigest, "namespace %s not found in MSO ValueDigests", namespace)
		}

		for _, item := range issuerSignedItems {
			expectedDigest, err := mso.GetDigest(namespace, item.DigestID)
			if err != nil {
				return NewCategoryError(ErrCategoryDigest, "digest ID %d not found in namespace %s",
					item.DigestID, namespace)
			}

			actualDigest, err := item.Digest(mso.DigestAlg())
			if err != nil {
				return NewWrappedCategoryError(ErrCategoryDigest, err, "failed to calculate digest")
			}

			if !bytes.Equal(expectedDigest, actualDigest) {
				return NewCategoryError(ErrCategoryDigest, "digest mismatch for ID %d in namespace %s",
					item.DigestID, namespace)
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
		return NewWrappedCategoryError(ErrCategoryVerification, err, "failed to get signature algorithm")
	}

	dsPubKey, err := issuerSigned.DocumentSigningKey()
	if err != nil {
		return NewWrappedCategoryError(ErrCategoryVerification, err, "failed to get document signing key")
	}

	verifier, err := cose.NewVerifier(algorithm, dsPubKey)
	if err != nil {
		return NewWrappedCategoryError(ErrCategoryVerification, err, "failed to create signature verifier")
	}

	issuerAuth := issuerSigned.GetIssuerAuth()

	if err := issuerAuth.Verify(nil, verifier); err != nil {
		return NewWrappedCategoryError(ErrCategoryVerification, err, "failed to verify issuer signature")
	}

	return nil
}
