package mdoc

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/veraison/go-cose"
)

type VerifierOption func(*Verifier)

func AllowSelfCert() VerifierOption {
	return func(s *Verifier) {
		s.allowSelfCert = true
	}
}

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

func SkipVerifyCertificate() VerifierOption {
	return func(s *Verifier) {
		s.skipVerifyCertificate = true
	}
}

func SkipVerifyDeviceSigned() VerifierOption {
	return func(s *Verifier) {
		s.skipVerifyDeviceSigned = true
	}
}

func SkipVerifyIssuerAuth() VerifierOption {
	return func(s *Verifier) {
		s.skipVerifyIssuerAuth = true
	}
}

func SkipValidateCertification() VerifierOption {
	return func(s *Verifier) {
		s.skipValidateCertification = true
	}
}

func SkipSignedDateValidation() VerifierOption {
	return func(s *Verifier) {
		s.skipSignedDateValidation = true
	}
}

type Verifier struct {
	roots                     *x509.CertPool
	allowSelfCert             bool
	skipVerifyDeviceSigned    bool
	skipVerifyCertificate     bool
	skipVerifyIssuerAuth      bool
	skipValidateCertification bool
	skipSignedDateValidation  bool
	signCurrenTime            time.Time
	certCurrentTime           time.Time
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

func (v *Verifier) Verify(doc Document, sessTrans []byte) error {
	mso, err := doc.IssuerSigned.MobileSecurityObject()
	if err != nil {
		return fmt.Errorf("failed to get MobileSecurityObject")
	}

	// 9.1.3 mdoc authentication
	if err := v.verifyDeviceSigned(mso, doc, sessTrans); err != nil {
		return fmt.Errorf("failed to verifyDeviceSigned: %v", err)
	}

	// 9.3.1 Inspection procedure for issuer data authentication
	// 1. Validate the certificate included in the MSO header according to 9.3.3.
	if err := v.verifyCertificate(doc.IssuerSigned); err != nil {
		return fmt.Errorf("failed to verifyCertificate: %v", err)
	}

	// 2. Verify the digital signature of the IssuerAuth structure (see 9.1.2.4) using the working_public_
	//    key, working_public_key_parameters, and working_public_key_algorithm from the certificate
	//    validation procedure of step 1.
	if err := v.verifyIssuerAuth(doc.IssuerSigned); err != nil {
		return fmt.Errorf("failed to verifyIssuerAuth: %v", err)
	}

	// 3. Calculate the digest value for every IssuerSignedItem returned in the DeviceResponse structure
	//    according to 9.1.2.5 and verify that these calculated digests equal the corresponding digest values
	//    in the MSO.
	if err := verifyDigests(doc.IssuerSigned, mso); err != nil {
		return fmt.Errorf("failed to verifyDigests: %v", err)
	}

	// 4. Verify that the DocType in the MSO matches the relevant DocType in the Documents structure.
	if doc.DocType != mso.DocType {
		return fmt.Errorf("docType unmatche ")
	}

	// 5. Validate the elements in the ValidityInfo structure, i.e. verify that:
	// — the 'signed' date is within the validity period of the certificate in the MSO header,
	// — the current timestamp shall be equal or later than the ‘validFrom’ element,
	// — the 'validUntil' element shall be equal or later than the current timestamp.
	if err := v.validateCertification(mso, doc); err != nil {
		return fmt.Errorf("failed to validate certificate: %v", err)
	}
	return nil
}

func (v *Verifier) verifyDeviceSigned(mso *MobileSecurityObject, doc Document, sessionTranscript []byte) error {
	if v.skipVerifyDeviceSigned {
		return nil
	}
	deviceAuthenticationByte, err := doc.DeviceSigned.DeviceAuthenticationBytes(doc.DocType, sessionTranscript)
	if err != nil {
		return fmt.Errorf("failed to Marshal cbor %w", err)
	}

	alg, err := doc.DeviceSigned.Alg()
	if err != nil {
		return fmt.Errorf("failed to get alg %w", err)
	}

	pubKey, err := mso.DeviceKey()
	if err != nil {
		return fmt.Errorf("failed to get deviceKey %w", err)
	}

	verifier, err := cose.NewVerifier(alg, pubKey)
	if err != nil {
		return fmt.Errorf("Failed to create NewVerifier: %v", err)
	}

	doc.DeviceSigned.DeviceAuth.DeviceSignature.Payload = deviceAuthenticationByte

	return doc.DeviceSigned.DeviceAuth.DeviceSignature.Verify(nil, verifier)
}

func verifyDigests(issuerSigned IssuerSigned, mso *MobileSecurityObject) error {
	for ns, itembytes := range issuerSigned.NameSpaces {
		digestIDs, ok := mso.ValueDigests[ns]
		if !ok {
			return fmt.Errorf("failed to get ValueDigests of %s", ns)
		}

		for _, itemByte := range itembytes {
			item, err := itemByte.IssuerSignedItem()
			if err != nil {
				return fmt.Errorf("failed to get IssuerSignedItem: %v", err)
			}

			digest, ok := digestIDs[DigestID(item.DigestID)]
			if !ok {
				return fmt.Errorf("failed to get ValueDigests of %s", ns)
			}

			calc, err := itemByte.Digest(mso.DigestAlgorithm)
			if err != nil {
				return err
			}

			if !bytes.Equal(digest, calc) {
				return fmt.Errorf("digest unmatched digestID:%v", item.DigestID)
			}
		}

	}
	return nil
}

func (v *Verifier) verifyIssuerAuth(issuerSigned IssuerSigned) error {
	if v.skipVerifyIssuerAuth {
		return nil
	}
	alg, err := issuerSigned.Alg()
	if err != nil {
		return fmt.Errorf("failed to get alg %w", err)
	}

	documentSigningKey, err := issuerSigned.DocumentSigningKey()
	if err != nil {
		return fmt.Errorf("Failed to parseCertificates: %v", err)
	}

	verifier, err := cose.NewVerifier(alg, documentSigningKey)
	if err != nil {
		return fmt.Errorf("Failed to create NewVerifier: %v", err)
	}

	return issuerSigned.IssuerAuth.Verify(nil, verifier)
}

func certificateToPEM(cert *x509.Certificate) {
	if cert == nil {
		return
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	fmt.Println(string(pem.EncodeToMemory(pemBlock)))
	return
}

func (v *Verifier) verifyCertificate(issuerSigned IssuerSigned) error {
	if v.skipVerifyCertificate {
		return nil
	}

	certs, err := issuerSigned.X5CertificateChain()
	if err != nil {
		return fmt.Errorf("Failed to get X5CertificateChain: %v", err)
	}

	// TODO: 証明書が見つからないので一時凌ぎ...
	if v.allowSelfCert {
		for _, cert := range certs {
			v.roots.AddCert(cert)
		}
	}

	// veirfy
	opts := x509.VerifyOptions{
		Roots:       v.roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: v.certCurrentTime,
	}

	// Perform the verification
	if _, err := certs[0].Verify(opts); err != nil {
		return fmt.Errorf("failed to verify certificate chain: %v", err)
	}
	return nil
}

func (v *Verifier) validateCertification(mso *MobileSecurityObject, doc Document) error {
	if v.skipValidateCertification {
		return nil
	}
	certificate, err := doc.IssuerSigned.Certificate()
	if err != nil {
		return fmt.Errorf("failed to get certificate: %v", err)
	}
	if !v.skipSignedDateValidation {
		if mso.ValidityInfo.Signed.Before(certificate.NotBefore) || mso.ValidityInfo.Signed.After(certificate.NotAfter) {
			return fmt.Errorf("failed to veirfy signed date: %v: NotBefore=%v: NotAfter=%v: ", mso.ValidityInfo, certificate.NotBefore, certificate.NotAfter)
		}
	}
	if v.signCurrenTime.Before(mso.ValidityInfo.ValidFrom) || v.signCurrenTime.After(mso.ValidityInfo.ValidUntil) {
		return fmt.Errorf("failed to check validity: %v", mso.ValidityInfo)
	}
	return nil
}
