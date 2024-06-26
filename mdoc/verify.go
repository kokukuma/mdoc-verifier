package mdoc

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/veraison/go-cose"
)

var (
	Now = time.Now()
)

// ISO/IEC 18013-5
func Verify(doc Document, sessTrans []byte, roots *x509.CertPool, allowSelfCert bool) error {

	mso, err := doc.IssuerSigned.MobileSecurityObject()
	if err != nil {
		return fmt.Errorf("failed to get MobileSecurityObject")
	}

	// 9.1.3 mdoc authentication
	if err := VerifyDeviceSigned(mso, doc, sessTrans); err != nil {
		return fmt.Errorf("failed to VerifyDeviceSigned: %v", err)
	}

	// 9.3.1 Inspection procedure for issuer data authentication
	// 1. Validate the certificate included in the MSO header according to 9.3.3.
	if err := VerifyCertificate(doc.IssuerSigned, roots, allowSelfCert); err != nil {
		return fmt.Errorf("failed to VerifyCertificate: %v", err)
	}

	// 2. Verify the digital signature of the IssuerAuth structure (see 9.1.2.4) using the working_public_
	//    key, working_public_key_parameters, and working_public_key_algorithm from the certificate
	//    validation procedure of step 1.
	if err := VerifyIssuerAuth(doc.IssuerSigned); err != nil {
		return fmt.Errorf("failed to VerifyIssuerAuth: %v", err)
	}

	// 3. Calculate the digest value for every IssuerSignedItem returned in the DeviceResponse structure
	//    according to 9.1.2.5 and verify that these calculated digests equal the corresponding digest values
	//    in the MSO.
	if err := VerifyDigests(doc.IssuerSigned, mso); err != nil {
		return fmt.Errorf("failed to VerifyDigests: %v", err)
	}

	// 4. Verify that the DocType in the MSO matches the relevant DocType in the Documents structure.
	if doc.DocType != mso.DocType {
		return fmt.Errorf("docType unmatche ")
	}

	// 5. Validate the elements in the ValidityInfo structure, i.e. verify that:
	// — the 'signed' date is within the validity period of the certificate in the MSO header,
	// — the current timestamp shall be equal or later than the ‘validFrom’ element,
	// — the 'validUntil' element shall be equal or later than the current timestamp.
	certificate, err := doc.IssuerSigned.Certificate()
	if err != nil {
		return fmt.Errorf("failed to get certificate: %v", err)
	}
	if mso.ValidityInfo.Signed.Before(certificate.NotBefore) || mso.ValidityInfo.Signed.After(certificate.NotAfter) {
		return fmt.Errorf("failed to veirfy signed date: %v", mso.ValidityInfo)
	}
	if Now.Before(mso.ValidityInfo.ValidFrom) || Now.After(mso.ValidityInfo.ValidUntil) {
		return fmt.Errorf("failed to check validity: %v", mso.ValidityInfo)
	}

	return nil
}

func VerifyDeviceSigned(mso *MobileSecurityObject, doc Document, sessionTranscript []byte) error {
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
		return fmt.Errorf("failed to get alg %w", err)
	}

	verifier, err := cose.NewVerifier(alg, pubKey)
	if err != nil {
		return fmt.Errorf("Failed to create NewVerifier: %v", err)
	}

	doc.DeviceSigned.DeviceAuth.DeviceSignature.Payload = deviceAuthenticationByte

	return doc.DeviceSigned.DeviceAuth.DeviceSignature.Verify(nil, verifier)
}

func VerifyDigests(issuerSigned IssuerSigned, mso *MobileSecurityObject) error {
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

func VerifyIssuerAuth(issuerSigned IssuerSigned) error {
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

func VerifyCertificate(issuerSigned IssuerSigned, roots *x509.CertPool, allowSelfCert bool) error {
	certs, err := issuerSigned.X5CertificateChain()
	if err != nil {
		return fmt.Errorf("Failed to get X5CertificateChain: %v", err)
	}

	if allowSelfCert {
		for _, cert := range certs {
			roots.AddCert(cert)
		}
	}

	// veirfy
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	// Perform the verification
	if _, err := certs[0].Verify(opts); err != nil {
		return fmt.Errorf("failed to verify certificate chain: %v", err)
	}
	return nil
}
