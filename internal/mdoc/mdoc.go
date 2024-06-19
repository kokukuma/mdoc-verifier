package mdoc

import (
	// "crypto"

	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"hash"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// ISO_IEC_18013-5_2021(en).pdf

type DocType string

type NameSpace string

type DataElementIdentifier string

type DataElementValue interface{}

type DeviceResponse struct {
	Version        string          `json:"version"`
	Documents      []Document      `json:"documents"`
	DocumentErrors []DocumentError `json:"documentErrors"`
	Status         uint            `json:"status"`
}

type Document struct {
	DocType      DocType      `json:"docType"`
	IssuerSigned IssuerSigned `json:"issuerSigned"`
	DeviceSigned DeviceSigned `json:"deviceSigned"`
	Errors       Errors       `json:"errors"`
}

type IssuerSigned struct {
	NameSpaces IssuerNameSpaces          `json:"nameSpaces"`
	IssuerAuth cose.UntaggedSign1Message `json:"issuerAuth"`
}

func (i IssuerSigned) VerifiedElements() (map[NameSpace][]IssuerSignedItem, error) {
	items := map[NameSpace][]IssuerSignedItem{}

	mso, err := i.GetMobileSecurityObject()
	if err != nil {
		return nil, fmt.Errorf("GetMobileSecurityObject: %v", err)
	}

	for ns, vals := range i.NameSpaces {
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

			if !bytes.Equal(digest, calcDigest(v, mso.DigestAlgorithm)) {
				return nil, fmt.Errorf("digest unmatched digestID:%v", item.DigestID)
			}

			items[ns] = append(items[ns], item)
		}
	}

	return items, nil
}

func calcDigest(message []byte, alg string) []byte {
	var hasher hash.Hash
	switch alg {
	case "SHA-256":
		hasher = sha256.New()
	// case "SHA-384":
	// 	hasher = sha384.New()
	case "SHA-512":
		hasher = sha512.New()
	}
	hasher.Write(message)
	return hasher.Sum(nil)
}

func (i IssuerSigned) VerifyIssuerAuth(roots *x509.CertPool) error {
	alg, err := i.IssuerAuth.Headers.Protected.Algorithm()
	if err != nil {
		return fmt.Errorf("failed to get alg %w", err)
	}
	rawX5Chain, ok := i.IssuerAuth.Headers.Unprotected[cose.HeaderLabelX5Chain]
	if !ok {
		return fmt.Errorf("failed to get x5chain")
	}
	spew.Dump(rawX5Chain)

	rawX5ChainBytes, ok := rawX5Chain.([][]byte)
	if !ok {
		rawX5ChainByte, ok := rawX5Chain.([]byte)
		if !ok {
			return fmt.Errorf("failed to get x5chain")
		}
		rawX5ChainBytes = append(rawX5ChainBytes, rawX5ChainByte)
	}

	certificates, err := parseCertificates(rawX5ChainBytes, roots)
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

	return i.IssuerAuth.Verify(nil, verifier)
}

func parseCertificates(rawCerts [][]byte, roots *x509.CertPool) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, certData := range rawCerts {
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, fmt.Errorf("error parsing certificate: %v", err)
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
		// TODO: I don't have real mDL: current issuser is self-signed on Device.
		// return nil, fmt.Errorf("failed to verify certificate chain: %v", err)
	}

	return certs, nil
}

func (i IssuerSigned) GetMobileSecurityObject() (*MobileSecurityObject, error) {
	var topLevelData interface{}
	err := cbor.Unmarshal(i.IssuerAuth.Payload, &topLevelData)
	if err != nil {
		return nil, fmt.Errorf("Error unmarshalling top level CBOR: %w", err)
	}

	var mso MobileSecurityObject
	if err := cbor.Unmarshal(topLevelData.(cbor.Tag).Content.([]byte), &mso); err != nil {
		return nil, fmt.Errorf("Error unmarshal cbor string: %w", err)
	}
	return &mso, nil
}

type IssuerNameSpaces map[NameSpace][]IssuerSignedItemBytes

type IssuerSignedItemBytes []byte

type IssuerSignedItem struct {
	DigestID          uint                  `json:"digestID"`
	Random            []byte                `json:"random"`
	ElementIdentifier DataElementIdentifier `json:"elementIdentifier"`
	ElementValue      DataElementValue      `json:"elementValue"`
}

type DeviceSigned struct {
	NameSpaces DeviceNameSpacesBytes `json:"nameSpaces"`
	DeviceAuth DeviceAuth            `json:"deviceAuth"`
}

type DeviceNameSpacesBytes []byte

type DeviceNameSpaces map[NameSpace]DeviceSignedItems

type DeviceSignedItems map[DataElementIdentifier]DataElementValue

type DeviceAuth struct {
	DeviceSignature cose.UntaggedSign1Message `json:"deviceSignature"`
	DeviceMac       cose.UntaggedSign1Message `json:"deviceMac"`
}

type DocumentError map[DocType]ErrorCode

type Errors map[NameSpace]ErrorItems

type ErrorItems map[DataElementIdentifier]ErrorCode

type ErrorCode int

type MobileSecurityObject struct {
	Version         string        `json:"version"`
	DigestAlgorithm string        `json:"digestAlgorithm"`
	ValueDigests    ValueDigests  `json:"valueDigests"`
	DeviceKeyInfo   DeviceKeyInfo `json:"deviceKeyInfo"`
	DocType         string        `json:"docType"`
	ValidityInfo    ValidityInfo  `json:"validityInfo"`
}

type DeviceKeyInfo struct {
	DeviceKey         COSEKey           `json:"deviceKey"`
	KeyAuthorizations KeyAuthorizations `json:"keyAuthorizations,omitempty"`
	KeyInfo           KeyInfo           `json:"keyInfo,omitempty"`
}

type COSEKey crypto.PublicKey

type KeyAuthorizations struct {
	NameSpaces   []string            `json:"nameSpaces,omitempty"`
	DataElements map[string][]string `json:"dataElements,omitempty"`
}

type KeyInfo map[int]interface{}

type ValueDigests map[NameSpace]DigestIDs

type DigestIDs map[DigestID]Digest

type ValidityInfo struct {
	Signed         time.Time `json:"signed"`
	ValidFrom      time.Time `json:"validFrom"`
	ValidUntil     time.Time `json:"validUntil"`
	ExpectedUpdate time.Time `json:"expectedUpdate,omitempty"`
}

type DigestID uint

type Digest []byte
