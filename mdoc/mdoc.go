package mdoc

import (
	// "crypto"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/kokukuma/identity-credential-api-demo/protocol"
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

func (i *IssuerSigned) Alg() (cose.Algorithm, error) {
	return i.IssuerAuth.Headers.Protected.Algorithm()
}

func (i *IssuerSigned) DocumentSigningKey() (*ecdsa.PublicKey, error) {
	certificate, err := i.Certificate()
	if err != nil {
		return nil, fmt.Errorf("Failed to get X5CertificateChain: %v", err)
	}

	documentSigningKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Failed to parseCertificates: %v", err)
	}
	return documentSigningKey, nil
}

func (i *IssuerSigned) Certificate() (*x509.Certificate, error) {
	certificates, err := i.X5CertificateChain()
	if err != nil {
		return nil, fmt.Errorf("Failed to get X5CertificateChain: %v", err)
	}
	return certificates[0], nil
}

func (i *IssuerSigned) X5CertificateChain() ([]*x509.Certificate, error) {

	rawX5Chain, ok := i.IssuerAuth.Headers.Unprotected[cose.HeaderLabelX5Chain]
	if !ok {
		return nil, fmt.Errorf("failed to get x5chain")
	}

	rawX5ChainBytes, ok := rawX5Chain.([][]byte)
	if !ok {
		rawX5ChainByte, ok := rawX5Chain.([]byte)
		if !ok {
			return nil, fmt.Errorf("failed to get x5chain")
		}
		rawX5ChainBytes = append(rawX5ChainBytes, rawX5ChainByte)
	}

	var certs []*x509.Certificate
	for _, certData := range rawX5ChainBytes {
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, fmt.Errorf("error parsing certificate: %v", err)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

func (i *IssuerSigned) MobileSecurityObject() (*MobileSecurityObject, error) {
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

func (i *IssuerSigned) IssuerSignedItems() (map[NameSpace][]IssuerSignedItem, error) {
	items := map[NameSpace][]IssuerSignedItem{}

	for ns, itemBytes := range i.NameSpaces {
		for _, itemByte := range itemBytes {
			item, err := itemByte.IssuerSignedItem()
			if err != nil {
				return nil, err
			}
			items[ns] = append(items[ns], item)
		}
	}
	return items, nil
}

type IssuerNameSpaces map[NameSpace][]IssuerSignedItemBytes

type IssuerSignedItemBytes cbor.RawMessage

func (i IssuerSignedItemBytes) IssuerSignedItem() (IssuerSignedItem, error) {
	var item IssuerSignedItem
	if err := cbor.Unmarshal(i, &item); err != nil {
		return IssuerSignedItem{}, err
	}
	return item, nil
}

func (i *IssuerSignedItemBytes) Digest(alg string) ([]byte, error) {
	v, err := cbor.Marshal(cbor.Tag{
		Number:  24,
		Content: i,
	})
	if err != nil {
		return nil, err
	}
	return protocol.Digest(v, alg), nil
}

type IssuerSignedItem struct {
	DigestID          uint                  `json:"digestID"`
	Random            []byte                `json:"random"`
	ElementIdentifier DataElementIdentifier `json:"elementIdentifier"`
	ElementValue      DataElementValue      `json:"elementValue"`
}

type MobileSecurityObject struct {
	Version         string        `json:"version"`
	DigestAlgorithm string        `json:"digestAlgorithm"`
	ValueDigests    ValueDigests  `json:"valueDigests"`
	DeviceKeyInfo   DeviceKeyInfo `json:"deviceKeyInfo"`
	DocType         DocType       `json:"docType"`
	ValidityInfo    ValidityInfo  `json:"validityInfo"`
}

func (m *MobileSecurityObject) DeviceKey() (*ecdsa.PublicKey, error) {
	// TODO: algによって変えたほうが.
	return parseECDSA(m.DeviceKeyInfo.DeviceKey)
}

type DeviceKeyInfo struct {
	DeviceKey         COSEKey           `json:"deviceKey"`
	KeyAuthorizations KeyAuthorizations `json:"keyAuthorizations,omitempty"`
	KeyInfo           KeyInfo           `json:"keyInfo,omitempty"`
}

type COSEKey struct {
	Kty       int             `cbor:"1,keyasint,omitempty"`
	Kid       []byte          `cbor:"2,keyasint,omitempty"`
	Alg       int             `cbor:"3,keyasint,omitempty"`
	KeyOpts   int             `cbor:"4,keyasint,omitempty"`
	IV        []byte          `cbor:"5,keyasint,omitempty"`
	CrvOrNOrK cbor.RawMessage `cbor:"-1,keyasint,omitempty"` // K for symmetric keys, Crv for elliptic curve keys, N for RSA modulus
	XOrE      cbor.RawMessage `cbor:"-2,keyasint,omitempty"` // X for curve x-coordinate, E for RSA public exponent
	Y         cbor.RawMessage `cbor:"-3,keyasint,omitempty"` // Y for curve y-cooridate
	D         []byte          `cbor:"-4,keyasint,omitempty"`
}

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

type DeviceSigned struct {
	NameSpaces DeviceNameSpacesBytes `json:"nameSpaces"`
	DeviceAuth DeviceAuth            `json:"deviceAuth"`
}

func (d *DeviceSigned) Alg() (cose.Algorithm, error) {
	return d.DeviceAuth.DeviceSignature.Headers.Protected.Algorithm()
}

func (d *DeviceSigned) DeviceAuthenticationBytes(docType DocType, sessionTranscript []byte) ([]byte, error) {
	deviceAuthentication := []interface{}{
		"DeviceAuthentication",
		cbor.RawMessage(sessionTranscript),
		docType,
		cbor.Tag{Number: 24, Content: d.NameSpaces},
	}
	da, err := cbor.Marshal(deviceAuthentication)
	if err != nil {
		return nil, fmt.Errorf("error encoding transcript: %v", err)
	}
	deviceAuthenticationByte, err := cbor.Marshal(cbor.Tag{Number: 24, Content: da})
	if err != nil {
		return nil, fmt.Errorf("failed to Marshal cbor %w", err)
	}
	return deviceAuthenticationByte, nil
}

type DeviceNameSpacesBytes cbor.RawMessage

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
