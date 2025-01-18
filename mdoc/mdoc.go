package mdoc

import (
	// "crypto"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"hash"
	"io"
	"log"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/kokukuma/mdoc-verifier/document"
	"github.com/veraison/go-cose"
)

type DeviceResponse struct {
	Version        string          `json:"version"`
	Documents      []Document      `json:"documents,omitempty"`
	DocumentErrors []DocumentError `json:"documentErrors,omitempty"`
	Status         uint            `json:"status"`
}

func (d DeviceResponse) GetDocument(docType document.DocType) (*Document, error) {
	for _, doc := range d.Documents {
		if doc.DocType == docType {
			return &doc, nil
		}
	}
	return nil, fmt.Errorf("failed to find doc: doctype=%s", docType)
}

type Document struct {
	DocType      document.DocType `json:"docType"`
	IssuerSigned IssuerSigned     `json:"issuerSigned"`
	DeviceSigned DeviceSigned     `json:"deviceSigned"`
	Errors       Errors           `json:"errors,omitempty"`
}

func (d *Document) GetElementValue(namespace document.NameSpace, elementIdentifier document.ElementIdentifier) (document.ElementValue, error) {
	if d.DocType == "" {
		return nil, fmt.Errorf("invalid document type")
	}
	return d.IssuerSigned.GetElementValue(namespace, elementIdentifier)
}

type IssuerSigned struct {
	NameSpaces IssuerNameSpaces          `json:"nameSpaces,omitempty"`
	IssuerAuth cose.UntaggedSign1Message `json:"issuerAuth"`
}

func (i *IssuerSigned) Alg() (cose.Algorithm, error) {
	if i.IssuerAuth.Headers.Protected == nil {
		return 0, fmt.Errorf("protected header is nil")
	}
	return i.IssuerAuth.Headers.Protected.Algorithm()
}

func (i *IssuerSigned) DocumentSigningKey() (*ecdsa.PublicKey, error) {
	certificate, err := i.DSCertificate()
	if err != nil {
		return nil, fmt.Errorf("Failed to get X5CertificateChain: %w", err)
	}

	documentSigningKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unexpected public key type: %T, expected *ecdsa.PublicKey", certificate.PublicKey)
	}
	return documentSigningKey, nil
}

func (i *IssuerSigned) DSCertificate() (*x509.Certificate, error) {
	certificates, err := i.DSCertificateChain()
	if err != nil {
		return nil, fmt.Errorf("Failed to get DSCertificateChain: %w", err)
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("no certificates in x5chain")
	}
	return certificates[0], nil
}

func (i *IssuerSigned) DSCertificateChain() ([]*x509.Certificate, error) {
	if i.IssuerAuth.Headers.Unprotected == nil {
		return nil, fmt.Errorf("missing unprotected headers")
	}

	rawX5Chain, ok := i.IssuerAuth.Headers.Unprotected[cose.HeaderLabelX5Chain]
	if !ok {
		return nil, fmt.Errorf("x5chain not found in unprotected headers")
	}

	var rawX5ChainBytes [][]byte
	switch v := rawX5Chain.(type) {
	case [][]byte:
		rawX5ChainBytes = v
	case []byte:
		rawX5ChainBytes = [][]byte{v}
	default:
		return nil, fmt.Errorf("unexpected x5chain type: %T", rawX5Chain)
	}

	if len(rawX5ChainBytes) == 0 {
		return nil, fmt.Errorf("empty x5chain")
	}

	certs := make([]*x509.Certificate, 0, len(rawX5ChainBytes))
	for _, certData := range rawX5ChainBytes {
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, fmt.Errorf("error parsing certificate: %w", err)
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

func (i *IssuerSigned) GetElementValue(namespace document.NameSpace, elementIdentifier document.ElementIdentifier) (document.ElementValue, error) {
	var itemBytes []IssuerSignedItemBytes

	for ns, ib := range i.NameSpaces {
		if ns == namespace {
			itemBytes = ib
		}
	}

	if itemBytes == nil {
		return nil, fmt.Errorf("namespace not found")
	}

	for _, ib := range itemBytes {
		item, err := ib.IssuerSignedItem()
		if err != nil {
			return nil, err
		}
		if item.ElementIdentifier == elementIdentifier {
			if tag, ok := item.ElementValue.(cbor.Tag); ok {
				return tag.Content, nil
			}
			return item.ElementValue, nil
		}
	}

	return nil, fmt.Errorf("element name not found")
}

func (i *IssuerSigned) IssuerSignedItems() (map[document.NameSpace][]IssuerSignedItem, error) {
	items := map[document.NameSpace][]IssuerSignedItem{}

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

type IssuerNameSpaces map[document.NameSpace][]IssuerSignedItemBytes

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

	var hasher hash.Hash
	switch alg {
	case "SHA-256":
		hasher = sha256.New()
	case "SHA-512":
		hasher = sha512.New()
	}

	hasher.Write(v)
	return hasher.Sum(nil), nil
}

type IssuerSignedItem struct {
	DigestID          uint                       `json:"digestID"`
	Random            []byte                     `json:"random"`
	ElementIdentifier document.ElementIdentifier `json:"elementIdentifier"`
	ElementValue      document.ElementValue      `json:"elementValue"`
}

type MobileSecurityObject struct {
	Version         string           `json:"version"`
	DigestAlgorithm string           `json:"digestAlgorithm"`
	ValueDigests    ValueDigests     `json:"valueDigests"`
	DeviceKeyInfo   DeviceKeyInfo    `json:"deviceKeyInfo"`
	DocType         document.DocType `json:"docType"`
	ValidityInfo    ValidityInfo     `json:"validityInfo"`
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

type ValueDigests map[document.NameSpace]DigestIDs

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

func (d *DeviceSigned) DeviceAuthenticationBytes(docType document.DocType, sessionTranscript []byte) ([]byte, error) {
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

type DeviceNameSpaces map[document.NameSpace]DeviceSignedItems

type DeviceSignedItems map[document.ElementIdentifier]document.ElementValue

type DeviceAuth struct {
	// DeviceSignature cose.UntaggedSign1Message `json:"deviceSignature"`
	// DeviceMac       cose.UntaggedSign1Message `json:"deviceMac"`
	DeviceSignature UntaggedSign1Message `json:"deviceSignature"`
	DeviceMac       UntaggedSign1Message `json:"deviceMac"`
}

type DocumentError map[document.DocType]ErrorCode

type Errors map[document.NameSpace]ErrorItems

type ErrorItems map[document.ElementIdentifier]ErrorCode

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

// Appleのシミュレータが返す値がdevieSignature不完全な状態で返してくる。
// Parse失敗するので一旦無視するために別に作る...
type UntaggedSign1Message cose.UntaggedSign1Message

func (m *UntaggedSign1Message) MarshalCBOR() ([]byte, error) {
	return (*cose.UntaggedSign1Message)(m).MarshalCBOR()
}

func (m *UntaggedSign1Message) UnmarshalCBOR(data []byte) error {
	// return nil
	var msg cose.UntaggedSign1Message

	err := cbor.Unmarshal(data, &msg)
	if err != nil {
		// Appleのシミュレータが返す値がdevieSignature不完全な状態で返してくる。
		// Parse失敗するので一旦無視
		*m = UntaggedSign1Message{}
		return nil
	}

	*m = UntaggedSign1Message(msg)
	return nil
}

func (m *UntaggedSign1Message) Sign(rand io.Reader, external []byte, signer cose.Signer) error {
	return (*cose.UntaggedSign1Message)(m).Sign(rand, external, signer)
}

func (m *UntaggedSign1Message) Verify(external []byte, verifier cose.Verifier) error {
	return (*cose.UntaggedSign1Message)(m).Verify(external, verifier)
}
