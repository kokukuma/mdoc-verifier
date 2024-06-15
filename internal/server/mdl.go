package server

import (
	// "crypto"

	"crypto"
	"time"

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
