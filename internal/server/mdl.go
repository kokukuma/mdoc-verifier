package server

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
	NameSpaces IssuerNameSpaces `json:"nameSpaces"`
	IssuerAuth []interface{}    `json:"issuerAuth"`
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

// TODO:
// DeviceMac:COSE_Mac0
// DeviceSignature:COSE_Sign1
type DeviceAuth struct {
	DeviceSignature []interface{} `json:"deviceSignature"`
	DeviceMac       []interface{} `json:"deviceMac"`
}

type DocumentError map[DocType]ErrorCode

type Errors map[NameSpace]ErrorItems

type ErrorItems map[DataElementIdentifier]ErrorCode

type ErrorCode int
