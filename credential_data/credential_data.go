package credential_data

// https://github.com/WICG/digital-credentials

import (
	doc "github.com/kokukuma/mdoc-verifier/document"
)

type IdentityRequest struct {
	Selector        Selector `json:"selector"`
	Nonce           string   `json:"nonce"`
	ReaderPublicKey string   `json:"readerPublicKey"`
}

type Selector struct {
	Format    []string  `json:"format"`
	Retention Retention `json:"retention"`
	DocType   string    `json:"doctype"`
	Fields    []Field   `json:"fields"`
}

type Field struct {
	Namespace      doc.NameSpace         `json:"namespace"`
	Name           doc.ElementIdentifier `json:"name"`
	IntentToRetain bool                  `json:"intentToRetain"`
}

type Retention struct {
	Days int `json:"days"`
}
