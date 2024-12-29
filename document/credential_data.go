package document

// https://github.com/WICG/digital-credentials

// TODO: 沿ってるかどうか確認
// https://wicg.github.io/digital-credentials/

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
	Namespace      NameSpace         `json:"namespace"`
	Name           ElementIdentifier `json:"name"`
	IntentToRetain bool              `json:"intentToRetain"`
}

type Retention struct {
	Days int `json:"days"`
}
