package document

// MEMO: ここに沿ってるだけ...
// https://digital-credentials.dev/

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
