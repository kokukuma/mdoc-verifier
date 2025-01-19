package document

import "github.com/kokukuma/mdoc-verifier/mdoc"

// MEMO: ここに沿ってるだけ...
// https://digital-credentials.dev/

type Selector struct {
	Format    []string  `json:"format"`
	Retention Retention `json:"retention"`
	DocType   string    `json:"doctype"`
	Fields    []Field   `json:"fields"`
}

type Field struct {
	Namespace      mdoc.NameSpace         `json:"namespace"`
	Name           mdoc.ElementIdentifier `json:"name"`
	IntentToRetain bool                   `json:"intentToRetain"`
}

type Retention struct {
	Days int `json:"days"`
}
