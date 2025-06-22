package document

//  https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l

type DCQLQuery struct {
	Credentials    []CredentialQuery    `json:"credentials"`
	CredentialSets []CredentialSetQuery `json:"credential_sets,omitempty"`
}

type CredentialQuery struct {
	ID        string           `json:"id"`
	Format    string           `json:"format"`
	Meta      *MetaConstraints `json:"meta,omitempty"`
	Claims    []ClaimQuery     `json:"claims,omitempty"`
	ClaimSets [][]string       `json:"claim_sets,omitempty"`
}

type MetaConstraints struct {
	// For sd-jwt
	VCTValues []string `json:"vct_values,omitempty"`

	// For mdoc
	DocType string `json:"doctype_value,omitempty"`

	Additional map[string]interface{} `json:"additional,omitempty"`
}

type ClaimQuery struct {
	ID     string        `json:"id,omitempty"`
	Path   []interface{} `json:"path,omitempty"`
	Values []interface{} `json:"values,omitempty"`
}

type CredentialSetQuery struct {
	Options  [][]string  `json:"options"`
	Required *bool       `json:"required,omitempty"`
	Purpose  interface{} `json:"purpose,omitempty"`
}

type Purpose struct {
	Description  string                 `json:"description"`
	Organization string                 `json:"organization"`
	Context      map[string]interface{} `json:"context,omitempty"`
}

type ClaimPathPointer []interface{}

func (cpp ClaimPathPointer) String() string {
	return ""
}
