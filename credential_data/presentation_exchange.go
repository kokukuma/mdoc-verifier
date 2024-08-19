package credential_data

// https://identity.foundation/presentation-exchange/spec/v2.0.0/

type PresentationDefinition struct {
	ID               string            `json:"id"`
	InputDescriptors []InputDescriptor `json:"input_descriptors"`
}

type InputDescriptor struct {
	Name        string      `json:"name"`
	ID          string      `json:"id"`
	Format      Format      `json:"format,omitempty"`
	Constraints Constraints `json:"constraints"`
	Purpose     string      `json:"purpose"`
	// TODO:
	SubmissionRequirements interface{} `json:"submission_requirements"`
	Group                  []string    `json:"group"`
}

type Constraints struct {
	LimitDisclosure string      `json:"limit_disclosure,omitempty"`
	Fields          []PathField `json:"fields,omitempty"`
}

type Format struct {
	MsoMdoc   MsoMdoc   `json:"mso_mdoc,omitempty"`
	LdpVP     LdpVP     `json:"ldp_vp,omitempty"`
	JwtVCJSON JwtVCJSON `json:"jwt_vc_json,omitempty"`
}

type MsoMdoc struct {
	Alg []string `json:"alg,omitempty"`
}

type JwtVCJSON struct {
	Alg []string `json:"alg,omitempty"`
}

type LdpVP struct {
	ProofType []string `json:"proof_type,omitempty"`
}

type PathField struct {
	Path           []string `json:"path"`
	Filter         Filter   `json:"filter,omitempty"`
	IntentToRetain bool     `json:"intent_to_retain"`
}

type Filter struct {
	Type    string `json:"type,omitempty"`
	Pattern string `json:"pattern,omitempty"`
}
