package document

// TODO: 沿ってるかどうか確認
// https://identity.foundation/presentation-exchange/spec/v2.0.0/

type PresentationDefinition struct {
	ID               string            `json:"id"`
	InputDescriptors []InputDescriptor `json:"input_descriptors"`
}

type InputDescriptor struct {
	Name                   string                  `json:"name"`
	ID                     string                  `json:"id"`
	Format                 Format                  `json:"format,omitempty"`
	Constraints            Constraints             `json:"constraints"`
	Purpose                string                  `json:"purpose"`
	SubmissionRequirements []SubmissionRequirement `json:"submission_requirements"`
	Group                  []string                `json:"group"`
}

type SubmissionRequirement struct {
	Name       string                  `json:"name,omitempty"`
	Purpose    string                  `json:"purpose,omitempty"`
	Rule       string                  `json:"rule"`            // "all" または "pick"
	Count      int                     `json:"count,omitempty"` // minimum: 1
	Min        int                     `json:"min,omitempty"`   // minimum: 0
	Max        int                     `json:"max,omitempty"`   // minimum: 0
	From       string                  `json:"from,omitempty"`
	FromNested []SubmissionRequirement `json:"from_nested,omitempty"`
}

type Constraints struct {
	LimitDisclosure string        `json:"limit_disclosure,omitempty"`
	Fields          []PathField   `json:"fields,omitempty"`
	Statuses        *Statuses     `json:"statuses,omitempty"`
	SubjectIsIssuer string        `json:"subject_is_issuer,omitempty"`
	IsHolder        []IsHolder    `json:"is_holder,omitempty"`
	SameSubject     []SameSubject `json:"same_subject,omitempty"`
}

type Statuses struct {
	Active    *StatusDirective `json:"active,omitempty"`
	Suspended *StatusDirective `json:"suspended,omitempty"`
	Revoked   *StatusDirective `json:"revoked,omitempty"`
}

type StatusDirective struct {
	Directive string   `json:"directive"` // "required", "allowed", "disallowed"
	Type      []string `json:"type,omitempty"`
}

type SameSubject struct {
	FieldID   []string `json:"field_id"`
	Directive string   `json:"directive"` // "required" または "preferred"
}

type IsHolder struct {
	FieldID   []string `json:"field_id"`
	Directive string   `json:"directive"` // "required" または "preferred"
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
	ID             string   `json:"id,omitempty"`
	Purpose        string   `json:"purpose,omitempty"`
	Name           string   `json:"name,omitempty"`
	Optional       bool     `json:"optional,omitempty"`
	Predicate      string   `json:"predicate,omitempty"`
}

type Filter struct {
	Type    string `json:"type,omitempty"`
	Pattern string `json:"pattern,omitempty"`
}
