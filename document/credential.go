package document

import (
	"fmt"

	"github.com/kokukuma/mdoc-verifier/mdoc"
)

type CredentialRequirement struct {
	CredentialType CredentialType
	Credentials    []Credential
}

type CredentialType string

type Credential struct {
	ID                string
	DocType           mdoc.DocType
	Namespace         mdoc.NameSpace
	ElementIdentifier []mdoc.ElementIdentifier
	Retention         int
	Required          bool
}

const (
	// ISO/IEC 18013-5 mobile Driving License
	CredentialTypeMDOC CredentialType = "mso_mdoc"

	// SD-JWT based Verifiable Credentials
	CredentialTypeSDJWT CredentialType = "dc+sd-jwt"

	// W3C Verifiable Credentials Data Model
	CredentialTypeVC CredentialType = "vc+jwt"
)

func (c CredentialRequirement) Selector() []Selector {
	var selectors []Selector
	for _, cred := range c.Credentials {
		selectors = append(selectors, Selector{
			Format:    []string{string(c.CredentialType)}, // TODO: check if it is work; original = mdoc
			Retention: Retention{Days: cred.Retention},
			DocType:   string(cred.DocType),
			Fields: FormatFields(
				cred.Namespace,
				intentToRetain(cred.Retention),
				cred.ElementIdentifier...),
		})

	}
	return selectors
}

func (c CredentialRequirement) DCQLQuery() DCQLQuery {
	query := DCQLQuery{
		Credentials: make([]CredentialQuery, 0),
	}

	for _, cred := range c.Credentials {
		claims := make([]ClaimQuery, len(cred.ElementIdentifier))
		for i, elem := range cred.ElementIdentifier {
			claims[i] = ClaimQuery{
				ID:   fmt.Sprintf("%s_%s", cred.Namespace, elem),
				Path: []interface{}{string(cred.Namespace), string(elem)},
			}
		}

		credQuery := CredentialQuery{
			ID:     cred.ID,
			Format: string(c.CredentialType),
			Meta: &MetaConstraints{
				DocType: string(cred.DocType),
				Additional: map[string]interface{}{
					"alg": []string{"ES256"},
				},
			},
			Claims: claims,
		}
		query.Credentials = append(query.Credentials, credQuery)
	}

	// TODO

	// query.CredentialSets = []CredentialSetQuery{
	// 	{
	// 		Options:  [][]string{[]string{id}},
	// 		Required: ptr(c.Required),
	// 	},
	// }

	return query
}

// bool型のポインタを返すヘルパー関数
func ptr(b bool) *bool {
	return &b
}

func intentToRetain(retainDay int) bool {
	return retainDay > 0
}

func (c CredentialRequirement) PresentationDefinition() PresentationDefinition {
	pd := PresentationDefinition{}
	for _, cred := range c.Credentials {
		LimitDisclosure := "optional"
		if cred.Required {
			LimitDisclosure = "required"
		}

		pd.InputDescriptors = append(pd.InputDescriptors, InputDescriptor{
			// ID: string(cred.DocType),
			ID: cred.ID,
			Format: Format{
				MsoMdoc: MsoMdoc{
					Alg: []string{"ES256"},
				},
			},
			Constraints: Constraints{
				LimitDisclosure: LimitDisclosure,
				Fields: FormatPathField(
					cred.Namespace,
					intentToRetain(cred.Retention),
					cred.ElementIdentifier...),
			},
		})
	}

	return pd
}

func FormatPathField(ns mdoc.NameSpace, retain bool, ids ...mdoc.ElementIdentifier) []PathField {
	result := []PathField{}

	for _, id := range ids {
		result = append(result, PathField{
			Path:           []string{fmt.Sprintf("$['%s']['%s']", ns, id)},
			IntentToRetain: retain,
		})
	}
	return result
}

func FormatFields(ns mdoc.NameSpace, retain bool, ids ...mdoc.ElementIdentifier) []Field {
	var fields []Field

	for _, id := range ids {
		fields = append(fields, Field{
			Namespace:      ns,
			Name:           id,
			IntentToRetain: retain,
		})
	}
	return fields
}
