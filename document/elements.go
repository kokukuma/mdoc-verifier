package document

import (
	"fmt"

	"github.com/kokukuma/mdoc-verifier/mdoc"
)

type Elements map[mdoc.DocType]map[mdoc.NameSpace][]mdoc.ElementIdentifier

func (d Elements) Selector() []Selector {
	var selectors []Selector
	for docType, Namespaces := range d {
		for ns, elems := range Namespaces {
			selectors = append(selectors, Selector{
				Format:    []string{"mdoc"},
				Retention: Retention{Days: 90},
				DocType:   string(docType),
				Fields:    FormatFields(ns, false, elems...),
			})
		}
	}
	return selectors
}

func (d Elements) DCQLQuery(id string) DCQLQuery {
	query := DCQLQuery{
		Credentials: make([]CredentialQuery, 0),
	}

	for docType, namespaces := range d {
		for ns, elems := range namespaces {
			claims := make([]ClaimQuery, len(elems))
			for i, elem := range elems {
				claims[i] = ClaimQuery{
					ID:   fmt.Sprintf("%s_%s", ns, elem),
					Path: []interface{}{string(ns), string(elem)},
				}
			}

			credQuery := CredentialQuery{
				ID:     string(docType),
				Format: "mso_mdoc",
				Meta: &MetaConstraints{
					DocType: string(docType),
					Additional: map[string]interface{}{
						"alg": []string{"ES256"},
					},
				},
				Claims: claims,
			}

			query.Credentials = append(query.Credentials, credQuery)
		}
	}

	credentialIDs := make([]string, 0)
	for docType := range d {
		credentialIDs = append(credentialIDs, string(docType))
	}

	query.CredentialSets = []CredentialSetQuery{
		{
			Options:  [][]string{credentialIDs},
			Required: ptr(true),
		},
	}

	return query
}

// bool型のポインタを返すヘルパー関数
func ptr(b bool) *bool {
	return &b
}

func (d Elements) PresentationDefinition(id string) PresentationDefinition {
	pd := PresentationDefinition{}
	for docType, Namespaces := range d {
		for ns, elems := range Namespaces {
			pd.InputDescriptors = append(pd.InputDescriptors, InputDescriptor{
				ID: string(docType),
				Format: Format{
					MsoMdoc: MsoMdoc{
						Alg: []string{"ES256"},
					},
				},
				Constraints: Constraints{
					LimitDisclosure: "required",
					Fields:          FormatPathField(ns, true, elems...),
				},
			})
		}
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
