package credential_data

import (
	"fmt"

	doc "github.com/kokukuma/mdoc-verifier/document"
)

type Documents map[doc.DocType]map[doc.NameSpace][]doc.ElementIdentifier

func (d Documents) AddDocument(doc doc.DocType, ns doc.NameSpace, elems ...doc.ElementIdentifier) {
	d[doc][ns] = elems
}

func (d Documents) Selector() []Selector {
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

func (d Documents) PresentationDefinition(id string) PresentationDefinition {
	pd := PresentationDefinition{
		ID: id,
		InputDescriptors: []InputDescriptor{
			{
				ID: "eu.europa.ec.eudi.loyalty.1",
				// ID:      "eu.europa.ec.eudi.pid.1",
				Name:    "EUDI PID",
				Purpose: "We need to verify you are over 18 using your PID",
				Format: Format{
					MsoMdoc: MsoMdoc{
						Alg: []string{
							"ES256",
							"ES384",
							"ES512",
						},
					},
				},
				Constraints: Constraints{
					Fields: []PathField{
						{
							Path: []string{"$['eu.europa.ec.eudi.loyalty.1']['family_name']"},
							// Path:           []string{"$['eu.europa.ec.eudi.pid.1']['family_name']"},
							IntentToRetain: false,
						},
					},
				},
			},
		},
	}
	//	for docType, Namespaces := range d {
	//		for ns, elems := range Namespaces {
	//			pd.InputDescriptors = append(pd.InputDescriptors, InputDescriptor{
	//				ID: string(docType),
	//				Format: Format{
	//					MsoMdoc: MsoMdoc{
	//						Alg: []string{"ES256"},
	//					},
	//				},
	//				Constraints: Constraints{
	//					LimitDisclosure: "required",
	//					Fields:          FormatPathField(ns, true, elems...),
	//				},
	//			})
	//		}
	//	}
	return pd
}

func FormatPathField(ns doc.NameSpace, retain bool, ids ...doc.ElementIdentifier) []PathField {
	result := []PathField{}

	for _, id := range ids {
		result = append(result, PathField{
			Path:           []string{fmt.Sprintf("$['%s']['%s']", ns, id)},
			IntentToRetain: retain,
		})
	}
	return result
}

func FormatFields(ns doc.NameSpace, retain bool, ids ...doc.ElementIdentifier) []Field {
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
