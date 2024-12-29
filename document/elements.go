package document

import (
	"fmt"
)

type Elements map[DocType]map[NameSpace][]ElementIdentifier

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

func FormatPathField(ns NameSpace, retain bool, ids ...ElementIdentifier) []PathField {
	result := []PathField{}

	for _, id := range ids {
		result = append(result, PathField{
			Path:           []string{fmt.Sprintf("$['%s']['%s']", ns, id)},
			IntentToRetain: retain,
		})
	}
	return result
}

func FormatFields(ns NameSpace, retain bool, ids ...ElementIdentifier) []Field {
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
