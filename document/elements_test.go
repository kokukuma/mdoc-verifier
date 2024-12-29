package document

import (
	"reflect"
	"testing"
)

func TestElements_Selector(t *testing.T) {
	elements := Elements{
		"docType1": {
			"namespace1": {"elem1", "elem2"},
		},
	}

	expected := []Selector{
		{
			Format:    []string{"mdoc"},
			Retention: Retention{Days: 90},
			DocType:   "docType1",
			Fields:    FormatFields("namespace1", false, "elem1", "elem2"),
		},
	}

	result := elements.Selector()
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Selector() = %v, want %v", result, expected)
	}
}

func TestElements_PresentationDefinition(t *testing.T) {
	elements := Elements{
		"docType1": {
			"namespace1": {"elem1", "elem2"},
		},
	}

	expected := PresentationDefinition{
		InputDescriptors: []InputDescriptor{
			{
				ID: "docType1",
				Format: Format{
					MsoMdoc: MsoMdoc{
						Alg: []string{"ES256"},
					},
				},
				Constraints: Constraints{
					LimitDisclosure: "required",
					Fields:          FormatPathField("namespace1", true, "elem1", "elem2"),
				},
			},
		},
	}

	result := elements.PresentationDefinition("testID")
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("PresentationDefinition() = %v, want %v", result, expected)
	}
}

func TestFormatPathField(t *testing.T) {
	ns := NameSpace("namespace1")
	ids := []ElementIdentifier{"elem1", "elem2"}

	expected := []PathField{
		{
			Path:           []string{"$['namespace1']['elem1']"},
			IntentToRetain: true,
		},
		{
			Path:           []string{"$['namespace1']['elem2']"},
			IntentToRetain: true,
		},
	}

	result := FormatPathField(ns, true, ids...)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("FormatPathField() = %v, want %v", result, expected)
	}
}

func TestFormatFields(t *testing.T) {
	ns := NameSpace("namespace1")
	ids := []ElementIdentifier{"elem1", "elem2"}

	expected := []Field{
		{
			Namespace:      ns,
			Name:           "elem1",
			IntentToRetain: false,
		},
		{
			Namespace:      ns,
			Name:           "elem2",
			IntentToRetain: false,
		},
	}

	result := FormatFields(ns, false, ids...)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("FormatFields() = %v, want %v", result, expected)
	}
}
