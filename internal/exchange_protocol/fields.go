package exchange_protocol

import "fmt"

// ISO_IEC_18013-5_2021(en).pdf
var (
	FamilyNameField = Field{
		Namespace:      "org.iso.18013.5.1",
		Name:           "family_name",
		IntentToRetain: false,
	}

	GivenNameField = Field{
		Namespace:      "org.iso.18013.5.1",
		Name:           "given_name",
		IntentToRetain: false,
	}

	AgeOver21Field = Field{
		Namespace:      "org.iso.18013.5.1",
		Name:           "age_over_21",
		IntentToRetain: false,
	}

	DocumentNumberField = Field{
		Namespace:      "org.iso.18013.5.1",
		Name:           "document_number",
		IntentToRetain: false,
	}

	PortraitField = Field{
		Namespace:      "org.iso.18013.5.1",
		Name:           "portrait",
		IntentToRetain: false,
	}

	DrivingPrivilegesField = Field{
		Namespace:      "org.iso.18013.5.1",
		Name:           "driving_privileges",
		IntentToRetain: false,
	}
)

func ConvPathField(fs ...Field) []PathField {
	result := []PathField{}

	for _, f := range fs {
		result = append(result, PathField{
			Path:           []string{fmt.Sprintf("$['%s']['%s']", f.Namespace, f.Name)},
			IntentToRetain: f.IntentToRetain,
		})
	}
	return result
}
