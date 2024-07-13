package mdoc

import "fmt"

// ISO_IEC_18013-5_2021(en).pdf

type Element struct {
	Namespace string
	Name      string
}

var (
	EUFamilyName = Element{
		Namespace: "eu.europa.ec.eudi.pid.1",
		Name:      "family_name",
	}
	FamilyName = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "family_name",
	}

	GivenName = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "given_name",
	}

	BirthDate = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "birth_date",
	}

	IssueDate = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "issue_date",
	}

	ExpiryDate = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "expiry_date",
	}

	IssuingCountry = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "issuing_country",
	}

	IssuingAuthority = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "issuing_authority",
	}

	DocumentNumber = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "document_number",
	}

	Portrait = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "portrait",
	}

	DrivingPrivileges = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "driving_privileges",
	}

	UnDistinguishingSign = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "un_distinguishing_sign",
	}

	AdministrativeNumber = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "administrative_number",
	}

	Sex = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "sex",
	}

	Height = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "height",
	}

	Weight = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "weight",
	}

	EyeColour = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "eye_colour",
	}

	HairColour = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "hair_colour",
	}

	BirthPlace = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "birth_place",
	}

	ResidentAddress = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "resident_address",
	}

	PortraitCaptureDate = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "portrait_capture_date",
	}

	AgeInYears = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "age_in_years",
	}

	AgeBirthYear = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "age_birth_year",
	}

	IssuingJurisdiction = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "issuing_jurisdiction",
	}

	Nationality = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "nationality",
	}

	ResidentCity = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "resident_city",
	}

	ResidentState = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "resident_state",
	}

	ResidentPostalCode = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "resident_postal_code",
	}

	ResidentCountry = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "resident_country",
	}

	// BiometricTemplate_X = Element{
	// 	Namespace: "org.iso.18013.5.1",
	// 	Name:      "biometric_template_x",
	// }

	FamilyNameNationalCharacter = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "family_name_national_character",
	}

	GivenNameNationalCharacter = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "given_name_national_character",
	}

	SignatureUsualMark = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "signature_usual_mark",
	}
)

// only 21 works now...why..
func AgeOver(age int) (Element, error) {
	if age < 0 && age > 99 {
		return Element{}, fmt.Errorf("unsupported range of age: %v", age)
	}
	return Element{
		Namespace: "org.iso.18013.5.1",
		Name:      fmt.Sprintf("age_over_%d", age),
	}, nil
}
