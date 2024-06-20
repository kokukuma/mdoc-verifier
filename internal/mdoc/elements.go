package mdoc

// ISO_IEC_18013-5_2021(en).pdf

type Element struct {
	Namespace string
	Name      string
}

var (
	FamilyName = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "family_name",
	}

	GivenName = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "given_name",
	}

	AgeOver21 = Element{
		Namespace: "org.iso.18013.5.1",
		Name:      "age_over_21",
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
)
