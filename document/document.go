package document

type DocType string

var (
	IsoMDL  DocType = "org.iso.18013.5.1.mDL"
	EudiPid DocType = "eu.europa.ec.eudi.pid.1"
	// EudiLoyalty DocType = "eu.europa.ec.eudi.loyalty.1"
)

type NameSpace string

var (
	ISO1801351 NameSpace = "org.iso.18013.5.1"
	EUDIPID1   NameSpace = "eu.europa.ec.eudi.pid.1"
	// EUDILOYALTY NameSpace = "eu.europa.ec.eudi.loyalty.1"
)

type ElementIdentifier string

type ElementValue interface{}

var (
	// Namespace: "org.iso.18013.5.1"
	IsoFamilyName                  ElementIdentifier = "family_name"
	IsoGivenName                   ElementIdentifier = "given_name"
	IsoBirthDate                   ElementIdentifier = "birth_date"
	IsoIssueDate                   ElementIdentifier = "expiry_date"
	IsoIssuingCountry              ElementIdentifier = "issuing_country"
	IsoIssuingAuthority            ElementIdentifier = "issuing_authority"
	IsoDocumentNumber              ElementIdentifier = "document_number"
	IsoPortrait                    ElementIdentifier = "portrait"
	IsoDrivingPrivileges           ElementIdentifier = "driving_privileges"
	IsoUnDistinguishingSign        ElementIdentifier = "un_distinguishing_sign"
	IsoAdministrativeNumber        ElementIdentifier = "administrative_number"
	IsoSex                         ElementIdentifier = "sex"
	IsoHeight                      ElementIdentifier = "height"
	IsoWeight                      ElementIdentifier = "weight"
	IsoEyeColour                   ElementIdentifier = "eye_colour"
	IsoHairColour                  ElementIdentifier = "hair_colour"
	IsoBirthPlace                  ElementIdentifier = "birth_place"
	IsoResidentAddress             ElementIdentifier = "resident_address"
	IsoPortraitCaptureDate         ElementIdentifier = "portrait_capture_date"
	IsoAgeInYears                  ElementIdentifier = "age_in_years"
	IsoAgeBirthYear                ElementIdentifier = "age_birth_year"
	IsoIssuingJurisdiction         ElementIdentifier = "issuing_jurisdiction"
	IsoNationality                 ElementIdentifier = "nationality"
	IsoResidentCity                ElementIdentifier = "resident_city"
	IsoResidentState               ElementIdentifier = "resident_state"
	IsoResidentPostalCode          ElementIdentifier = "resident_postal_code"
	IsoResidentCountry             ElementIdentifier = "resident_country"
	IsoFamilyNameNationalCharacter ElementIdentifier = "family_name_national_character"
	IsoGivenNameNationalCharacter  ElementIdentifier = "given_name_national_character"
	IsoSignatureUsualMark          ElementIdentifier = "signature_usual_mark"

	// Namespace: "eu.europa.ec.eudi.pid.1"
	EudiFamilyName           ElementIdentifier = "family_name"
	EudiGivenName            ElementIdentifier = "given_name"
	EudiBirthDate            ElementIdentifier = "birth_date"
	EudiAgeOver18            ElementIdentifier = "age_over_18"
	EudiAgeInYears           ElementIdentifier = "age_in_years"
	EudiAgeBirthYear         ElementIdentifier = "age_birth_year"
	EudiGivenNameBirth       ElementIdentifier = "given_name_birth"
	EudiBirthPlace           ElementIdentifier = "birth_place"
	EudiBirthCountry         ElementIdentifier = "birth_country"
	EudiBirthState           ElementIdentifier = "birth_state"
	EudiBirthCity            ElementIdentifier = "birth_city"
	EudiResidentAddress      ElementIdentifier = "resident_address"
	EudiResidentCountry      ElementIdentifier = "resident_country"
	EudiResidentState        ElementIdentifier = "resident_state"
	EudiResidentCity         ElementIdentifier = "resident_city"
	EudiResidentPostalCode   ElementIdentifier = "resident_postal_code"
	EudiResidentStreet       ElementIdentifier = "resident_street"
	EudiResidentHouseNumber  ElementIdentifier = "resident_house_number"
	EudiGender               ElementIdentifier = "gender"
	EudiNationality          ElementIdentifier = "nationality"
	EudiIssuanceDate         ElementIdentifier = "issuance_date"
	EudiExpiryDate           ElementIdentifier = "expiry_date"
	EudiIssuingAuthority     ElementIdentifier = "issuing_authority"
	EudiDocumentNumber       ElementIdentifier = "document_number"
	EudiAdministrativeNumber ElementIdentifier = "administrative_number"
	EudiIssuingCountry       ElementIdentifier = "issuing_country"
	EudiIssuingJurisdiction  ElementIdentifier = "issuing_jurisdiction"

	// EudiLoyaltyEmailAddress ElementIdentifier = "email_address"
)

//
//
// // only 21 works now...why..
// func AgeOver(age int) (Element, error) {
// 	if age < 0 && age > 99 {
// 		return Element{}, fmt.Errorf("unsupported range of age: %v", age)
// 	}
// 	return Element{
// 		Namespace: "org.iso.18013.5.1",
// 		Name:      fmt.Sprintf("age_over_%d", age),
// 	}, nil
// }
// 	// BiometricTemplate_X = Element{
// 	// 	Namespace: "org.iso.18013.5.1",
// 	// 	Name:      "biometric_template_x",
// 	// }
//
