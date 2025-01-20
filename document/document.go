package document

import (
	"fmt"

	"github.com/kokukuma/mdoc-verifier/mdoc"
)

var (
	IsoMDL  mdoc.DocType = "org.iso.18013.5.1.mDL"
	EudiPid mdoc.DocType = "eu.europa.ec.eudi.pid.1"
)

var (
	ISO1801351 mdoc.NameSpace = "org.iso.18013.5.1"
	EUDIPID1   mdoc.NameSpace = "eu.europa.ec.eudi.pid.1"
)

var (
	// Namespace: "org.iso.18013.5.1"
	IsoFamilyName                  mdoc.ElementIdentifier = "family_name"
	IsoGivenName                   mdoc.ElementIdentifier = "given_name"
	IsoBirthDate                   mdoc.ElementIdentifier = "birth_date"
	IsoIssueDate                   mdoc.ElementIdentifier = "expiry_date"
	IsoIssuingCountry              mdoc.ElementIdentifier = "issuing_country"
	IsoIssuingAuthority            mdoc.ElementIdentifier = "issuing_authority"
	IsoDocumentNumber              mdoc.ElementIdentifier = "document_number"
	IsoPortrait                    mdoc.ElementIdentifier = "portrait"
	IsoDrivingPrivileges           mdoc.ElementIdentifier = "driving_privileges"
	IsoUnDistinguishingSign        mdoc.ElementIdentifier = "un_distinguishing_sign"
	IsoAdministrativeNumber        mdoc.ElementIdentifier = "administrative_number"
	IsoSex                         mdoc.ElementIdentifier = "sex"
	IsoHeight                      mdoc.ElementIdentifier = "height"
	IsoWeight                      mdoc.ElementIdentifier = "weight"
	IsoEyeColour                   mdoc.ElementIdentifier = "eye_colour"
	IsoHairColour                  mdoc.ElementIdentifier = "hair_colour"
	IsoBirthPlace                  mdoc.ElementIdentifier = "birth_place"
	IsoResidentAddress             mdoc.ElementIdentifier = "resident_address"
	IsoPortraitCaptureDate         mdoc.ElementIdentifier = "portrait_capture_date"
	IsoAgeInYears                  mdoc.ElementIdentifier = "age_in_years"
	IsoAgeBirthYear                mdoc.ElementIdentifier = "age_birth_year"
	IsoIssuingJurisdiction         mdoc.ElementIdentifier = "issuing_jurisdiction"
	IsoNationality                 mdoc.ElementIdentifier = "nationality"
	IsoResidentCity                mdoc.ElementIdentifier = "resident_city"
	IsoResidentState               mdoc.ElementIdentifier = "resident_state"
	IsoResidentPostalCode          mdoc.ElementIdentifier = "resident_postal_code"
	IsoResidentCountry             mdoc.ElementIdentifier = "resident_country"
	IsoFamilyNameNationalCharacter mdoc.ElementIdentifier = "family_name_national_character"
	IsoGivenNameNationalCharacter  mdoc.ElementIdentifier = "given_name_national_character"
	IsoSignatureUsualMark          mdoc.ElementIdentifier = "signature_usual_mark"

	// Namespace: "eu.europa.ec.eudi.pid.1"
	EudiFamilyName           mdoc.ElementIdentifier = "family_name"
	EudiGivenName            mdoc.ElementIdentifier = "given_name"
	EudiBirthDate            mdoc.ElementIdentifier = "birth_date"
	EudiAgeOver18            mdoc.ElementIdentifier = "age_over_18"
	EudiAgeInYears           mdoc.ElementIdentifier = "age_in_years"
	EudiAgeBirthYear         mdoc.ElementIdentifier = "age_birth_year"
	EudiGivenNameBirth       mdoc.ElementIdentifier = "given_name_birth"
	EudiBirthPlace           mdoc.ElementIdentifier = "birth_place"
	EudiBirthCountry         mdoc.ElementIdentifier = "birth_country"
	EudiBirthState           mdoc.ElementIdentifier = "birth_state"
	EudiBirthCity            mdoc.ElementIdentifier = "birth_city"
	EudiResidentAddress      mdoc.ElementIdentifier = "resident_address"
	EudiResidentCountry      mdoc.ElementIdentifier = "resident_country"
	EudiResidentState        mdoc.ElementIdentifier = "resident_state"
	EudiResidentCity         mdoc.ElementIdentifier = "resident_city"
	EudiResidentPostalCode   mdoc.ElementIdentifier = "resident_postal_code"
	EudiResidentStreet       mdoc.ElementIdentifier = "resident_street"
	EudiResidentHouseNumber  mdoc.ElementIdentifier = "resident_house_number"
	EudiGender               mdoc.ElementIdentifier = "gender"
	EudiNationality          mdoc.ElementIdentifier = "nationality"
	EudiIssuanceDate         mdoc.ElementIdentifier = "issuance_date"
	EudiExpiryDate           mdoc.ElementIdentifier = "expiry_date"
	EudiIssuingAuthority     mdoc.ElementIdentifier = "issuing_authority"
	EudiDocumentNumber       mdoc.ElementIdentifier = "document_number"
	EudiAdministrativeNumber mdoc.ElementIdentifier = "administrative_number"
	EudiIssuingCountry       mdoc.ElementIdentifier = "issuing_country"
	EudiIssuingJurisdiction  mdoc.ElementIdentifier = "issuing_jurisdiction"
)

func AgeOver(age int) (mdoc.ElementIdentifier, error) {
	if age < 0 || age > 99 {
		return mdoc.ElementIdentifier(""), fmt.Errorf("unsupported range of age: %v", age)
	}
	return mdoc.ElementIdentifier(fmt.Sprintf("age_over_%d", age)), nil
}
