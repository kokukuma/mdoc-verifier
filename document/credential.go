package document

import (
	"fmt"

	"github.com/kokukuma/mdoc-verifier/mdoc"
)

type CredentialOption func(*Credential)

func WithRetention(retention int) CredentialOption {
	return func(c *Credential) {
		c.Retention = retention
	}
}

func WithLimitDisclosure(limitDisclosure LimitDisclosure) CredentialOption {
	return func(c *Credential) {
		c.LimitDisclosure = limitDisclosure
	}
}

func WithPurpose(purpose string) CredentialOption {
	return func(c *Credential) {
		c.Purpose = purpose
	}
}

func WithAlgorithms(algs ...string) CredentialOption {
	return func(c *Credential) {
		c.Alg = algs
	}
}

// ErrValidation is returned when credential validation fails
type ErrValidation struct {
	Field   string
	Message string
}

func (e ErrValidation) Error() string {
	return fmt.Sprintf("validation error for %s: %s", e.Field, e.Message)
}

// IsValidElementForNamespace checks if an element identifier is valid for a given namespace
func IsValidElementForNamespace(namespace mdoc.NameSpace, element mdoc.ElementIdentifier) bool {
	// Check namespace and element prefix matching
	switch namespace {
	case ISO1801351:
		// For ISO namespace, verify the element is one of the predefined ISO elements
		validISOElements := map[mdoc.ElementIdentifier]bool{
			IsoFamilyName: true, IsoGivenName: true, IsoBirthDate: true, 
			IsoExpiryDate: true, IsoIssuingCountry: true, IsoIssuingAuthority: true,
			IsoDocumentNumber: true, IsoPortrait: true, IsoDrivingPrivileges: true,
			IsoUnDistinguishingSign: true, IsoAdministrativeNumber: true, IsoSex: true,
			IsoHeight: true, IsoWeight: true, IsoEyeColour: true, IsoHairColour: true,
			IsoBirthPlace: true, IsoResidentAddress: true, IsoPortraitCaptureDate: true,
			IsoAgeInYears: true, IsoAgeBirthYear: true, IsoIssuingJurisdiction: true,
			IsoNationality: true, IsoResidentCity: true, IsoResidentState: true,
			IsoResidentPostalCode: true, IsoResidentCountry: true,
			IsoFamilyNameNationalCharacter: true, IsoGivenNameNationalCharacter: true,
			IsoSignatureUsualMark: true,
		}
		return validISOElements[element]
		
	case EUDIPID1:
		// For EUDI namespace, verify the element is one of the predefined EUDI elements
		validEUDIElements := map[mdoc.ElementIdentifier]bool{
			EudiFamilyName: true, EudiGivenName: true, EudiBirthDate: true,
			EudiAgeOver18: true, EudiAgeInYears: true, EudiAgeBirthYear: true,
			EudiGivenNameBirth: true, EudiBirthPlace: true, EudiBirthCountry: true,
			EudiBirthState: true, EudiBirthCity: true, EudiResidentAddress: true,
			EudiResidentCountry: true, EudiResidentState: true, EudiResidentCity: true,
			EudiResidentPostalCode: true, EudiResidentStreet: true, EudiResidentHouseNumber: true,
			EudiGender: true, EudiNationality: true, EudiIssuanceDate: true,
			EudiExpiryDate: true, EudiIssuingAuthority: true, EudiDocumentNumber: true,
			EudiAdministrativeNumber: true, EudiIssuingCountry: true, EudiIssuingJurisdiction: true,
		}
		return validEUDIElements[element]
		
	default:
		// For unrecognized namespaces, always return false
		return false
	}
}

// IsValidDocTypeNamespace checks if a docType and namespace combination is valid
func IsValidDocTypeNamespace(docType mdoc.DocType, namespace mdoc.NameSpace) bool {
	validCombinations := map[mdoc.DocType]mdoc.NameSpace{
		IsoMDL:  ISO1801351,
		EudiPid: EUDIPID1,
	}

	expectedNamespace, exists := validCombinations[docType]
	if !exists {
		return false
	}

	return expectedNamespace == namespace
}

// SupportedAlgorithms returns a map of supported signing algorithms
func SupportedAlgorithms() map[string]bool {
	return map[string]bool{
		"ES256": true,
		"ES384": true,
		"ES512": true,
		"PS256": true,
		"PS384": true,
		"PS512": true,
		"RS256": true,
		"RS384": true,
		"RS512": true,
	}
}

func NewCredential(
	id string,
	docType mdoc.DocType,
	namespace mdoc.NameSpace,
	elements []mdoc.ElementIdentifier,
	opts ...CredentialOption,
) (*Credential, error) {
	// Validate ID
	if id == "" {
		return nil, &ErrValidation{Field: "id", Message: "cannot be empty"}
	}

	// Validate elements array is not empty
	if len(elements) == 0 {
		return nil, &ErrValidation{Field: "elements", Message: "must contain at least one element"}
	}

	// Validate docType and namespace combination
	if !IsValidDocTypeNamespace(docType, namespace) {
		return nil, &ErrValidation{
			Field:   "docType+namespace",
			Message: fmt.Sprintf("invalid combination: docType=%s, namespace=%s", docType, namespace),
		}
	}

	// credential with default
	cred := Credential{
		ID:                id,
		DocType:           docType,
		Namespace:         namespace,
		ElementIdentifier: elements,
		LimitDisclosure:   LimitDisclosurePreferred,
		Alg:               []string{"ES256"},
	}

	for _, opt := range opts {
		opt(&cred)
	}

	// Validate LimitDisclosure setting
	if cred.LimitDisclosure != LimitDisclosureRequired && cred.LimitDisclosure != LimitDisclosurePreferred {
		return nil, &ErrValidation{
			Field:   "limitDisclosure",
			Message: fmt.Sprintf("unsupported value: %s", cred.LimitDisclosure),
		}
	}

	// Validate algorithms
	supportedAlgs := SupportedAlgorithms()
	for _, alg := range cred.Alg {
		if !supportedAlgs[alg] {
			return nil, &ErrValidation{
				Field:   "alg",
				Message: fmt.Sprintf("unsupported algorithm: %s", alg),
			}
		}
	}

	// Validate all element identifiers are valid for the namespace
	for _, element := range elements {
		if !IsValidElementForNamespace(namespace, element) {
			return nil, &ErrValidation{
				Field:   "elementIdentifier",
				Message: fmt.Sprintf("invalid element %s for namespace %s", element, namespace),
			}
		}
	}

	// Validate retention is non-negative
	if cred.Retention < 0 {
		return nil, &ErrValidation{Field: "retention", Message: "must be non-negative"}
	}

	return &cred, nil
}

type CredentialRequirement struct {
	CredentialType CredentialType
	Credentials    []Credential
}

type Credential struct {
	ID                string
	DocType           mdoc.DocType
	Namespace         mdoc.NameSpace
	ElementIdentifier []mdoc.ElementIdentifier
	Retention         int
	LimitDisclosure   LimitDisclosure
	Purpose           string
	Alg               []string
}

type CredentialType string

type LimitDisclosure string

const (
	// ISO/IEC 18013-5 mobile Driving License
	CredentialTypeMDOC CredentialType = "mso_mdoc"

	// SD-JWT based Verifiable Credentials
	CredentialTypeSDJWT CredentialType = "dc+sd-jwt"

	// W3C Verifiable Credentials Data Model
	CredentialTypeVC CredentialType = "vc+jwt"

	// LimitDisclosure
	LimitDisclosureRequired  LimitDisclosure = "required"
	LimitDisclosurePreferred LimitDisclosure = "preferred"
)

func (c CredentialRequirement) Selector() []Selector {
	var selectors []Selector
	for _, cred := range c.Credentials {
		selectors = append(selectors, Selector{
			Format:    []string{string(c.CredentialType)}, // TODO: check if it is work; original = mdoc
			Retention: Retention{Days: cred.Retention},
			DocType:   string(cred.DocType),
			Fields: formatFields(
				cred.Namespace,
				intentToRetain(cred.Retention),
				cred.ElementIdentifier...),
		})

	}
	return selectors
}

func formatFields(ns mdoc.NameSpace, retain bool, ids ...mdoc.ElementIdentifier) []Field {
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

func (c CredentialRequirement) DCQLQuery() DCQLQuery {
	query := DCQLQuery{
		Credentials:    make([]CredentialQuery, 0),
		CredentialSets: make([]CredentialSetQuery, 0),
	}

	// Collect credential IDs for credential sets
	credentialIDs := make([]string, 0, len(c.Credentials))

	// Build credential queries
	for _, cred := range c.Credentials {
		credentialIDs = append(credentialIDs, cred.ID)

		// Build claim queries
		claims := make([]ClaimQuery, len(cred.ElementIdentifier))
		for i, elem := range cred.ElementIdentifier {
			claims[i] = ClaimQuery{
				ID:   fmt.Sprintf("%s_%s", cred.Namespace, elem),
				Path: []interface{}{string(cred.Namespace), string(elem)},
			}
		}

		// Build credential query
		credQuery := CredentialQuery{
			ID:     cred.ID,
			Format: string(c.CredentialType),
			Meta: &MetaConstraints{
				DocType: string(cred.DocType),
				Additional: map[string]interface{}{
					"alg": cred.Alg,
				},
			},
			Claims: claims,
		}

		// Add limitDisclosure if specified
		if cred.LimitDisclosure != "" {
			if credQuery.Meta.Additional == nil {
				credQuery.Meta.Additional = make(map[string]interface{})
			}
			credQuery.Meta.Additional["limit_disclosure"] = cred.LimitDisclosure
		}

		query.Credentials = append(query.Credentials, credQuery)
	}

	// Add credential set query if we have any credentials
	if len(credentialIDs) > 0 {
		csq := CredentialSetQuery{
			Options: [][]string{credentialIDs}, // All credentials in one set
		}

		// Add purpose if any credential has it specified
		for _, cred := range c.Credentials {
			if cred.Purpose != "" {
				csq.Purpose = cred.Purpose
				break
			}
		}

		query.CredentialSets = append(query.CredentialSets, csq)
	}

	return query
}

func intentToRetain(retainDay int) bool {
	return retainDay > 0
}

func (c CredentialRequirement) PresentationDefinition() PresentationDefinition {
	pd := PresentationDefinition{}
	for _, cred := range c.Credentials {
		pd.InputDescriptors = append(pd.InputDescriptors, InputDescriptor{
			ID: string(cred.DocType),
			// ID: cred.ID,
			Format: Format{
				MsoMdoc: MsoMdoc{
					Alg: cred.Alg,
				},
			},
			Constraints: Constraints{
				LimitDisclosure: string(cred.LimitDisclosure),
				Fields: formatPathField(
					cred.Namespace,
					intentToRetain(cred.Retention),
					cred.ElementIdentifier...),
			},
			Purpose: cred.Purpose,
		})
	}

	return pd
}

func formatPathField(ns mdoc.NameSpace, retain bool, ids ...mdoc.ElementIdentifier) []PathField {
	result := []PathField{}

	for _, id := range ids {
		result = append(result, PathField{
			Path:           []string{fmt.Sprintf("$['%s']['%s']", ns, id)},
			IntentToRetain: retain,
		})
	}
	return result
}
