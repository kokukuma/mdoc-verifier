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

func NewCredential(
	id string,
	docType mdoc.DocType,
	namespace mdoc.NameSpace,
	elements []mdoc.ElementIdentifier,
	opts ...CredentialOption,
) (*Credential, error) {

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

	// TODO: validation
	// avaiable convination: docType, namespace, elementIdentifiers

	if cred.LimitDisclosure != LimitDisclosureRequired && cred.LimitDisclosure != LimitDisclosurePreferred {
		return nil, fmt.Errorf("unsupported LimitDiscloure was specified: %s", cred.LimitDisclosure)
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
			// ID: string(cred.DocType),
			ID: cred.ID,
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
