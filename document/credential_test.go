package document

import (
	"testing"

	"github.com/kokukuma/mdoc-verifier/mdoc"
)

func TestNewCredential_Validation(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		docType   mdoc.DocType
		namespace mdoc.NameSpace
		elements  []mdoc.ElementIdentifier
		opts      []CredentialOption
		wantErr   bool
		errField  string
	}{
		{
			name:      "Valid ISO MDL credential",
			id:        "test-id-1",
			docType:   IsoMDL,
			namespace: ISO1801351,
			elements:  []mdoc.ElementIdentifier{IsoFamilyName, IsoGivenName},
			wantErr:   false,
		},
		{
			name:      "Valid EUDI PID credential",
			id:        "test-id-2",
			docType:   EudiPid,
			namespace: EUDIPID1,
			elements:  []mdoc.ElementIdentifier{EudiFamilyName, EudiAgeOver18},
			wantErr:   false,
		},
		{
			name:      "Empty ID",
			id:        "",
			docType:   IsoMDL,
			namespace: ISO1801351,
			elements:  []mdoc.ElementIdentifier{IsoFamilyName},
			wantErr:   true,
			errField:  "id",
		},
		{
			name:      "Empty elements array",
			id:        "test-id-3",
			docType:   IsoMDL,
			namespace: ISO1801351,
			elements:  []mdoc.ElementIdentifier{},
			wantErr:   true,
			errField:  "elements",
		},
		{
			name:      "Invalid docType-namespace combination",
			id:        "test-id-4",
			docType:   IsoMDL,
			namespace: EUDIPID1, // Doesn't match docType
			elements:  []mdoc.ElementIdentifier{IsoFamilyName},
			wantErr:   true,
			errField:  "docType+namespace",
		},
		{
			name:      "Invalid element for namespace",
			id:        "test-id-5",
			docType:   IsoMDL,
			namespace: ISO1801351,
			elements:  []mdoc.ElementIdentifier{"non_existent_element"}, // Element doesn't exist
			wantErr:   true,
			errField:  "elementIdentifier",
		},
		{
			name:      "Invalid algorithm",
			id:        "test-id-6",
			docType:   IsoMDL,
			namespace: ISO1801351,
			elements:  []mdoc.ElementIdentifier{IsoFamilyName},
			opts:      []CredentialOption{WithAlgorithms("INVALID_ALG")},
			wantErr:   true,
			errField:  "alg",
		},
		{
			name:      "Invalid limitDisclosure",
			id:        "test-id-7",
			docType:   IsoMDL,
			namespace: ISO1801351,
			elements:  []mdoc.ElementIdentifier{IsoFamilyName},
			opts:      []CredentialOption{WithLimitDisclosure("invalid")},
			wantErr:   true,
			errField:  "limitDisclosure",
		},
		{
			name:      "Negative retention",
			id:        "test-id-8",
			docType:   IsoMDL,
			namespace: ISO1801351,
			elements:  []mdoc.ElementIdentifier{IsoFamilyName},
			opts:      []CredentialOption{WithRetention(-1)},
			wantErr:   true,
			errField:  "retention",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCredential(tt.id, tt.docType, tt.namespace, tt.elements, tt.opts...)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCredential() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if tt.wantErr {
				validationErr, ok := err.(*ErrValidation)
				if !ok {
					t.Errorf("NewCredential() error should be ErrValidation, got %T", err)
					return
				}
				
				if validationErr.Field != tt.errField {
					t.Errorf("NewCredential() error field = %v, want %v", validationErr.Field, tt.errField)
				}
			} else if got == nil {
				t.Errorf("NewCredential() returned nil without error")
			}
		})
	}
}

func TestIsValidElementForNamespace(t *testing.T) {
	// Using a non-existent element identifier for cross-namespace testing
	nonExistentIsoElement := mdoc.ElementIdentifier("non_existent_iso_element")
	nonExistentEudiElement := mdoc.ElementIdentifier("non_existent_eudi_element")
	
	tests := []struct {
		name      string
		namespace mdoc.NameSpace
		element   mdoc.ElementIdentifier
		want      bool
	}{
		{
			name:      "Valid ISO element",
			namespace: ISO1801351,
			element:   IsoFamilyName,
			want:      true,
		},
		{
			name:      "Valid EUDI element",
			namespace: EUDIPID1,
			element:   EudiFamilyName,
			want:      true,
		},
		{
			name:      "ISO element in EUDI namespace",
			namespace: EUDIPID1,
			element:   nonExistentIsoElement,
			want:      false,
		},
		{
			name:      "EUDI element in ISO namespace",
			namespace: ISO1801351, 
			element:   nonExistentEudiElement,
			want:      false,
		},
		{
			name:      "Non-existent namespace",
			namespace: "non.existent.namespace",
			element:   IsoFamilyName,
			want:      false,
		},
		{
			name:      "Non-existent element",
			namespace: ISO1801351,
			element:   "non_existent_element",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidElementForNamespace(tt.namespace, tt.element); got != tt.want {
				t.Errorf("IsValidElementForNamespace() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsValidDocTypeNamespace(t *testing.T) {
	tests := []struct {
		name      string
		docType   mdoc.DocType
		namespace mdoc.NameSpace
		want      bool
	}{
		{
			name:      "Valid ISO combination",
			docType:   IsoMDL,
			namespace: ISO1801351,
			want:      true,
		},
		{
			name:      "Valid EUDI combination",
			docType:   EudiPid,
			namespace: EUDIPID1,
			want:      true,
		},
		{
			name:      "Invalid combination 1",
			docType:   IsoMDL,
			namespace: EUDIPID1,
			want:      false,
		},
		{
			name:      "Invalid combination 2",
			docType:   EudiPid,
			namespace: ISO1801351,
			want:      false,
		},
		{
			name:      "Non-existent docType",
			docType:   "non.existent.doctype",
			namespace: ISO1801351,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidDocTypeNamespace(tt.docType, tt.namespace); got != tt.want {
				t.Errorf("IsValidDocTypeNamespace() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSupportedAlgorithms(t *testing.T) {
	algMap := SupportedAlgorithms()
	
	// Check that known valid algorithms are supported
	supportedAlgs := []string{"ES256", "ES384", "ES512", "RS256"}
	for _, alg := range supportedAlgs {
		if !algMap[alg] {
			t.Errorf("Algorithm %s should be supported", alg)
		}
	}
	
	// Check that invalid algorithms are not supported
	unsupportedAlgs := []string{"NONE", "HS256", "INVALID"}
	for _, alg := range unsupportedAlgs {
		if algMap[alg] {
			t.Errorf("Algorithm %s should not be supported", alg)
		}
	}
}

func TestErrValidation_Error(t *testing.T) {
	err := &ErrValidation{Field: "test_field", Message: "test message"}
	expected := "validation error for test_field: test message"
	
	if err.Error() != expected {
		t.Errorf("ErrValidation.Error() = %v, want %v", err.Error(), expected)
	}
}