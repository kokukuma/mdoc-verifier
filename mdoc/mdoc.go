// Package mdoc provides a library for handling ISO/IEC 18013-5:2021 mobile driving license (mDL)
// and other mobile documents (mDoc) verification. It implements the structures and functions
// needed to parse, validate, and verify mobile documents according to the standard.
//
// The package follows the ISO/IEC 18013-5:2021 specification for mobile documents, including
// data structures, cryptographic verification procedures, and document validation processes.
// It supports verification of both issuer-signed data and device-signed data, validation of
// cryptographic signatures, certificate verification, and digest validation.
//
// The main entry point for verification is the Verifier struct, which can be configured
// with various options to customize the verification process. The Document and DeviceResponse
// structures represent the mobile document and the response from a mobile device, respectively.
package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"hash"
	"io"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// DocType represents the type of mobile document, such as "org.iso.18013.5.1.mDL".
// It identifies which credential is being presented and verified.
type DocType string

// NameSpace represents a grouping of related elements within a document,
// such as "org.iso.18013.5.1" for MDL data elements.
type NameSpace string

// ElementIdentifier uniquely identifies a data element within a namespace,
// such as "family_name" or "birth_date" in the ISO MDL namespace.
type ElementIdentifier string

// ElementValue represents the value of a data element, which can be
// of various types including strings, numbers, booleans, or complex objects.
type ElementValue interface{}

// DeviceResponse represents the response from a mobile device containing
// one or more mobile documents, as defined in ISO/IEC 18013-5:2021 section 8.3.
// It is the top-level structure returned by the device during a credential presentation.
type DeviceResponse struct {
	// Version indicates the protocol version, typically "1.0"
	Version string `json:"version"`

	// Documents contains the successfully retrieved mobile documents
	Documents []Document `json:"documents,omitempty"`

	// DocumentErrors contains errors for documents that could not be retrieved
	DocumentErrors []DocumentError `json:"documentErrors,omitempty"`

	// Status indicates the overall status of the response (0 = success)
	Status uint `json:"status"`
}

// ErrDocumentNotFound is returned when a document with the specified DocType is not found
// in the DeviceResponse. This typically occurs when trying to retrieve a document that doesn't
// exist in the device's response.
type ErrDocumentNotFound struct {
	// DocType is the type of document that was requested but not found
	DocType DocType
}

// Error returns a formatted error message that includes the DocType that was not found.
// This implements the error interface.
func (e ErrDocumentNotFound) Error() string {
	return fmt.Sprintf("document not found: doctype=%s", e.DocType)
}

// GetDocument retrieves a document of the specified type from the DeviceResponse.
// It searches through the Documents array to find a document with a matching DocType.
//
// Parameters:
//   - docType: The type of document to retrieve (e.g., "org.iso.18013.5.1.mDL")
//
// Returns:
//   - *Document: A pointer to the found document if successful
//   - error: An ErrDocumentNotFound error if no document with the specified DocType exists in the response
//
// Example:
//
//	mdl, err := response.GetDocument("org.iso.18013.5.1.mDL")
//	if err != nil {
//	    // Handle error (document not found)
//	}
//	// Use the mdl document
func (d DeviceResponse) GetDocument(docType DocType) (*Document, error) {
	for _, doc := range d.Documents {
		if doc.DocType == docType {
			return &doc, nil
		}
	}
	return nil, &ErrDocumentNotFound{DocType: docType}
}

// Document represents a mobile document as defined in ISO/IEC 18013-5:2021.
// It contains the document type, issuer-signed data, device-signed data,
// and any errors that occurred during document retrieval.
type Document struct {
	// DocType identifies the type of document, e.g., "org.iso.18013.5.1.mDL"
	DocType DocType `json:"docType"`

	// IssuerSigned contains data elements signed by the issuing authority
	IssuerSigned IssuerSigned `json:"issuerSigned"`

	// DeviceSigned contains data elements signed by the device
	DeviceSigned DeviceSigned `json:"deviceSigned"`

	// Errors contains any errors that occurred during document retrieval
	Errors Errors `json:"errors,omitempty"`
}

// ErrInvalidDocument indicates the document is invalid or improperly formed.
// This error is returned when attempting to perform operations on a document that
// is missing required fields or has structural issues.
type ErrInvalidDocument struct {
	// Reason provides a detailed explanation of why the document is invalid
	Reason string
}

// Error returns a formatted error message with the reason for the document's invalidity.
// This implements the error interface.
func (e ErrInvalidDocument) Error() string {
	return fmt.Sprintf("invalid document: %s", e.Reason)
}

// ErrNamespaceNotFound indicates the requested namespace was not found in the document.
// This typically occurs when trying to access a namespace that doesn't exist in the
// document's IssuerSigned data.
type ErrNamespaceNotFound struct {
	// Namespace is the namespace that was requested but not found
	Namespace NameSpace
}

// Error returns a formatted error message with the namespace that was not found.
// This implements the error interface.
func (e ErrNamespaceNotFound) Error() string {
	return fmt.Sprintf("namespace not found: %s", e.Namespace)
}

// ErrElementNotFound indicates the requested element was not found in the specified namespace.
// This typically occurs when trying to access a data element that doesn't exist within
// a valid namespace.
type ErrElementNotFound struct {
	// Namespace is the namespace where the element was sought
	Namespace NameSpace

	// ElementID is the identifier of the element that was not found
	ElementID ElementIdentifier
}

// Error returns a formatted error message with both the element ID and namespace
// where the element was not found. This implements the error interface.
func (e ErrElementNotFound) Error() string {
	return fmt.Sprintf("element %s not found in namespace %s", e.ElementID, e.Namespace)
}

// GetElementValue retrieves a specific data element from the document.
// It takes a namespace and an element identifier and returns the corresponding value.
// This is the main method for accessing individual data elements within a mobile document.
//
// The method performs several validation steps:
// 1. Checks if the document is valid (has a DocType and namespaces)
// 2. Verifies that the requested namespace exists
// 3. Searches for the requested element within the namespace
// 4. Handles special cases like CBOR tagged values
//
// Parameters:
//   - namespace: The namespace containing the element (e.g., "org.iso.18013.5.1")
//   - elementIdentifier: The identifier of the element (e.g., "family_name")
//
// Returns:
//   - ElementValue: The value of the requested element if found
//   - error: One of the following error types:
//   - ErrInvalidDocument: If the document is missing required fields
//   - ErrNamespaceNotFound: If the requested namespace doesn't exist
//   - ErrElementNotFound: If the element doesn't exist in the namespace
//   - Other errors: If there are issues parsing the element data
//
// Example:
//
//	familyName, err := doc.GetElementValue("org.iso.18013.5.1", "family_name")
//	if err != nil {
//	    // Handle error
//	}
//	name, ok := familyName.(string)
//	if !ok {
//	    // Handle type assertion error
//	}
func (d *Document) GetElementValue(namespace NameSpace, elementIdentifier ElementIdentifier) (ElementValue, error) {
	if d.DocType == "" {
		return nil, &ErrInvalidDocument{Reason: "missing document type"}
	}

	if d.IssuerSigned.NameSpaces == nil {
		return nil, &ErrInvalidDocument{Reason: "no namespaces available"}
	}

	itemBytes, exists := d.IssuerSigned.NameSpaces[namespace]
	if !exists {
		return nil, &ErrNamespaceNotFound{Namespace: namespace}
	}

	for _, ib := range itemBytes {
		item, err := ib.IssuerSignedItem()
		if err != nil {
			return nil, fmt.Errorf("failed to parse issuer signed item: %w", err)
		}
		if item.ElementIdentifier == elementIdentifier {
			if tag, ok := item.ElementValue.(cbor.Tag); ok {
				return tag.Content, nil
			}
			return item.ElementValue, nil
		}
	}
	return nil, &ErrElementNotFound{Namespace: namespace, ElementID: elementIdentifier}
}

// IssuerSigned contains the data elements signed by the issuing authority
// and the cryptographic material needed to verify that signature.
type IssuerSigned struct {
	// NameSpaces contains the data elements grouped by namespace
	NameSpaces IssuerNameSpaces `json:"nameSpaces,omitempty"`

	// IssuerAuth contains the issuer's cryptographic signature over the data
	IssuerAuth cose.UntaggedSign1Message `json:"issuerAuth"`
}

// GetNameSpaces returns a list of all namespaces present in the issuer-signed data.
// This can be used to enumerate the available namespaces before accessing specific data elements.
func (i *IssuerSigned) GetNameSpaces() []NameSpace {
	nss := []NameSpace{}
	for ns := range i.NameSpaces {
		nss = append(nss, ns)
	}
	return nss
}

// ErrNamespaceEmpty indicates that the requested namespace exists but contains no items.
// This error occurs when a namespace is defined in the document's structure but has
// no data elements (IssuerSignedItems) within it.
type ErrNamespaceEmpty struct {
	// Namespace is the namespace that exists but is empty
	Namespace NameSpace
}

// Error returns a formatted error message with the namespace that was found but is empty.
// This implements the error interface.
func (e ErrNamespaceEmpty) Error() string {
	return fmt.Sprintf("namespace is empty: %s", e.Namespace)
}

// GetIssuerSignedItems retrieves all issuer-signed items from the specified namespace.
// This method allows access to all data elements within a namespace, rather than just a single
// element as with GetElementValue.
//
// Each IssuerSignedItem contains a DigestID, Random bytes for entropy, an ElementIdentifier,
// and the actual ElementValue. These items are signed by the issuing authority and can be
// verified against the document's Mobile Security Object (MSO).
//
// Parameters:
//   - ns: The namespace to retrieve items from (e.g., "org.iso.18013.5.1")
//
// Returns:
//   - []IssuerSignedItem: A slice containing all items in the namespace if successful
//   - error: One of the following error types:
//   - ErrNamespaceEmpty: If the namespace exists but contains no items
//   - ErrNamespaceNotFound: If the namespace doesn't exist in the document
//   - Other errors: If there are issues parsing or decoding the items
//
// Example:
//
//	items, err := doc.IssuerSigned.GetIssuerSignedItems("org.iso.18013.5.1")
//	if err != nil {
//	    // Handle error
//	}
//	for _, item := range items {
//	    fmt.Printf("Element: %s, Value: %v\n", item.ElementIdentifier, item.ElementValue)
//	}
func (i *IssuerSigned) GetIssuerSignedItems(ns NameSpace) ([]IssuerSignedItem, error) {
	items, exists := i.NameSpaces[ns]
	if !exists {
		return nil, &ErrNamespaceNotFound{Namespace: ns}
	}

	if len(items) == 0 {
		return nil, &ErrNamespaceEmpty{Namespace: ns}
	}

	result := make([]IssuerSignedItem, 0, len(items))
	for _, b := range items {
		isi, err := b.IssuerSignedItem()
		if err != nil {
			return nil, NewWrappedCategoryError(ErrCategoryElement, err, "failed to parse issuer signed item")
		}
		result = append(result, *isi)
	}
	return result, nil
}

// GetIssuerAuth returns the issuer's cryptographic signature structure.
// This is used during verification to validate the authenticity of the document.
func (i *IssuerSigned) GetIssuerAuth() cose.UntaggedSign1Message {
	return i.IssuerAuth
}

// ErrMissingProtectedHeader indicates that the protected header is missing in the COSE structure.
// This error occurs when attempting to access algorithms or other data from a COSE structure
// that has no protected header, which is required for proper verification.
type ErrMissingProtectedHeader struct{}

// Error returns a formatted error message indicating the missing protected header.
// This implements the error interface.
func (e ErrMissingProtectedHeader) Error() string {
	return "missing protected header in COSE structure"
}

// Alg returns the cryptographic algorithm used for the issuer's signature.
// This method extracts the algorithm identifier from the protected header of the COSE structure,
// which is needed to properly verify the issuer's signature.
//
// The algorithm identifier is a registered value as defined in the COSE specification (RFC 8152),
// such as ES256 (-7) for ECDSA with SHA-256, ES384 (-35) for ECDSA with SHA-384, etc.
//
// Returns:
//   - cose.Algorithm: The algorithm identifier if successful
//   - error: One of the following error types:
//   - ErrMissingProtectedHeader: If the protected header is missing in the COSE structure
//   - Other errors: If there are issues parsing or accessing the algorithm from the headers
//
// Example:
//
//	alg, err := doc.IssuerSigned.Alg()
//	if err != nil {
//	    // Handle error
//	}
//	fmt.Printf("Document signed with algorithm: %v\n", alg)
func (i *IssuerSigned) Alg() (cose.Algorithm, error) {
	if i.IssuerAuth.Headers.Protected == nil {
		return 0, &ErrMissingProtectedHeader{}
	}
	return i.IssuerAuth.Headers.Protected.Algorithm()
}

// ErrCertificateChainIssue indicates a problem with the certificate chain.
// This error occurs when there are issues with the X.509 certificate chain used
// to verify the document signing certificate, such as missing certificates,
// validation failures, or improper formatting.
type ErrCertificateChainIssue struct {
	// Reason provides a specific explanation of what's wrong with the certificate chain
	Reason string
}

// Error returns a formatted error message with the reason for the certificate chain issue.
// This implements the error interface.
func (e ErrCertificateChainIssue) Error() string {
	return fmt.Sprintf("certificate chain issue: %s", e.Reason)
}

// ErrInvalidKeyType indicates that the public key is not of the expected type.
// This error occurs when a key retrieved from a certificate is not an ECDSA public key,
// which is required for verifying the document's signatures according to the standard.
type ErrInvalidKeyType struct {
	// ActualType is the type of key that was found (instead of the expected ECDSA type)
	ActualType string
}

// Error returns a formatted error message with the actual key type that was found.
// This implements the error interface.
func (e ErrInvalidKeyType) Error() string {
	return fmt.Sprintf("invalid key type: got %s, expected *ecdsa.PublicKey", e.ActualType)
}

// DocumentSigningKey retrieves the ECDSA public key from the document signing certificate.
// This key is used to verify the issuer's signature on the document.
//
// The method first retrieves the document signing certificate (DSC) using the
// DocumentSigningCertificate method, then extracts the public key from that certificate.
// According to ISO/IEC 18013-5:2021, this key must be an ECDSA public key, and this method
// will return an error if a different key type is found.
//
// Returns:
//   - *ecdsa.PublicKey: The ECDSA public key extracted from the DSC if successful
//   - error: One of the following error types:
//   - ErrInvalidKeyType: If the key in the certificate is not an ECDSA key
//   - ErrCertificateChainIssue: If there are problems with the certificate chain
//   - Other errors: If there are issues retrieving or parsing the certificate
//
// Example:
//
//	pubKey, err := doc.IssuerSigned.DocumentSigningKey()
//	if err != nil {
//	    // Handle error
//	}
//	// Use the public key for verification
func (i *IssuerSigned) DocumentSigningKey() (*ecdsa.PublicKey, error) {
	certificate, err := i.DocumentSigningCertificate()
	if err != nil {
		return nil, NewWrappedCategoryError(ErrCategoryCertificate, err, "failed to get certificate")
	}

	documentSigningKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, &ErrInvalidKeyType{ActualType: fmt.Sprintf("%T", certificate.PublicKey)}
	}
	return documentSigningKey, nil
}

// DocumentSigningCertificate retrieves the document signing certificate (DSC)
// from the certificate chain. The DSC is the first certificate in the chain.
// Returns:
//   - The document signing certificate if successful
//   - ErrCertificateChainIssue if there are problems with the certificate chain
//   - Other errors if there are issues retrieving the certificate chain
func (i *IssuerSigned) DocumentSigningCertificate() (*x509.Certificate, error) {
	certificates, err := i.DocumentSigningCertificateChain()
	if err != nil {
		return nil, NewWrappedCategoryError(ErrCategoryCertificate, err, "failed to get certificate chain")
	}
	if len(certificates) == 0 {
		return nil, &ErrCertificateChainIssue{Reason: "no certificates in x5chain"}
	}
	return certificates[0], nil
}

// ErrMissingHeaders indicates that required headers are missing in the COSE structure.
// This error occurs when attempting to access COSE headers (protected or unprotected)
// that don't exist or are nil, which prevents proper verification.
type ErrMissingHeaders struct {
	// HeaderType specifies which header type is missing ("protected" or "unprotected")
	HeaderType string
}

// Error returns a formatted error message with the specific header type that is missing.
// This implements the error interface.
func (e ErrMissingHeaders) Error() string {
	return fmt.Sprintf("missing %s headers in COSE structure", e.HeaderType)
}

// ErrX5ChainIssue indicates a problem with the X.509 certificate chain.
// This error occurs when there are issues with the certificate chain in the x5chain
// header of the COSE structure, such as missing certificates, invalid format,
// or unexpected types.
type ErrX5ChainIssue struct {
	// Reason provides a specific explanation of what's wrong with the x5chain
	Reason string
}

// Error returns a formatted error message with the reason for the x5chain issue.
// This implements the error interface.
func (e ErrX5ChainIssue) Error() string {
	return fmt.Sprintf("x5chain issue: %s", e.Reason)
}

// DocumentSigningCertificateChain retrieves the complete certificate chain
// used to verify the document signing certificate.
//
// According to ISO/IEC 18013-5:2021, the certificate chain is stored in the unprotected
// header of the COSE structure under the x5chain label. This method extracts that
// chain, parses each certificate, and returns them as a slice of X.509 certificates.
//
// The first certificate in the chain is the Document Signing Certificate (DSC), followed
// by any intermediate certificates, with the root certificate typically being the last
// in the chain (though the root may be omitted if it's expected to be in the verifier's
// trust store).
//
// Returns:
//   - []*x509.Certificate: The parsed certificate chain if successful
//   - error: One of the following error types:
//   - ErrMissingHeaders: If the unprotected headers are missing from the COSE structure
//   - ErrX5ChainIssue: If there are problems with the x5chain content or format
//   - Other errors: If there are issues parsing the individual certificates
//
// Example:
//
//	certChain, err := doc.IssuerSigned.DocumentSigningCertificateChain()
//	if err != nil {
//	    // Handle error
//	}
//	// Access the document signing certificate (first in chain)
//	dsc := certChain[0]
//	fmt.Printf("Document signed by: %s\n", dsc.Subject.CommonName)
func (i *IssuerSigned) DocumentSigningCertificateChain() ([]*x509.Certificate, error) {
	if i.IssuerAuth.Headers.Unprotected == nil {
		return nil, &ErrMissingHeaders{HeaderType: "unprotected"}
	}

	rawX5Chain, ok := i.IssuerAuth.Headers.Unprotected[cose.HeaderLabelX5Chain]
	if !ok {
		return nil, &ErrX5ChainIssue{Reason: "x5chain not found in unprotected headers"}
	}

	var rawX5ChainBytes [][]byte
	switch v := rawX5Chain.(type) {
	case [][]byte:
		rawX5ChainBytes = v
	case []byte:
		rawX5ChainBytes = [][]byte{v}
	default:
		return nil, &ErrX5ChainIssue{Reason: fmt.Sprintf("unexpected x5chain type: %T", rawX5Chain)}
	}

	if len(rawX5ChainBytes) == 0 {
		return nil, &ErrX5ChainIssue{Reason: "empty x5chain"}
	}

	certs := make([]*x509.Certificate, 0, len(rawX5ChainBytes))
	for i, certData := range rawX5ChainBytes {
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, fmt.Errorf("error parsing certificate at index %d: %w", i, err)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// ErrMissingPayload indicates that the payload is missing in the COSE structure.
// This error occurs when attempting to access or process the payload of a COSE message
// that has a nil or empty payload, which is required for proper verification.
type ErrMissingPayload struct{}

// Error returns a formatted error message indicating the missing payload.
// This implements the error interface.
func (e ErrMissingPayload) Error() string {
	return "missing payload in COSE structure"
}

// ErrInvalidTaggedContent indicates that the content of a CBOR tag is not of the expected type.
// This error occurs when the content inside a CBOR tag does not match the expected type,
// particularly when attempting to extract the Mobile Security Object (MSO) from a
// tagged CBOR structure.
type ErrInvalidTaggedContent struct {
	// ActualType is the type of content that was found (instead of the expected type)
	ActualType string
}

// Error returns a formatted error message with the actual content type that was found.
// This implements the error interface.
func (e ErrInvalidTaggedContent) Error() string {
	return fmt.Sprintf("invalid tagged content type: got %s, expected []byte", e.ActualType)
}

// MobileSecurityObject retrieves the Mobile Security Object (MSO) from the issuer-signed data.
// The MSO contains the document's security properties, including digest values for the data elements.
//
// According to ISO/IEC 18013-5:2021 section 9.1.2.3, the MSO is a CBOR-encoded structure
// contained within the payload of the issuer's COSE_Sign1 message. It contains critical security
// information including:
// - Digest algorithm used for data elements
// - Digest values for each data element, organized by namespace
// - Information about the device key authorized to sign certain data elements
// - Document type identifier
// - Validity information (signed date, valid from/until dates)
//
// This method extracts the MSO from the COSE structure, handles the CBOR tagging,
// and unmarshals it into a structured object.
//
// Returns:
//   - *MobileSecurityObject: The parsed MSO structure if successful
//   - error: One of the following error types:
//   - ErrMissingPayload: If the payload is missing from the COSE structure
//   - ErrInvalidTaggedContent: If the tagged CBOR content is not of the expected type
//   - Other errors: If there are issues unmarshaling or parsing the MSO data
//
// Example:
//
//	mso, err := doc.IssuerSigned.MobileSecurityObject()
//	if err != nil {
//	    // Handle error
//	}
//	fmt.Printf("Document type: %s\n", mso.DocType)
//	fmt.Printf("Valid until: %s\n", mso.ValidityInfo.ValidUntil)
func (i *IssuerSigned) MobileSecurityObject() (*MobileSecurityObject, error) {
	if i.IssuerAuth.Payload == nil {
		return nil, &ErrMissingPayload{}
	}

	var taggedData cbor.Tag
	if err := cbor.Unmarshal(i.IssuerAuth.Payload, &taggedData); err != nil {
		return nil, NewWrappedCategoryError(ErrCategoryCOSE, err, "failed to unmarshal tagged data")
	}

	content, ok := taggedData.Content.([]byte)
	if !ok {
		return nil, &ErrInvalidTaggedContent{ActualType: fmt.Sprintf("%T", taggedData.Content)}
	}

	var mso MobileSecurityObject
	if err := cbor.Unmarshal(content, &mso); err != nil {
		return nil, NewWrappedCategoryError(ErrCategoryCOSE, err, "failed to unmarshal MSO data")
	}

	return &mso, nil
}

type IssuerNameSpaces map[NameSpace][]IssuerSignedItemBytes

type IssuerSignedItemBytes cbor.RawMessage

// ErrEmptyIssuerSignedItemBytes indicates that the IssuerSignedItemBytes is empty.
// This error occurs when attempting to parse an IssuerSignedItem from empty bytes.
type ErrEmptyIssuerSignedItemBytes struct{}

// Error returns a formatted error message indicating that the IssuerSignedItemBytes is empty.
// This implements the error interface.
func (e ErrEmptyIssuerSignedItemBytes) Error() string {
	return "empty issuer signed item bytes"
}

// IssuerSignedItem parses an IssuerSignedItem from its CBOR-encoded bytes.
// This method is used to access the structured data elements within a document.
//
// Returns:
//   - *IssuerSignedItem: The parsed item if successful
//   - error: One of the following error types:
//   - ErrEmptyIssuerSignedItemBytes: If the bytes are empty
//   - Other errors: If there are issues unmarshaling the CBOR data
//
// Example:
//
//	item, err := bytes.IssuerSignedItem()
//	if err != nil {
//	    // Handle error
//	}
//	fmt.Printf("Element: %s, Value: %v\n", item.ElementIdentifier, item.ElementValue)
func (i IssuerSignedItemBytes) IssuerSignedItem() (*IssuerSignedItem, error) {
	if len(i) == 0 {
		return nil, &ErrEmptyIssuerSignedItemBytes{}
	}
	var item IssuerSignedItem
	if err := cbor.Unmarshal(i, &item); err != nil {
		return nil, NewWrappedCategoryError(ErrCategoryDocument, err, "failed to unmarshal issuer signed item")
	}
	item.rawBytes = i
	return &item, nil
}

type IssuerSignedItem struct {
	DigestID          DigestID          `json:"digestID"`
	Random            []byte            `json:"random"`
	ElementIdentifier ElementIdentifier `json:"elementIdentifier"`
	ElementValue      ElementValue      `json:"elementValue"`
	rawBytes          IssuerSignedItemBytes
}

// ErrNilIssuerSignedItem indicates that the IssuerSignedItem is nil.
// This error occurs when attempting to calculate a digest for a nil IssuerSignedItem.
type ErrNilIssuerSignedItem struct{}

// Error returns a formatted error message indicating that the IssuerSignedItem is nil.
// This implements the error interface.
func (e ErrNilIssuerSignedItem) Error() string {
	return "issuer signed item is nil"
}

// ErrUnsupportedDigestAlgorithm indicates that the specified digest algorithm is not supported.
// This error occurs when attempting to use a digest algorithm that the system does not recognize
// or support for calculating digests.
type ErrUnsupportedDigestAlgorithm struct {
	// Algorithm is the unsupported algorithm that was requested
	Algorithm string
}

// Error returns a formatted error message with the unsupported algorithm.
// This implements the error interface.
func (e ErrUnsupportedDigestAlgorithm) Error() string {
	return fmt.Sprintf("unsupported digest algorithm: %s", e.Algorithm)
}

// Digest calculates the cryptographic digest of the IssuerSignedItem using the specified algorithm.
// This method is used during verification to check that the data elements match their
// expected digest values in the Mobile Security Object (MSO).
//
// The digest is calculated according to ISO/IEC 18013-5:2021 section 9.1.2.5, which involves
// creating a CBOR tag and then hashing the resulting bytes using the specified algorithm.
//
// Parameters:
//   - alg: The digest algorithm to use ("SHA-256", "SHA-384", or "SHA-512")
//
// Returns:
//   - []byte: The calculated digest value if successful
//   - error: One of the following error types:
//   - ErrNilIssuerSignedItem: If the IssuerSignedItem is nil
//   - ErrUnsupportedDigestAlgorithm: If the specified algorithm is not supported
//   - Other errors: If there are issues marshaling the data or calculating the digest
//
// Example:
//
//	digest, err := item.Digest("SHA-256")
//	if err != nil {
//	    // Handle error
//	}
//	// Use the digest for verification
func (i *IssuerSignedItem) Digest(alg string) ([]byte, error) {
	if i == nil {
		return nil, &ErrNilIssuerSignedItem{}
	}

	v, err := cbor.Marshal(cbor.Tag{
		Number:  24,
		Content: i.rawBytes,
	})
	if err != nil {
		return nil, NewWrappedCategoryError(ErrCategoryDigest, err, "failed to marshal tagged CBOR")
	}

	var hasher hash.Hash
	switch alg {
	case "SHA-256":
		hasher = sha256.New()
	case "SHA-384":
		hasher = sha512.New384()
	case "SHA-512":
		hasher = sha512.New()
	default:
		return nil, &ErrUnsupportedDigestAlgorithm{Algorithm: alg}
	}

	if _, err := hasher.Write(v); err != nil {
		return nil, NewWrappedCategoryError(ErrCategoryDigest, err, "failed to write to hasher")
	}
	return hasher.Sum(nil), nil
}

// MobileSecurityObject represents the Mobile Security Object (MSO) as defined in
// ISO/IEC 18013-5:2021 section 9.1.2.3. The MSO contains the security properties
// of the document, including digest values for data elements and device key information.
type MobileSecurityObject struct {
	// Version indicates the MSO version, typically "1.0"
	Version string `json:"version"`

	// DigestAlgorithm specifies the algorithm used for digest calculations
	DigestAlgorithm string `json:"digestAlgorithm"`

	// ValueDigests contains digest values for the data elements, grouped by namespace
	ValueDigests ValueDigests `json:"valueDigests"`

	// DeviceKeyInfo contains information about the device key used for device authentication
	DeviceKeyInfo DeviceKeyInfo `json:"deviceKeyInfo"`

	// DocType identifies the type of document, e.g., "org.iso.18013.5.1.mDL"
	DocType DocType `json:"docType"`

	// ValidityInfo contains validity period information for the document
	ValidityInfo ValidityInfo `json:"validityInfo"`
}

// GetDocType returns the document type identifier from the MSO.
func (m *MobileSecurityObject) GetDocType() DocType {
	return m.DocType
}

// DigestAlg returns the digest algorithm identifier from the MSO.
func (m *MobileSecurityObject) DigestAlg() string {
	return m.DigestAlgorithm
}

// GetValidityInfo returns the validity information from the MSO.
func (m *MobileSecurityObject) GetValidityInfo() ValidityInfo {
	return m.ValidityInfo
}

// ErrDeviceKeyNotAvailable indicates that the device key is not available in the MSO.
// This error occurs when attempting to access or use the device key from the Mobile
// Security Object (MSO), but the key information is missing or nil. The device key
// is required for verifying device signatures.
type ErrDeviceKeyNotAvailable struct{}

// Error returns a formatted error message indicating the missing device key.
// This implements the error interface.
func (e ErrDeviceKeyNotAvailable) Error() string {
	return "device key not available in MSO"
}

// DeviceKey retrieves the ECDSA public key from the device key information in the MSO.
// This key is used to verify device signatures during the mobile document verification process.
//
// According to ISO/IEC 18013-5:2021, the device key is an ECDSA public key included
// in the Mobile Security Object (MSO) by the issuing authority. This key is authorized
// to sign certain data elements when the document is presented by the device. The
// verifier uses this key to authenticate device-signed data elements.
//
// The device key is structured as a COSE_Key object within the MSO, and this method
// extracts and parses that key into an ECDSA public key that can be used with Go's
// standard crypto libraries.
//
// Returns:
//   - *ecdsa.PublicKey: The ECDSA public key from the device key information if successful
//   - error: One of the following error types:
//   - ErrDeviceKeyNotAvailable: If the device key is not available in the MSO
//   - Other errors: If there are issues parsing or converting the COSE_Key to an ECDSA key
//
// Example:
//
//	deviceKey, err := mso.DeviceKey()
//	if err != nil {
//	    // Handle error
//	}
//	// Use the device key to verify device signatures
func (m *MobileSecurityObject) DeviceKey() (*ecdsa.PublicKey, error) {
	if m == nil || m.DeviceKeyInfo.DeviceKey == nil {
		return nil, &ErrDeviceKeyNotAvailable{}
	}
	// TODO: Select algorithm based on the key type
	return parseECDSA(m.DeviceKeyInfo.DeviceKey)
}

// ErrDigestNotFound indicates that a digest with the specified ID was not found.
// This error occurs when trying to retrieve a specific digest value from the MSO's
// ValueDigests, but no digest with the specified ID exists within the given namespace.
type ErrDigestNotFound struct {
	// Namespace is the namespace where the digest was sought
	Namespace NameSpace

	// DigestID is the identifier of the digest that was not found
	DigestID DigestID
}

// Error returns a formatted error message with both the namespace and digest ID
// where the digest was not found. This implements the error interface.
func (e ErrDigestNotFound) Error() string {
	return fmt.Sprintf("digest not found: namespace=%s, digest_id=%d", e.Namespace, e.DigestID)
}

// ErrNamespaceDigestsNotFound indicates that no digests were found for the specified namespace.
// This error occurs when attempting to access digest values for a namespace that doesn't
// exist in the MSO's ValueDigests map.
type ErrNamespaceDigestsNotFound struct {
	// Namespace is the namespace for which no digest values were found
	Namespace NameSpace
}

// Error returns a formatted error message with the namespace for which no digests were found.
// This implements the error interface.
func (e ErrNamespaceDigestsNotFound) Error() string {
	return fmt.Sprintf("value digests not found for namespace: %s", e.Namespace)
}

// GetDigest retrieves a specific digest value from the MSO.
//
// According to ISO/IEC 18013-5:2021, the MSO contains digest values for each data element
// in the document, organized by namespace and digest ID. These digests are used during
// verification to ensure that the data elements presented match those that were signed
// by the issuing authority.
//
// This method looks up a specific digest value by its namespace and digest ID, which
// can then be compared against computed digests of the actual data elements during
// the verification process.
//
// Parameters:
//   - ns: The namespace containing the digest (e.g., "org.iso.18013.5.1")
//   - digestID: The unique identifier for the digest within the namespace
//
// Returns:
//   - Digest: The digest value (byte array) if found
//   - error: One of the following error types:
//   - ErrNamespaceDigestsNotFound: If the namespace doesn't exist in the MSO's ValueDigests
//   - ErrDigestNotFound: If the digest ID doesn't exist in the specified namespace
//
// Example:
//
//	// Get the expected digest for a data element
//	expectedDigest, err := mso.GetDigest("org.iso.18013.5.1", 1)
//	if err != nil {
//	    // Handle error
//	}
//	// Compare with computed digest during verification
func (m *MobileSecurityObject) GetDigest(ns NameSpace, digestID DigestID) (Digest, error) {
	digests, ok := m.ValueDigests[ns]
	if !ok {
		return nil, &ErrNamespaceDigestsNotFound{Namespace: ns}
	}
	digest, ok := digests[digestID]
	if !ok {
		return nil, &ErrDigestNotFound{Namespace: ns, DigestID: digestID}
	}
	return digest, nil
}

// ErrKeyAuthorizationsNotAvailable indicates that key authorizations are not available in the MSO.
// This error occurs when attempting to access the key authorizations from the Mobile Security
// Object (MSO), but this information is missing or nil. Key authorizations specify which
// data elements the device key is authorized to sign.
type ErrKeyAuthorizationsNotAvailable struct{}

// Error returns a formatted error message indicating that device key authorizations
// are not available. This implements the error interface.
func (e ErrKeyAuthorizationsNotAvailable) Error() string {
	return "device key authorizations not available in MSO"
}

// KeyAuthorizations retrieves the key authorizations from the MSO,
// which specify what data elements the device key is authorized to sign.
//
// According to ISO/IEC 18013-5:2021, key authorizations define the scope of what
// the device key is permitted to sign when presenting the document. This includes
// either entire namespaces or specific data elements within namespaces. During
// verification, the verifier checks that the device has only signed elements that
// it is authorized to sign.
//
// The key authorizations structure contains two fields:
// - NameSpaces: A list of namespaces the device key is fully authorized to sign
// - DataElements: A map of namespaces to lists of element identifiers that the device key can sign
//
// Returns:
//   - *KeyAuthorizations: The key authorizations structure if available
//   - error: ErrKeyAuthorizationsNotAvailable if the key authorizations are not defined in the MSO
//
// Example:
//
//	keyAuth, err := mso.KeyAuthorizations()
//	if err != nil {
//	    // Handle error or absence of key authorizations
//	}
//	// Check if the device is authorized to sign specific elements
func (m *MobileSecurityObject) KeyAuthorizations() (*KeyAuthorizations, error) {
	if m == nil || m.DeviceKeyInfo.KeyAuthorizations == nil {
		return nil, &ErrKeyAuthorizationsNotAvailable{}
	}
	return m.DeviceKeyInfo.KeyAuthorizations, nil
}

// DeviceKeyInfo contains information about the device key used for authentication
// as defined in ISO/IEC 18013-5:2021 section 9.1.2.3.
type DeviceKeyInfo struct {
	// DeviceKey is the public key used for device authentication
	DeviceKey *COSEKey `json:"deviceKey"`

	// KeyAuthorizations specifies what data elements the device key is authorized to sign
	KeyAuthorizations *KeyAuthorizations `json:"keyAuthorizations,omitempty"`

	// KeyInfo contains additional information about the device key
	KeyInfo *KeyInfo `json:"keyInfo,omitempty"`
}

// COSEKey represents a COSE key as defined in RFC 8152.
// It contains the parameters for a cryptographic key.
type COSEKey struct {
	// Kty is the key type (1=OKP, 2=EC2, 3=RSA, 4=Symmetric)
	Kty int `cbor:"1,keyasint,omitempty"`

	// Kid is the key identifier
	Kid []byte `cbor:"2,keyasint,omitempty"`

	// Alg is the algorithm identifier
	Alg int `cbor:"3,keyasint,omitempty"`

	// KeyOpts specifies key operations that are permitted
	KeyOpts int `cbor:"4,keyasint,omitempty"`

	// IV is the initialization vector
	IV []byte `cbor:"5,keyasint,omitempty"`

	// CrvOrNOrK represents different parameters depending on key type:
	// - Crv for elliptic curve keys
	// - N for RSA modulus
	// - K for symmetric keys
	CrvOrNOrK cbor.RawMessage `cbor:"-1,keyasint,omitempty"`

	// XOrE represents different parameters depending on key type:
	// - X for curve x-coordinate
	// - E for RSA public exponent
	XOrE cbor.RawMessage `cbor:"-2,keyasint,omitempty"`

	// Y for curve y-coordinate (only for EC2 keys)
	Y cbor.RawMessage `cbor:"-3,keyasint,omitempty"`

	// D is the private key (should generally not be present in this context)
	D []byte `cbor:"-4,keyasint,omitempty"`
}

// KeyAuthorizations specifies what data elements the device key is authorized to sign.
// This is defined in ISO/IEC 18013-5:2021 section 9.1.2.3.
type KeyAuthorizations struct {
	// NameSpaces lists all namespaces the device key is authorized to sign
	NameSpaces []NameSpace `cbor:"nameSpaces,omitempty"`

	// DataElements lists specific elements within each namespace that the device key is authorized to sign
	DataElements map[NameSpace][]ElementIdentifier `cbor:"dataElements,omitempty"`
}

// KeyInfo contains additional information about the device key.
type KeyInfo map[int]interface{}

// ValueDigests maps namespaces to digest IDs and their corresponding digest values.
// This is defined in ISO/IEC 18013-5:2021 section 9.1.2.3.
type ValueDigests map[NameSpace]DigestIDs

// DigestIDs maps digest IDs to their corresponding digest values within a namespace.
type DigestIDs map[DigestID]Digest

// ValidityInfo contains the validity period information for the document,
// as defined in ISO/IEC 18013-5:2021 section 9.1.2.3.
type ValidityInfo struct {
	// Signed is the time when the document was signed by the issuer
	Signed time.Time `json:"signed"`

	// ValidFrom is the time from which the document is valid
	ValidFrom time.Time `json:"validFrom"`

	// ValidUntil is the time until which the document is valid
	ValidUntil time.Time `json:"validUntil"`

	// ExpectedUpdate is the time when an update is expected (optional)
	ExpectedUpdate time.Time `json:"expectedUpdate,omitempty"`
}

// DigestID uniquely identifies a digest within a namespace.
type DigestID uint32

// Digest is a byte array containing a cryptographic digest value.
type Digest []byte

// DeviceSigned contains data elements signed by the device
// and the cryptographic material used for device authentication.
// This is defined in ISO/IEC 18013-5:2021 section 9.1.3.
type DeviceSigned struct {
	// NameSpaces contains the device-signed data elements grouped by namespace
	NameSpaces *DeviceNameSpacesBytes `json:"nameSpaces"`

	// DeviceAuth contains the device's cryptographic signature or MAC
	DeviceAuth *DeviceAuth `json:"deviceAuth"`
}

// DeviceNameSpacesBytes is a raw CBOR message containing device-signed namespaces.
type DeviceNameSpacesBytes cbor.RawMessage

// DeviceNameSpaces maps namespaces to collections of device-signed items.
type DeviceNameSpaces map[NameSpace]DeviceSignedItems

// DeviceSignedItems maps element identifiers to their values within a namespace.
type DeviceSignedItems map[ElementIdentifier]ElementValue

// ErrDeviceSignedNil indicates that the DeviceSigned structure is nil.
// This error occurs when attempting to access or process the device-signed data,
// but the DeviceSigned structure itself is nil, which prevents proper verification.
type ErrDeviceSignedNil struct{}

// Error returns a formatted error message indicating that the device-signed data is nil.
// This implements the error interface.
func (e ErrDeviceSignedNil) Error() string {
	return "device signed data is nil"
}

// ErrMissingDeviceProtectedHeaders indicates that the protected headers are missing in the device signature.
// This error occurs when attempting to access the algorithm or other data from the protected
// headers of a device signature, but these headers are missing or nil.
type ErrMissingDeviceProtectedHeaders struct{}

// Error returns a formatted error message indicating that protected headers are not available
// in the device signature. This implements the error interface.
func (e ErrMissingDeviceProtectedHeaders) Error() string {
	return "protected headers not available in device signature"
}

// Alg returns the cryptographic algorithm used for the device's signature.
//
// This method extracts the algorithm identifier from the protected headers of the
// device signature COSE structure. The algorithm identifier is used during verification
// to ensure the correct verification algorithm is applied to the device signature.
//
// Returns:
//   - cose.Algorithm: The algorithm identifier if successful
//   - error: One of the following error types:
//   - ErrDeviceSignedNil: If the DeviceSigned structure is nil
//   - ErrMissingDeviceProtectedHeaders: If the protected headers are missing in the device signature
//   - Other errors: If there are issues parsing or accessing the algorithm
//
// Example:
//
//	alg, err := doc.DeviceSigned.Alg()
//	if err != nil {
//	    // Handle error
//	}
//	fmt.Printf("Device signature uses algorithm: %v\n", alg)
func (d *DeviceSigned) Alg() (cose.Algorithm, error) {
	if d == nil {
		return 0, &ErrDeviceSignedNil{}
	}

	if d.DeviceAuth.DeviceSignature.Headers.Protected == nil {
		return 0, &ErrMissingDeviceProtectedHeaders{}
	}

	return d.DeviceAuth.DeviceSignature.Headers.Protected.Algorithm()
}

// DeviceAuthMac returns the MAC structure used for device authentication, if present.
func (d *DeviceSigned) DeviceAuthMac() *UntaggedSign1Message {
	return d.DeviceAuth.DeviceMac
}

// DeviceAuthSignature returns the signature structure used for device authentication, if present.
func (d *DeviceSigned) DeviceAuthSignature() *UntaggedSign1Message {
	return d.DeviceAuth.DeviceSignature
}

// ErrEmptySessionTranscript indicates that the session transcript is empty.
// This error occurs when attempting to generate device authentication bytes but the
// provided session transcript is empty or nil. The session transcript is a required
// component for proper device authentication.
type ErrEmptySessionTranscript struct{}

// Error returns a formatted error message indicating that the session transcript is empty.
// This implements the error interface.
func (e ErrEmptySessionTranscript) Error() string {
	return "session transcript is empty"
}

// DeviceAuthenticationBytes generates the byte array used for device authentication.
// This includes the session transcript, document type, and device-signed namespaces.
//
// According to ISO/IEC 18013-5:2021 section 9.1.3, device authentication requires
// creating a specific CBOR-encoded structure that includes:
// 1. The literal string "DeviceAuthentication"
// 2. The session transcript (which binds the authentication to a specific session)
// 3. The document type
// 4. The device-signed namespaces (tagged with CBOR tag 24)
//
// This structure is then tagged with CBOR tag 24 and becomes the payload that is
// signed by the device. During verification, the verifier recreates this structure
// and uses it to verify the device's signature.
//
// Parameters:
//   - docType: The type of document being authenticated (e.g., "org.iso.18013.5.1.mDL")
//   - sessionTranscript: The session transcript bytes that bind the authentication to a specific session
//
// Returns:
//   - []byte: The CBOR-encoded device authentication bytes if successful
//   - error: One of the following error types:
//   - ErrDeviceSignedNil: If the DeviceSigned structure is nil
//   - ErrEmptySessionTranscript: If the provided session transcript is empty
//   - Other errors: If there are issues with CBOR marshaling or encoding
//
// Example:
//
//	authBytes, err := doc.DeviceSigned.DeviceAuthenticationBytes(doc.DocType, sessionTranscript)
//	if err != nil {
//	    // Handle error
//	}
//	// Use the authentication bytes to verify the device signature
func (d *DeviceSigned) DeviceAuthenticationBytes(docType DocType, sessionTranscript []byte) ([]byte, error) {
	if d == nil {
		return nil, &ErrDeviceSignedNil{}
	}

	if len(sessionTranscript) == 0 {
		return nil, &ErrEmptySessionTranscript{}
	}

	deviceAuthentication := []interface{}{
		"DeviceAuthentication",
		cbor.RawMessage(sessionTranscript),
		docType,
		cbor.Tag{Number: 24, Content: d.NameSpaces},
	}

	da, err := cbor.Marshal(deviceAuthentication)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal device authentication: %w", err)
	}

	deviceAuthenticationByte, err := cbor.Marshal(cbor.Tag{Number: 24, Content: da})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tagged device authentication: %w", err)
	}
	return deviceAuthenticationByte, nil
}

// ErrDeviceNameSpacesNil indicates that the device namespaces are nil.
// This error occurs when attempting to access or parse the device-signed namespaces,
// but this field is nil, which prevents proper verification of device-signed data.
type ErrDeviceNameSpacesNil struct{}

// Error returns a formatted error message indicating that the device namespaces are nil.
// This implements the error interface.
func (e ErrDeviceNameSpacesNil) Error() string {
	return "device namespaces are nil"
}

// DeviceNameSpaces parses and returns the device-signed namespaces.
//
// According to ISO/IEC 18013-5:2021 section 9.1.3, device-signed namespaces contain
// additional data elements that the device (rather than the issuer) has signed. These
// may include dynamic elements like the holder's current address, consent information,
// or other fields that may change over time without requiring a new credential to be issued.
//
// This method parses the raw CBOR-encoded device namespaces into a structured map
// that maps namespaces to collections of element identifiers and their values.
//
// Returns:
//   - DeviceNameSpaces: A map of namespaces to device-signed items if successful
//   - error: One of the following error types:
//   - ErrDeviceNameSpacesNil: If the device namespaces field is nil
//   - Other errors: If there are issues with CBOR unmarshaling or decoding
//
// Example:
//
//	deviceNS, err := doc.DeviceSigned.DeviceNameSpaces()
//	if err != nil {
//	    // Handle error
//	}
//	// Access specific device-signed elements
//	for namespace, items := range deviceNS {
//	    fmt.Printf("Namespace: %s\n", namespace)
//	    for elemID, value := range items {
//	        fmt.Printf("  Element: %s, Value: %v\n", elemID, value)
//	    }
//	}
func (d *DeviceSigned) DeviceNameSpaces() (DeviceNameSpaces, error) {
	if d.NameSpaces == nil {
		return nil, &ErrDeviceNameSpacesNil{}
	}

	var nameSpaces DeviceNameSpaces
	if err := cbor.Unmarshal(*d.NameSpaces, &nameSpaces); err != nil {
		return nil, fmt.Errorf("failed to unmarshal device namespaces: %w", err)
	}

	return nameSpaces, nil
}

type DeviceAuth struct {
	DeviceSignature *UntaggedSign1Message `json:"deviceSignature,omitempty"`
	DeviceMac       *UntaggedSign1Message `json:"deviceMac,omitempty"`
}

type DocumentError map[DocType]ErrorCode

type Errors map[NameSpace]ErrorItems

type ErrorItems map[ElementIdentifier]ErrorCode

type ErrorCode int

const (
	P256          = 1
	P384          = 2
	P521          = 3
	BrainpoolP256 = 8
	BrainpoolP384 = 9
	BrainpoolP512 = 10
)

func parseECDSA(coseKey *COSEKey) (*ecdsa.PublicKey, error) {
	if coseKey == nil {
		return nil, fmt.Errorf("cose key is nil")
	}

	var crv int
	if err := cbor.Unmarshal(coseKey.CrvOrNOrK, &crv); err != nil {
		return nil, fmt.Errorf("failed to unmarshal curve: %w", err)
	}

	var xBytes []byte
	if err := cbor.Unmarshal(coseKey.XOrE, &xBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal X coordinate: %w", err)
	}

	var yBytes []byte
	if err := cbor.Unmarshal(coseKey.Y, &yBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Y coordinate: %w", err)
	}

	if len(xBytes) == 0 || len(yBytes) == 0 {
		return nil, fmt.Errorf("invalid coordinates")
	}

	var curve elliptic.Curve
	switch crv {
	case P256: // RFC 8152 Table 21
		curve = elliptic.P256()
	case P384:
		curve = elliptic.P384()
	case P521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %d", crv)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	return pubKey, nil
}

// Appleのシミュレータが返す値がdevieSignature不完全な状態で返してくる。
// Parse失敗するので一旦無視するために別に作る...
type UntaggedSign1Message cose.UntaggedSign1Message

func (m *UntaggedSign1Message) Sign(rand io.Reader, external []byte, signer cose.Signer) error {
	return (*cose.UntaggedSign1Message)(m).Sign(rand, external, signer)
}

func (m *UntaggedSign1Message) Verify(external []byte, verifier cose.Verifier) error {
	return (*cose.UntaggedSign1Message)(m).Verify(external, verifier)
}

func (m *UntaggedSign1Message) MarshalCBOR() ([]byte, error) {
	return (*cose.UntaggedSign1Message)(m).MarshalCBOR()
}

func (m *UntaggedSign1Message) UnmarshalCBOR(data []byte) error {
	// return nil
	var msg cose.UntaggedSign1Message

	err := cbor.Unmarshal(data, &msg)
	if err != nil {
		// Appleのシミュレータが返す値がdevieSignature不完全な状態で返してくる。
		// Parse失敗するので一旦無視
		*m = UntaggedSign1Message{}
		return nil
	}

	*m = UntaggedSign1Message(msg)
	return nil
}
