// Package mdoc provides functionality for verifying mobile documents according to
// the ISO/IEC 18013-5:2021 standard. This file contains error handling utilities.
package mdoc

import (
	"errors"
	"fmt"
)

// Error categories for mdoc package
const (
	// ErrCategoryDocument represents errors related to document structure and validity
	ErrCategoryDocument = "document"
	
	// ErrCategoryNamespace represents errors related to namespaces
	ErrCategoryNamespace = "namespace"
	
	// ErrCategoryElement represents errors related to document elements
	ErrCategoryElement = "element"
	
	// ErrCategoryCertificate represents errors related to certificates
	ErrCategoryCertificate = "certificate"
	
	// ErrCategoryCOSE represents errors related to COSE structures
	ErrCategoryCOSE = "cose"
	
	// ErrCategoryDigest represents errors related to digest operations
	ErrCategoryDigest = "digest"
	
	// ErrCategoryVerification represents errors related to verification operations
	ErrCategoryVerification = "verification"
	
	// ErrCategoryDevice represents errors related to device operations
	ErrCategoryDevice = "device"
)

// formatError formats an error message with an optional category prefix.
// It ensures consistent error message formatting across the package.
// 
// Parameters:
//   - category: The error category, or empty for no category
//   - format: The format string for the error message
//   - args: Arguments for the format string
//
// Returns:
//   - A formatted error string
func formatError(category, format string, args ...interface{}) string {
	if category == "" {
		return fmt.Sprintf(format, args...)
	}
	return fmt.Sprintf("%s: %s", category, fmt.Sprintf(format, args...))
}

// NewError creates a new error with the specified format and arguments.
// It does not include a category.
//
// Parameters:
//   - format: The format string for the error message
//   - args: Arguments for the format string
//
// Returns:
//   - An error with the formatted message
func NewError(format string, args ...interface{}) error {
	return errors.New(fmt.Sprintf(format, args...))
}

// NewWrappedError creates a new error that wraps an existing error with additional context.
//
// Parameters:
//   - err: The underlying error to wrap
//   - format: The format string for the additional context
//   - args: Arguments for the format string
//
// Returns:
//   - An error that wraps the original error with additional context
func NewWrappedError(err error, format string, args ...interface{}) error {
	return fmt.Errorf("%s: %w", fmt.Sprintf(format, args...), err)
}

// NewCategoryError creates a new error with the specified category, format, and arguments.
//
// Parameters:
//   - category: The error category
//   - format: The format string for the error message
//   - args: Arguments for the format string
//
// Returns:
//   - An error with the formatted message including the category
func NewCategoryError(category, format string, args ...interface{}) error {
	return errors.New(formatError(category, format, args...))
}

// NewWrappedCategoryError creates a new error that wraps an existing error with a category and additional context.
//
// Parameters:
//   - category: The error category
//   - err: The underlying error to wrap
//   - format: The format string for the additional context
//   - args: Arguments for the format string
//
// Returns:
//   - An error that wraps the original error with a category and additional context
func NewWrappedCategoryError(category string, err error, format string, args ...interface{}) error {
	return fmt.Errorf("%s: %w", formatError(category, format, args...), err)
}

// IsDocumentError checks if an error is related to document issues
func IsDocumentError(err error) bool {
	var docErr ErrInvalidDocument
	var docNotFoundErr ErrDocumentNotFound
	return errors.As(err, &docErr) || errors.As(err, &docNotFoundErr)
}

// IsNamespaceError checks if an error is related to namespace issues
func IsNamespaceError(err error) bool {
	var nsNotFoundErr ErrNamespaceNotFound
	var nsEmptyErr ErrNamespaceEmpty
	var nsDigestsNotFoundErr ErrNamespaceDigestsNotFound
	return errors.As(err, &nsNotFoundErr) || errors.As(err, &nsEmptyErr) || errors.As(err, &nsDigestsNotFoundErr)
}

// IsElementError checks if an error is related to element issues
func IsElementError(err error) bool {
	var elemNotFoundErr ErrElementNotFound
	return errors.As(err, &elemNotFoundErr)
}

// IsCertificateError checks if an error is related to certificate issues
func IsCertificateError(err error) bool {
	var certChainErr ErrCertificateChainIssue
	var keyTypeErr ErrInvalidKeyType
	var x5ChainErr ErrX5ChainIssue
	return errors.As(err, &certChainErr) || errors.As(err, &keyTypeErr) || errors.As(err, &x5ChainErr)
}

// IsCOSEError checks if an error is related to COSE structure issues
func IsCOSEError(err error) bool {
	var missingHeadersErr ErrMissingHeaders
	var missingProtectedHeaderErr ErrMissingProtectedHeader
	var missingPayloadErr ErrMissingPayload
	var invalidTaggedContentErr ErrInvalidTaggedContent
	return errors.As(err, &missingHeadersErr) || errors.As(err, &missingProtectedHeaderErr) || 
		   errors.As(err, &missingPayloadErr) || errors.As(err, &invalidTaggedContentErr)
}

// IsDigestError checks if an error is related to digest issues
func IsDigestError(err error) bool {
	var digestNotFoundErr ErrDigestNotFound
	return errors.As(err, &digestNotFoundErr)
}

// IsDeviceError checks if an error is related to device issues
func IsDeviceError(err error) bool {
	var deviceKeyNotAvailableErr ErrDeviceKeyNotAvailable
	var keyAuthorizationsNotAvailableErr ErrKeyAuthorizationsNotAvailable
	var deviceSignedNilErr ErrDeviceSignedNil
	var deviceNameSpacesNilErr ErrDeviceNameSpacesNil
	var missingDeviceProtectedHeadersErr ErrMissingDeviceProtectedHeaders
	var emptySessionTranscriptErr ErrEmptySessionTranscript
	return errors.As(err, &deviceKeyNotAvailableErr) || errors.As(err, &keyAuthorizationsNotAvailableErr) ||
		   errors.As(err, &deviceSignedNilErr) || errors.As(err, &deviceNameSpacesNilErr) ||
		   errors.As(err, &missingDeviceProtectedHeadersErr) || errors.As(err, &emptySessionTranscriptErr)
}