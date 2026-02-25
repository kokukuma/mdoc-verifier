package mdocapi

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/fxamacker/cbor/v2"
	"github.com/kokukuma/mdoc-verifier/mdoc"
	"github.com/kokukuma/mdoc-verifier/session_transcript"
	"github.com/veraison/go-cose"
)

var (
	b64 = base64.URLEncoding.WithPadding(base64.StdPadding)

	// Deterministic CBOR encoder for consistent key ordering
	deterministicEncMode cbor.EncMode
)

func init() {
	// Create deterministic encoding mode with sorted map keys
	encOpts := cbor.EncOptions{
		Sort: cbor.SortCoreDeterministic, // Sort map keys per RFC 8949
	}
	var err error
	deterministicEncMode, err = encOpts.EncMode()
	if err != nil {
		panic(err)
	}
}

// COSE key type and curve constants
const (
	CoseKeyTypeEC2   = 2  // EC2 key type
	CoseKeyCurveP256 = 1  // P-256 curve
	CoseKeyLabelKty  = 1  // kty
	CoseKeyLabelCrv  = -1 // crv
	CoseKeyLabelX    = -2 // x coordinate
	CoseKeyLabelY    = -3 // y coordinate
)

// MdocAPIRequest represents the request format for org-iso-mdoc protocol
type MdocAPIRequest struct {
	DeviceRequest  string `json:"deviceRequest"`
	EncryptionInfo string `json:"encryptionInfo"`
}

// DocRequestInput represents input for creating a document request
type DocRequestInput struct {
	DocType    mdoc.DocType
	Namespaces map[mdoc.NameSpace]map[mdoc.ElementIdentifier]bool // namespace -> element -> intentToRetain
}

// PrepareEncryptionInfo creates encryptionInfo and session transcript for DC API
// Returns: (encryptionInfo bytes, sessionTranscript bytes, error)
func PrepareEncryptionInfo(nonce []byte, publicKey *ecdh.PublicKey, origin string) ([]byte, []byte, error) {
	if len(nonce) == 0 {
		return nil, nil, fmt.Errorf("nonce cannot be empty")
	}
	if publicKey == nil {
		return nil, nil, fmt.Errorf("publicKey cannot be nil")
	}
	if origin == "" {
		return nil, nil, fmt.Errorf("origin cannot be empty")
	}

	// Create COSE_Key from public key
	coseKey, err := createCoseKey(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create COSE_Key: %w", err)
	}

	// Create encryptionInfo: ["dcapi", {"nonce": bytes, "recipientPublicKey": COSE_Key}]
	encryptionInfo := []interface{}{
		"dcapi",
		map[interface{}]interface{}{
			"nonce":              nonce,
			"recipientPublicKey": coseKey,
		},
	}

	// Use deterministic encoding for consistent key ordering
	encryptionInfoBytes, err := deterministicEncMode.Marshal(encryptionInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode encryptionInfo: %w", err)
	}

	// Create session transcript using the encryptionInfo
	sessTrans, err := session_transcript.DcapiHandover(encryptionInfoBytes, origin)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create session transcript: %w", err)
	}

	return encryptionInfoBytes, sessTrans, nil
}

// CreateRequest creates a MdocAPIRequest with optional Reader Authentication
// If readerKey is nil, the request is created without readerAuth (unsigned)
func CreateRequest(
	docRequests []DocRequestInput,
	sessionTranscript []byte,
	readerKey *ecdsa.PrivateKey, // nil for unsigned request
	readerCertChain []string, // base64-encoded DER certificates
) (*MdocAPIRequest, []byte, error) {
	if len(docRequests) == 0 {
		return nil, nil, fmt.Errorf("docRequests cannot be empty")
	}
	if len(sessionTranscript) == 0 {
		return nil, nil, fmt.Errorf("sessionTranscript cannot be empty")
	}

	// Build docRequests array
	docRequestsArray := make([]interface{}, 0, len(docRequests))

	for _, dr := range docRequests {
		// Build itemsRequest
		itemsRequest := map[string]interface{}{
			"docType":    string(dr.DocType),
			"nameSpaces": buildNameSpaces(dr.Namespaces),
		}

		itemsRequestBytes, err := deterministicEncMode.Marshal(itemsRequest)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to encode itemsRequest: %w", err)
		}

		// Create Tagged(24, itemsRequestBytes) for CBOR bstr .cbor ItemsRequest
		itemsRequestTagged := cbor.Tag{
			Number:  24,
			Content: itemsRequestBytes,
		}

		docRequest := map[string]interface{}{
			"itemsRequest": itemsRequestTagged,
		}

		// Add readerAuth if signing key is provided
		if readerKey != nil {
			readerAuthBytes, err := createReaderAuth(itemsRequestBytes, sessionTranscript, readerKey, readerCertChain)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create readerAuth: %w", err)
			}
			// Use RawMessage to embed the COSE_Sign1 structure directly (not as bstr)
			docRequest["readerAuth"] = cbor.RawMessage(readerAuthBytes)
		}

		docRequestsArray = append(docRequestsArray, docRequest)
	}

	// Build deviceRequest
	deviceRequest := map[string]interface{}{
		"version":     "1.0",
		"docRequests": docRequestsArray,
	}

	deviceRequestBytes, err := deterministicEncMode.Marshal(deviceRequest)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode deviceRequest: %w", err)
	}

	return &MdocAPIRequest{
		DeviceRequest: b64.EncodeToString(deviceRequestBytes),
	}, deviceRequestBytes, nil
}

// CreateFullRequest creates a complete MdocAPIRequest with encryptionInfo and deviceRequest
func CreateFullRequest(
	nonce []byte,
	publicKey *ecdh.PublicKey,
	origin string,
	docRequests []DocRequestInput,
	readerKey *ecdsa.PrivateKey,
	readerCertChain []string,
) (*MdocAPIRequest, []byte, error) {
	// Prepare encryption info and session transcript
	encryptionInfoBytes, sessTrans, err := PrepareEncryptionInfo(nonce, publicKey, origin)
	if err != nil {
		return nil, nil, err
	}

	// Create the request
	req, _, err := CreateRequest(docRequests, sessTrans, readerKey, readerCertChain)
	if err != nil {
		return nil, nil, err
	}

	// Set encryptionInfo
	req.EncryptionInfo = b64.EncodeToString(encryptionInfoBytes)

	return req, encryptionInfoBytes, nil
}

// buildNameSpaces converts the namespace map to CBOR format
func buildNameSpaces(namespaces map[mdoc.NameSpace]map[mdoc.ElementIdentifier]bool) map[string]map[string]bool {
	result := make(map[string]map[string]bool)
	for ns, elements := range namespaces {
		nsMap := make(map[string]bool)
		for elem, retain := range elements {
			nsMap[string(elem)] = retain
		}
		result[string(ns)] = nsMap
	}
	return result
}

// createCoseKey creates a COSE_Key from an ECDH public key
func createCoseKey(publicKey *ecdh.PublicKey) (map[interface{}]interface{}, error) {
	// Get raw public key bytes (uncompressed: 0x04 || X || Y)
	rawBytes := publicKey.Bytes()
	if len(rawBytes) != 65 || rawBytes[0] != 0x04 {
		return nil, fmt.Errorf("invalid public key format")
	}

	x := rawBytes[1:33]
	y := rawBytes[33:65]

	coseKey := map[interface{}]interface{}{
		CoseKeyLabelKty: CoseKeyTypeEC2,   // kty: EC2
		CoseKeyLabelCrv: CoseKeyCurveP256, // crv: P-256
		CoseKeyLabelX:   x,                // x coordinate
		CoseKeyLabelY:   y,                // y coordinate
	}

	return coseKey, nil
}

// createReaderAuth creates a COSE_Sign1 structure for Reader Authentication
func createReaderAuth(
	itemsRequestBytes []byte,
	sessionTranscript []byte,
	readerKey *ecdsa.PrivateKey,
	readerCertChain []string,
) ([]byte, error) {
	// Create ReaderAuthentication structure: ["ReaderAuthentication", sessionTranscript, itemsRequestBytes]
	// itemsRequestBytes needs to be wrapped as Tagged(24, bytes)
	readerAuth := []interface{}{
		"ReaderAuthentication",
		cbor.RawMessage(sessionTranscript),
		cbor.Tag{Number: 24, Content: itemsRequestBytes},
	}

	readerAuthBytes, err := deterministicEncMode.Marshal(readerAuth)
	if err != nil {
		return nil, fmt.Errorf("failed to encode ReaderAuthentication: %w", err)
	}

	// Wrap in Tagged(24, ...) as per ISO 18013-5
	readerAuthTaggedBytes, err := deterministicEncMode.Marshal(cbor.Tag{Number: 24, Content: readerAuthBytes})
	if err != nil {
		return nil, fmt.Errorf("failed to encode tagged ReaderAuthentication: %w", err)
	}

	// Log the payload structure for debugging
	log.Printf("createReaderAuth: itemsRequestBytes (hex): %x", itemsRequestBytes)
	log.Printf("createReaderAuth: sessionTranscript (hex): %x", sessionTranscript)
	log.Printf("createReaderAuth: readerAuthTaggedBytes (payload for signing, hex): %x", readerAuthTaggedBytes)

	// Decode certificate chain
	certs := make([][]byte, len(readerCertChain))
	for i, certB64 := range readerCertChain {
		certBytes, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode certificate %d: %w", i, err)
		}
		certs[i] = certBytes
	}

	// Create COSE_Sign1 signer
	signer, err := cose.NewSigner(cose.AlgorithmES256, readerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	// Create COSE_Sign1 message with payload set for signing
	msg := cose.Sign1Message{
		Headers: cose.Headers{
			Protected: cose.ProtectedHeader{
				cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
			},
			Unprotected: cose.UnprotectedHeader{
				cose.HeaderLabelX5Chain: certs,
			},
		},
		Payload: readerAuthTaggedBytes, // Set payload for signing
	}

	// Sign the message (external AAD is nil)
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// Clear payload for detached signature output
	msg.Payload = nil

	// Marshal to CBOR
	signedBytes, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal COSE_Sign1: %w", err)
	}

	return signedBytes, nil
}

// ConvertCredentialToDocRequest converts a Credential to DocRequestInput
func ConvertCredentialToDocRequest(docType mdoc.DocType, namespace mdoc.NameSpace, elements []mdoc.ElementIdentifier, intentToRetain bool) DocRequestInput {
	elemMap := make(map[mdoc.ElementIdentifier]bool)
	for _, elem := range elements {
		elemMap[elem] = intentToRetain
	}

	return DocRequestInput{
		DocType: docType,
		Namespaces: map[mdoc.NameSpace]map[mdoc.ElementIdentifier]bool{
			namespace: elemMap,
		},
	}
}

// ============================================================================
// Version 1.1 API (Apple DC API compatible)
// ============================================================================

// CreateRequestV11 creates a MdocAPIRequest using version 1.1 format
// This format is compatible with Apple's DC API implementation
// Key differences from 1.0:
// - readerAuth moved to top-level "readerAuthAlg" array
// - deviceRequestInfo added for use case information
func CreateRequestV11(
	docRequests []DocRequestInput,
	sessionTranscript []byte,
	readerKey *ecdsa.PrivateKey,
	readerCertChain []string,
) (*MdocAPIRequest, []byte, error) {
	if len(docRequests) == 0 {
		return nil, nil, fmt.Errorf("docRequests cannot be empty")
	}
	if len(sessionTranscript) == 0 {
		return nil, nil, fmt.Errorf("sessionTranscript cannot be empty")
	}

	// Build docRequests array (without readerAuth - moved to top level)
	docRequestsArray := make([]interface{}, 0, len(docRequests))
	readerAuthAlgArray := make([]interface{}, 0)

	for _, dr := range docRequests {
		// Build itemsRequest
		itemsRequest := map[string]interface{}{
			"docType":    string(dr.DocType),
			"nameSpaces": buildNameSpaces(dr.Namespaces),
		}

		itemsRequestBytes, err := deterministicEncMode.Marshal(itemsRequest)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to encode itemsRequest: %w", err)
		}

		// Create Tagged(24, itemsRequestBytes)
		itemsRequestTagged := cbor.Tag{
			Number:  24,
			Content: itemsRequestBytes,
		}

		// docRequest contains itemsRequest
		docRequest := map[string]interface{}{
			"itemsRequest": itemsRequestTagged,
		}

		// Build readerAuth for this docRequest
		if readerKey != nil {
			readerAuthBytes, err := createReaderAuth(itemsRequestBytes, sessionTranscript, readerKey, readerCertChain)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create readerAuth: %w", err)
			}

			// Add readerAuth to docRequest (V1.0 style) as well as readerAuthAlg (V1.1 style)
			docRequest["readerAuth"] = cbor.RawMessage(readerAuthBytes)
			readerAuthAlgArray = append(readerAuthAlgArray, cbor.RawMessage(readerAuthBytes))
		}

		docRequestsArray = append(docRequestsArray, docRequest)
	}

	// Build deviceRequestInfo
	// useCases: array of use case objects
	// - mandatory: whether this use case is required
	// - documentSets: array of document set indices (referencing docRequests)
	documentSets := make([]interface{}, len(docRequests))
	for i := range docRequests {
		documentSets[i] = i // Reference to docRequests index
	}

	deviceRequestInfo := map[string]interface{}{
		"useCases": []interface{}{
			map[string]interface{}{
				"mandatory":    true,
				"documentSets": []interface{}{documentSets},
			},
		},
	}

	deviceRequestInfoBytes, err := deterministicEncMode.Marshal(deviceRequestInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode deviceRequestInfo: %w", err)
	}

	// Build deviceRequest with version 1.1 structure
	deviceRequest := map[string]interface{}{
		"version":     "1.1",
		"docRequests": docRequestsArray,
		"deviceRequestInfo": cbor.Tag{
			Number:  24,
			Content: deviceRequestInfoBytes,
		},
	}

	// Add readerAuthAlg if signing key is provided
	if readerKey != nil && len(readerAuthAlgArray) > 0 {
		deviceRequest["readerAuthAlg"] = readerAuthAlgArray
	}

	deviceRequestBytes, err := deterministicEncMode.Marshal(deviceRequest)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode deviceRequest: %w", err)
	}

	return &MdocAPIRequest{
		DeviceRequest: b64.EncodeToString(deviceRequestBytes),
	}, deviceRequestBytes, nil
}

// CreateFullRequestV11 creates a complete MdocAPIRequest with version 1.1 format
// Uses 32-byte nonce as per Apple's implementation
func CreateFullRequestV11(
	nonce []byte,
	publicKey *ecdh.PublicKey,
	origin string,
	docRequests []DocRequestInput,
	readerKey *ecdsa.PrivateKey,
	readerCertChain []string,
) (*MdocAPIRequest, []byte, error) {
	// Prepare encryption info and session transcript
	encryptionInfoBytes, sessTrans, err := PrepareEncryptionInfo(nonce, publicKey, origin)
	if err != nil {
		return nil, nil, err
	}

	// Create the request with version 1.1
	req, _, err := CreateRequestV11(docRequests, sessTrans, readerKey, readerCertChain)
	if err != nil {
		return nil, nil, err
	}

	// Set encryptionInfo
	req.EncryptionInfo = b64.EncodeToString(encryptionInfoBytes)

	return req, encryptionInfoBytes, nil
}
