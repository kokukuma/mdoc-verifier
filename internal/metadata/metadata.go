package metadata

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/form3tech-oss/jwt-go"
	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"
)

// https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html
// https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#idl-index

// type AuthenticatorAttestationType string
//
// const (
// 	BasicFull      AuthenticatorAttestationType = "basic_full"
// 	BasicSurrogate                              = "basic_surrogate"
// 	Ecdaa                                       = "ecdaa"
// 	AttCA                                       = "att_ca"
// )
//
type AuthenticatorStatus string

const (
	NotFidoCertified          = "NOT_FIDO_CERTIFIED"
	FidoCertified             = "FIDO_CERTIFIED"
	UserVerificationBypass    = "USER_VERIFICATION_BYPASS"
	AttestationKeyCompromise  = "ATTESTATION_KEY_COMPROMISE"
	UserKeyRemoteCompromise   = "USER_KEY_REMOTE_COMPROMISE"
	UserKeyPhysicalCompromise = "USER_KEY_PHYSICAL_COMPROMISE"
	UpdateAvailable           = "UPDATE_AVAILABLE"
	Revoked                   = "REVOKED"
	SelfAssertionSubmitted    = "SELF_ASSERTION_SUBMITTED"
	FidoCertifiedL1           = "FIDO_CERTIFIED_L1"
	FidoCertifiedL1plus       = "FIDO_CERTIFIED_L1plus"
	FidoCertifiedL2           = "FIDO_CERTIFIED_L2"
	FidoCertifiedL2plus       = "FIDO_CERTIFIED_L2plus"
	FidoCertifiedL3           = "FIDO_CERTIFIED_L3"
	FidoCertifiedL3plus       = "FIDO_CERTIFIED_L3plus"
)

//
// var UndesiredAuthenticatorStatus = [...]AuthenticatorStatus{
// 	AttestationKeyCompromise,
// 	UserVerificationBypass,
// 	UserKeyRemoteCompromise,
// 	UserKeyPhysicalCompromise,
// 	Revoked,
// }
//
// func IsUndesiredAuthenticatorStatus(status AuthenticatorStatus) bool {
// 	for _, s := range UndesiredAuthenticatorStatus {
// 		if s == status {
// 			return true
// 		}
// 	}
// 	return false
// }

type StatusReport struct {
	Status                           AuthenticatorStatus `json:"status"`
	EffectiveDate                    string              `json:"effectiveDate"`
	Certificate                      string              `json:"certificate"`
	URL                              string              `json:"url"`
	CertificationDescriptor          string              `json:"certificationDescriptor"`
	CertificateNumber                string              `json:"certificateNumber"`
	CertificationPolicyVersion       string              `json:"certificationPolicyVersion"`
	CertificationRequirementsVersion string              `json:"certificationRequirementsVersion"`
}

type BiometricStatusReport struct {
	CertLevel                        uint16 `json:"certLevel"`
	Modality                         uint32 `json:"modality"`
	EffectiveDate                    string `json:"effectiveDate"`
	CertificationDescriptor          string `json:"certificationDescriptor"`
	CertificateNumber                string `json:"certificateNumber"`
	CertificationPolicyVersion       string `json:"certificationPolicyVersion"`
	CertificationRequirementsVersion string `json:"certificationRequirementsVersion"`
}

type CodeAccuracyDescriptor struct {
	Base          uint16 `json:"base"`
	MinLength     uint16 `json:"minLength"`
	MaxRetries    uint16 `json:"maxRetries"`
	BlockSlowdown uint16 `json:"blockSlowdown"`
}

type BiometricAccuracyDescriptor struct {
	SelfAttestedFRR int64  `json:"selfAttestedFRR "`
	SelfAttestedFAR int64  `json:"selfAttestedFAR "`
	MaxTemplates    uint16 `json:"maxTemplates"`
	MaxRetries      uint16 `json:"maxRetries"`
	BlockSlowdown   uint16 `json:"blockSlowdown"`
}

type PatternAccuracyDescriptor struct {
	MinComplexity uint32 `json:"minComplexity"`
	MaxRetries    uint16 `json:"maxRetries"`
	BlockSlowdown uint16 `json:"blockSlowdown"`
}

type VerificationMethodDescriptor struct {
	UserVerification uint32                      `json:"userVerification"`
	CaDesc           CodeAccuracyDescriptor      `json:"caDesc"`
	BaDesc           BiometricAccuracyDescriptor `json:"baDesc"`
	PaDesc           PatternAccuracyDescriptor   `json:"paDesc"`
}

type VerificationMethodANDCombinations struct {
	VerificationMethodAndCombinations []VerificationMethodDescriptor `json:"verificationMethodANDCombinations"`
}

type rgbPaletteEntry struct {
	R uint16 `json:"r"`
	G uint16 `json:"g"`
	B uint16 `json:"b"`
}

type DisplayPNGCharacteristicsDescriptor struct {
	Width       uint32            `json:"width"`
	Height      uint32            `json:"height"`
	BitDepth    byte              `json:"bitDepth"`
	ColorType   byte              `json:"colorType"`
	Compression byte              `json:"compression"`
	Filter      byte              `json:"filter"`
	Interlace   byte              `json:"interlace"`
	Plte        []rgbPaletteEntry `json:"plte"`
}

type EcdaaTrustAnchor struct {
	X       string `json:"x"`
	Y       string `json:"y"`
	C       string `json:"c"`
	SX      string `json:"sx"`
	SY      string `json:"sy"`
	G1Curve string `json:"G1Curve"`
}

type ExtensionDescriptor struct {
	ID            string `json:"id"`
	Tag           uint16 `json:"tag"`
	Data          string `json:"data"`
	FailIfUnknown bool   `json:"fail_if_unknown"`
}

type MetadataStatement struct {
	LegalHeader                          string                                `json:"legalHeader"`
	Aaid                                 string                                `json:"aaid"`
	AaGUID                               string                                `json:"aaguid"`
	AttestationCertificateKeyIdentifiers []string                              `json:"attestationCertificateKeyIdentifiers"`
	Description                          string                                `json:"description"`
	AlternativeDescriptions              map[string]string                     `json:"alternativeDescriptions"`
	AuthenticatorVersion                 uint16                                `json:"authenticatorVersion"`
	ProtocolFamily                       string                                `json:"protocolFamily"`
	Upv                                  []Version                             `json:"upv"`
	AssertionScheme                      string                                `json:"assertionScheme"`
	AuthenticationAlgorithm              uint16                                `json:"authenticationAlgorithm"`
	AuthenticationAlgorithms             []string                              `json:"authenticationAlgorithms"`
	PublicKeyAlgAndEncoding              uint16                                `json:"publicKeyAlgAndEncoding"`
	PublicKeyAlgAndEncodings             []string                              `json:"publicKeyAlgAndEncodings"`
	AttestationTypes                     []string                              `json:"attestationTypes"`
	UserVerificationDetails              [][]VerificationMethodDescriptor      `json:"userVerificationDetails"`
	KeyProtection                        []string                              `json:"keyProtection"`
	IsKeyRestricted                      bool                                  `json:"isKeyRestricted"`
	IsFreshUserVerificationRequired      bool                                  `json:"isFreshUserVerificationRequired"`
	MatcherProtection                    []string                              `json:"matcherProtection"`
	CryptoStrength                       uint16                                `json:"cryptoStrength"`
	OperatingEnv                         string                                `json:"operatingEnv"`
	AttachmentHint                       []string                              `json:"attachmentHint"`
	IsSecondFactorOnly                   bool                                  `json:"isSecondFactorOnly"`
	TcDisplay                            []string                              `json:"tcDisplay"`
	TcDisplayContentType                 string                                `json:"tcDisplayContentType"`
	TcDisplayPNGCharacteristics          []DisplayPNGCharacteristicsDescriptor `json:"tcDisplayPNGCharacteristics"`
	AttestationRootCertificates          []string                              `json:"attestationRootCertificates"`
	EcdaaTrustAnchors                    []EcdaaTrustAnchor                    `json:"ecdaaTrustAnchors"`
	Icon                                 string                                `json:"icon"`
	SupportedExtensions                  []ExtensionDescriptor                 `json:"supportedExtensions"`
}

type Version struct {
	Major uint16 `json:"major"`
	Minor uint16 `json:"minor"`
}

type MetadataBlobPayloadEntry struct {
	Aaid                                 string                  `json:"aaid"`
	AaGUID                               string                  `json:"aaguid"`
	AttestationCertificateKeyIdentifiers []string                `json:"attestationCertificateKeyIdentifiers"`
	Hash                                 string                  `json:"hash"`
	URL                                  string                  `json:"url"`
	BiometricStatusReports               []BiometricStatusReport `json:"biometricStatusReports"`
	StatusReports                        []StatusReport          `json:"statusReports"`
	TimeOfLastStatusChange               string                  `json:"timeOfLastStatusChange"`
	RogueListURL                         string                  `json:"rogueListURL"`
	RogueListHash                        string                  `json:"rogueListHash"`
	MetadataStatement                    MetadataStatement
}

type MetadataBlobPayload struct {
	LegalHeader string                     `json:"legalHeader"`
	Number      int                        `json:"no"`
	NextUpdate  string                     `json:"nextUpdate"`
	Entries     []MetadataBlobPayloadEntry `json:"entries"`
}

func (m *MetadataBlobPayload) EntriesMap() (map[uuid.UUID]MetadataBlobPayloadEntry, error) {
	result := make(map[uuid.UUID]MetadataBlobPayloadEntry)

	for _, e := range m.Entries {
		if e.AaGUID == "" {
			continue
		}
		uuid, err := uuid.Parse(e.AaGUID)
		if err != nil {
			return nil, err
		}
		result[uuid] = e
	}
	return result, nil
}

func ProcessMDSBLOB(url string, c http.Client) (MetadataBlobPayload, error) {
	// https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-object-processing-rules
	var payload MetadataBlobPayload

	body, err := downloadBytes(url, c)
	if err != nil {
		return payload, err
	}
	return unmarshalMDSTOC(body, c)
}

func unmarshalMDSTOC(body []byte, c http.Client) (MetadataBlobPayload, error) {
	var payload MetadataBlobPayload

	token, err := jwt.Parse(string(body), func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Header["x5u"].([]interface{}); ok {
			// TODO: download
			return nil, errors.New("not supported yet")
		}

		var chain []interface{}
		if x5c, ok := token.Header["x5c"].([]interface{}); !ok {
			root, err := getMetdataBlobSigningTrustAnchor(c)
			if nil != err {
				return nil, err
			}
			chain[0] = root
		} else {
			chain = x5c
		}

		cert, err := getValidatedCert(chain, c)
		if err != nil {
			return nil, err
		}
		return cert.PublicKey, err
	})
	if err != nil {
		return payload, err
	}

	err = mapstructure.Decode(token.Claims, &payload)

	return payload, err
}

func getCert(certBase64 interface{}) (*x509.Certificate, error) {
	n, err := base64.StdEncoding.DecodeString(certBase64.(string))
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(n)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func getValidatedCert(chain []interface{}, c http.Client) (*x509.Certificate, error) {
	root, err := getMetdataBlobSigningTrustAnchor(c)
	if err != nil {
		return nil, err
	}

	// root
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(root)
	if !ok {
		return nil, errors.New("failed to add root cert")
	}

	// intermediates
	ints := x509.NewCertPool()
	for _, certElem := range chain[1:] {
		intcert, err := getCert(certElem)
		if err != nil {
			return nil, err
		}
		ints.AddCert(intcert)
	}

	// leaf verify
	cert, err := getCert(chain[0])
	if err != nil {
		return nil, err
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: ints,
	}

	if _, err := cert.Verify(opts); err != nil {
		return nil, err
	}
	return cert, nil

}

func getMetdataBlobSigningTrustAnchor(c http.Client) ([]byte, error) {
	rooturl := "https://valid.r3.roots.globalsign.com/"
	return downloadBytes(rooturl, c)
}

func downloadBytes(url string, c http.Client) ([]byte, error) {
	res, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)
	return body, err
}
