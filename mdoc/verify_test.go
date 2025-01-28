package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kokukuma/mdoc-verifier/pkg/pki"
	"github.com/veraison/go-cose"
)

func TestVerifyDSCertificate(t *testing.T) {
	tests := []struct {
		name                string
		rootPath            string
		signingPath         string
		skipVerifyCert      bool
		certCurrentTime     time.Time
		wantErr             bool
		expectedErrContains string
	}{
		{
			name:        "valid certificate",
			rootPath:    "issuer_root.pem",
			signingPath: "issuer_signing.pem",
			wantErr:     false,
		},
		{
			name:           "skip verification",
			skipVerifyCert: true,
			wantErr:        false,
		},
		{
			name:                "invalid certificate",
			rootPath:            "issuer_root.pem",
			signingPath:         "invalid_signing.pem",
			wantErr:             true,
			expectedErrContains: "failed to verify dsCert chain",
		},
		{
			name:                "expired certificate check",
			rootPath:            "issuer_root.pem",
			signingPath:         "issuer_signing.pem",
			certCurrentTime:     time.Date(3050, 1, 1, 0, 0, 0, 0, time.UTC),
			wantErr:             true,
			expectedErrContains: "certificate has expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var roots *x509.CertPool
			var dsCert *x509.Certificate
			var err error

			if tt.rootPath != "" {
				rootPath, err := getPath(tt.rootPath)
				if err != nil {
					t.Fatalf("failed to get root path: %v", err)
				}
				roots, err = pki.GetRootCertificate(rootPath)
				if err != nil {
					t.Fatalf("failed to load root certs: %v", err)
				}
			}

			if tt.signingPath != "" {
				signingPath, err := getPath(tt.signingPath)
				if err != nil {
					t.Fatalf("failed to get signing path: %v", err)
				}
				dsCert, err = pki.LoadCertificate(signingPath)
				if err != nil {
					t.Fatalf("failed to load ds certs: %v", err)
				}
			}

			verifier := &Verifier{
				roots:                 roots,
				skipVerifyCertificate: tt.skipVerifyCert,
				certCurrentTime:       tt.certCurrentTime,
			}

			err = verifier.verifyDSCertificate(dsCert)

			if tt.wantErr {
				if err == nil {
					t.Error("verifyDSCertificate() error = nil, want error")
					return
				}
				if tt.expectedErrContains != "" && !strings.Contains(err.Error(), tt.expectedErrContains) {
					t.Errorf("verifyDSCertificate() error = %v, want error containing %v", err, tt.expectedErrContains)
				}
			} else {
				if err != nil {
					t.Errorf("verifyDSCertificate() error = %v, want nil", err)
				}
			}
		})
	}
}

func TestVerifyIssuerAuthSignature(t *testing.T) {
	validPrivateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name         string
		issuerSigned IssuerSigneder
		verifier     *Verifier
		wantErr      bool
		errSubstr    string
	}{
		{
			name: "successful verification",
			issuerSigned: &MockIssuerSigned{
				privateKey: validPrivateKey,
				alg:        cose.AlgorithmES256,
				payload:    []byte("test"),
			},
			verifier: &Verifier{},
			wantErr:  false,
		},
		{
			name:         "skip verification",
			issuerSigned: &MockIssuerSigned{},
			verifier:     &Verifier{skipVerifyIssuerAuth: true},
			wantErr:      false,
		},
		{
			name: "invalid algorithm",
			issuerSigned: &MockIssuerSigned{
				privateKey: validPrivateKey,
				alg:        -1, // 無効なアルゴリズム
				payload:    []byte("test"),
			},
			verifier:  &Verifier{},
			wantErr:   true,
			errSubstr: "failed to create signature verifier",
		},
		{
			name: "nil private key",
			issuerSigned: &MockIssuerSigned{
				privateKey: nil,
				alg:        cose.AlgorithmES256,
				payload:    []byte("test"),
			},
			verifier:  &Verifier{},
			wantErr:   true,
			errSubstr: "failed to get document signing key",
		},
		{
			name: "mismatched algorithm",
			issuerSigned: &MockIssuerSigned{
				privateKey: validPrivateKey,
				alg:        cose.AlgorithmES256,
				payload:    []byte("test"),
				verifyErr:  true,
			},
			verifier:  &Verifier{},
			wantErr:   true,
			errSubstr: "failed to verify issuer signature",
		},
		{
			name: "verify returns error",
			issuerSigned: &MockIssuerSigned{
				privateKey: validPrivateKey,
				alg:        cose.AlgorithmES256,
				payload:    []byte("test"),
				verifyErr:  true,
			},
			verifier:  &Verifier{},
			wantErr:   true,
			errSubstr: "failed to verify issuer signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.verifier.verifyIssuerAuthSignature(tt.issuerSigned)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
					return
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error message does not contain %q: %v", tt.errSubstr, err)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyDigests(t *testing.T) {
	tests := []struct {
		name         string
		issuerSigned IssuerSigneder
		mso          MSOer
		wantErr      bool
		errSubstr    string
	}{
		{
			name:         "successful verification",
			issuerSigned: &MockIssuerSigned{},
			mso:          &MockMSO{},
			wantErr:      false,
		},
		{
			name:         "digest not found",
			issuerSigned: &MockIssuerSigned{},
			mso: &MockMSO{
				digestErr: fmt.Errorf("digest not found"),
			},
			wantErr:   true,
			errSubstr: "digest ID 0 not found in namespace",
		},
		{
			name:         "digest calculation error",
			issuerSigned: &MockIssuerSigned{},
			mso: &MockMSO{
				alg: "invalid alg",
			},
			wantErr:   true,
			errSubstr: "failed to calculate digest",
		},
		{
			name:         "digest mismatch",
			issuerSigned: &MockIssuerSigned{},
			mso: &MockMSO{
				digest: []byte("different_digest"),
			},
			wantErr:   true,
			errSubstr: "digest mismatch for ID 0 in namespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := &Verifier{}

			err := verifier.verifyDigests(tt.issuerSigned, tt.mso)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
					return
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error message does not contain %q: %v", tt.errSubstr, err)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyMDocAuthentication(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name              string
		sessionTranscript []byte
		skipVerify        bool
		setupMock         func() (MSOer, DeviceSigneder)
		wantErr           bool
		errMsg            string
	}{
		{
			name:              "success case with device signature",
			sessionTranscript: []byte("sessionTranscript"),
			setupMock: func() (MSOer, DeviceSigneder) {
				return &MockMSO{
						deviceKey: &privateKey.PublicKey,
					}, &MockDeviceSigned{
						authBytes:  []byte("test authentication bytes"),
						algorithm:  cose.AlgorithmES256,
						privateKey: privateKey,
					}
			},
			wantErr: false,
		},
		{
			name:              "success case with skip verify",
			sessionTranscript: []byte("sessionTranscript"),
			skipVerify:        true,
			setupMock: func() (MSOer, DeviceSigneder) {
				return &MockMSO{}, &MockDeviceSigned{}
			},
			wantErr: false,
		},
		{
			name:              "error key authorization failure",
			sessionTranscript: []byte("sessionTranscript"),
			setupMock: func() (MSOer, DeviceSigneder) {
				return &MockMSO{}, &MockDeviceSigned{
					deviceSignErr: errors.New("deviceSignErr"),
					algorithm:     cose.AlgorithmES256,
					privateKey:    privateKey,
				}
			},
			wantErr: true,
			errMsg:  "key authorization verification failed",
		},
		{
			name:              "error auth bytes",
			sessionTranscript: []byte("sessionTranscript"),
			setupMock: func() (MSOer, DeviceSigneder) {
				return &MockMSO{
						deviceKey: &privateKey.PublicKey,
					}, &MockDeviceSigned{
						algorithm:    cose.AlgorithmES256,
						privateKey:   privateKey,
						authBytesErr: errors.New("auth bytes error"),
					}
			},
			wantErr: true,
			errMsg:  "failed to generate device authentication bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mso, deviceSigned := tt.setupMock()
			verifier := &Verifier{
				skipVerifyDeviceSigned: tt.skipVerify,
			}

			err := verifier.verifyMDocAuthentication(mso, deviceSigned, tt.sessionTranscript)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestVerifyDeviceSignature(t *testing.T) {
	tests := []struct {
		name              string
		sessionTranscript []byte
		setupMock         func() (MSOer, DeviceSigneder)
		wantErr           bool
		errMsg            string
	}{
		{
			name:              "success case",
			sessionTranscript: []byte("sessionTranscript"),
			setupMock: func() (MSOer, DeviceSigneder) {
				authBytes := []byte("authentication bytes")
				privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

				return &MockMSO{
						deviceKey: &privateKey.PublicKey,
					}, &MockDeviceSigned{
						privateKey: privateKey,
						algorithm:  cose.AlgorithmES256,
						authBytes:  authBytes,
					}
			},
			wantErr: false,
		},
		{
			name:              "error getting algorithm",
			sessionTranscript: []byte("sessionTranscript"),
			setupMock: func() (MSOer, DeviceSigneder) {
				return &MockMSO{}, &MockDeviceSigned{
					algErr: errors.New("algorithm error"),
				}
			},
			wantErr: true,
			errMsg:  "failed to get signature algorithm",
		},
		{
			name:              "error getting device key",
			sessionTranscript: []byte("sessionTranscript"),
			setupMock: func() (MSOer, DeviceSigneder) {
				return &MockMSO{
					deviceKeyErr: errors.New("device key error"),
				}, &MockDeviceSigned{}
			},
			wantErr: true,
			errMsg:  "failed to get device public key",
		},
		{
			name:              "error getting auth bytes",
			sessionTranscript: []byte("sessionTranscript"),
			setupMock: func() (MSOer, DeviceSigneder) {
				privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &MockMSO{
						deviceKey: &privateKey.PublicKey,
					}, &MockDeviceSigned{
						privateKey:   privateKey,
						algorithm:    cose.AlgorithmES256,
						authBytesErr: errors.New("auth bytes error"),
					}
			},
			wantErr: true,
			errMsg:  "failed to generate device authentication bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mso, deviceSigned := tt.setupMock()
			verifier := &Verifier{}

			err := verifier.verifyDeviceSignature(mso, deviceSigned, tt.sessionTranscript)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestVerifyMSOValidity(t *testing.T) {
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name                     string
		skipSignedDateValidation bool
		signCurrentTime          time.Time
		dsCert                   *x509.Certificate
		validityInfo             ValidityInfo
		wantErr                  bool
		errMsg                   string
	}{
		{
			name: "success case",
			dsCert: &x509.Certificate{
				NotBefore: baseTime.Add(-24 * time.Hour), // 2023-12-31
				NotAfter:  baseTime.Add(48 * time.Hour),  // 2024-01-03
			},
			signCurrentTime: baseTime, // 2024-01-01
			validityInfo: ValidityInfo{
				Signed:     baseTime,                      // 2024-01-01
				ValidFrom:  baseTime.Add(-12 * time.Hour), // 2023-12-31 12:00
				ValidUntil: baseTime.Add(24 * time.Hour),  // 2024-01-02
			},
			wantErr: false,
		},
		{
			name:                     "success case with skip signed date validation",
			skipSignedDateValidation: true,
			dsCert: &x509.Certificate{
				NotBefore: baseTime.Add(24 * time.Hour), // 2024-01-02
				NotAfter:  baseTime.Add(48 * time.Hour), // 2024-01-03
			},
			signCurrentTime: baseTime, // 2024-01-01
			validityInfo: ValidityInfo{
				Signed:     baseTime.Add(-48 * time.Hour), // 2023-12-30
				ValidFrom:  baseTime.Add(-12 * time.Hour), // 2023-12-31 12:00
				ValidUntil: baseTime.Add(24 * time.Hour),  // 2024-01-02
			},
			wantErr: false,
		},
		{
			name: "error signed date before cert validity",
			dsCert: &x509.Certificate{
				NotBefore: baseTime.Add(24 * time.Hour), // 2024-01-02
				NotAfter:  baseTime.Add(72 * time.Hour), // 2024-01-04
			},
			signCurrentTime: baseTime, // 2024-01-01
			validityInfo: ValidityInfo{
				Signed:     baseTime,                      // 2024-01-01
				ValidFrom:  baseTime.Add(-12 * time.Hour), // 2023-12-31 12:00
				ValidUntil: baseTime.Add(24 * time.Hour),  // 2024-01-02
			},
			wantErr: true,
			errMsg:  "MSO signed date outside dsCert validity period",
		},
		{
			name: "error signed date after cert validity",
			dsCert: &x509.Certificate{
				NotBefore: baseTime.Add(-48 * time.Hour), // 2023-12-30
				NotAfter:  baseTime.Add(-24 * time.Hour), // 2023-12-31
			},
			signCurrentTime: baseTime, // 2024-01-01
			validityInfo: ValidityInfo{
				Signed:     baseTime,                      // 2024-01-01
				ValidFrom:  baseTime.Add(-12 * time.Hour), // 2023-12-31 12:00
				ValidUntil: baseTime.Add(24 * time.Hour),  // 2024-01-02
			},
			wantErr: true,
			errMsg:  "MSO signed date outside dsCert validity period",
		},
		{
			name: "error current time before valid from",
			dsCert: &x509.Certificate{
				NotBefore: baseTime.Add(-48 * time.Hour), // 2023-12-30
				NotAfter:  baseTime.Add(48 * time.Hour),  // 2024-01-03
			},
			signCurrentTime: baseTime, // 2024-01-01
			validityInfo: ValidityInfo{
				Signed:     baseTime,                     // 2024-01-01
				ValidFrom:  baseTime.Add(12 * time.Hour), // 2024-01-01 12:00
				ValidUntil: baseTime.Add(24 * time.Hour), // 2024-01-02
			},
			wantErr: true,
			errMsg:  "current time outside MSO validity period",
		},
		{
			name: "error current time after valid until",
			dsCert: &x509.Certificate{
				NotBefore: baseTime.Add(-48 * time.Hour), // 2023-12-30
				NotAfter:  baseTime.Add(48 * time.Hour),  // 2024-01-03
			},
			signCurrentTime: baseTime.Add(48 * time.Hour), // 2024-01-03
			validityInfo: ValidityInfo{
				Signed:     baseTime,                      // 2024-01-01
				ValidFrom:  baseTime.Add(-12 * time.Hour), // 2023-12-31 12:00
				ValidUntil: baseTime.Add(24 * time.Hour),  // 2024-01-02
			},
			wantErr: true,
			errMsg:  "current time outside MSO validity period",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// MockMSOの設定
			mso := &MockMSO{
				validityInfo: tt.validityInfo,
			}

			// GetValidityInfoをオーバーライド
			verifier := &Verifier{
				skipSignedDateValidation: tt.skipSignedDateValidation,
				signCurrenTime:           tt.signCurrentTime,
			}

			err := verifier.verifyMSOValidity(tt.dsCert, mso)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// インターフェースを満たすモック構造体

type MockIssuerSigned struct {
	privateKey *ecdsa.PrivateKey
	alg        cose.Algorithm
	payload    []byte
	verifyErr  bool
	algErr     error
}

func (m *MockIssuerSigned) Alg() (cose.Algorithm, error) {
	if m.algErr != nil {
		return 0, m.algErr
	}
	return m.alg, nil
}

func (m *MockIssuerSigned) DocumentSigningKey() (*ecdsa.PublicKey, error) {
	if m.privateKey == nil {
		return nil, errors.New("failed to get DocumentSigningKey")
	}
	return &m.privateKey.PublicKey, nil
}

func (m *MockIssuerSigned) GetIssuerAuth() cose.UntaggedSign1Message {
	signer, _ := cose.NewSigner(m.alg, m.privateKey)
	sign := cose.UntaggedSign1Message{
		Headers: cose.Headers{
			Protected: cose.ProtectedHeader{
				cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
			},
		},
	}
	sign.Payload = m.payload
	sign.Sign(rand.Reader, nil, signer)

	if m.verifyErr {
		sign.Payload = []byte("verifyErr")
	}

	return sign
}

func (m *MockIssuerSigned) GetNameSpaces() []NameSpace {
	return []NameSpace{
		"namespace",
	}
}

func (m *MockIssuerSigned) GetIssuerSignedItems(NameSpace) ([]IssuerSignedItem, error) {
	return []IssuerSignedItem{
		{
			DigestID:          DigestID(0),
			Random:            []byte("random"),
			ElementIdentifier: ElementIdentifier("id"),
			ElementValue:      ElementValue("value"),
			rawBytes:          IssuerSignedItemBytes{},
		},
	}, nil
}

type MockMSO struct {
	deviceKey    *ecdsa.PublicKey
	deviceKeyErr error
	digest       []byte
	digestErr    error
	validityInfo ValidityInfo
	alg          string
}

func (m *MockMSO) DeviceKey() (*ecdsa.PublicKey, error) {
	return m.deviceKey, m.deviceKeyErr
}

func (m *MockMSO) GetDocType() DocType {
	return DocType("test_doc_type")
}

func (m *MockMSO) GetDigest(ns NameSpace, id DigestID) (Digest, error) {
	if m.digestErr != nil {
		return nil, m.digestErr
	}
	if m.digest != nil {
		return m.digest, nil
	}
	isi := IssuerSignedItem{
		rawBytes: IssuerSignedItemBytes{},
	}
	return isi.Digest("SHA-256")
}

func (m *MockMSO) DigestAlg() string {
	if m.alg != "" {
		return m.alg
	}
	return "SHA-256"
}

func (m *MockMSO) GetValidityInfo() ValidityInfo {
	return m.validityInfo
}

func (m *MockMSO) KeyAuthorizations() (*KeyAuthorizations, error) {
	return &KeyAuthorizations{}, nil
}

type MockDeviceSigned struct {
	authBytes     []byte
	authBytesErr  error
	algErr        error
	deviceSignErr error
	algorithm     cose.Algorithm
	privateKey    *ecdsa.PrivateKey
}

func (m *MockDeviceSigned) Alg() (cose.Algorithm, error) {
	if m.algErr != nil {
		return 0, m.algErr
	}
	return m.algorithm, nil
}

func (m *MockDeviceSigned) DeviceAuthMac() *UntaggedSign1Message {
	return nil
}

func (m *MockDeviceSigned) DeviceAuthSignature() *UntaggedSign1Message {
	signer, _ := cose.NewSigner(cose.AlgorithmES256, m.privateKey)
	sign := UntaggedSign1Message{}
	sign.Payload = m.authBytes
	sign.Sign(rand.Reader, nil, signer)
	signature := sign.Signature

	return &UntaggedSign1Message{
		Headers: cose.Headers{
			Protected: cose.ProtectedHeader{
				cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
			},
		},
		Signature: signature, // 外部から渡された署名を使用
	}
}

func (m *MockDeviceSigned) DeviceAuthenticationBytes(docType DocType, st []byte) ([]byte, error) {
	return m.authBytes, m.authBytesErr
}

func (m *MockDeviceSigned) DeviceNameSpaces() (DeviceNameSpaces, error) {
	if m.deviceSignErr != nil {
		return DeviceNameSpaces{}, m.deviceSignErr
	}
	return DeviceNameSpaces{}, nil
}
