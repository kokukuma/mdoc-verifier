package exchange_protocol

import (
	"encoding/base64"
	"fmt"

	"github.com/cisco/go-hpke"
)

// DecryptAndroidHPKEV1 decrypts the CipherText in the AndroidHPKEV1 struct using the provided recipient private key
// func DecryptAndroidHPKEV1(claims *AndroidHPKEV1, recipientPrivKey, recipientPubKey, nonceStr, origin string) ([]byte, error) {
func DecryptHPKE(claims *HPKEEnvelope, recipientPrivKey, info []byte) ([]byte, error) {

	// Initialize the HPKE context
	suite, err := hpke.AssembleCipherSuite(hpke.DHKEM_P256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128)
	if err != nil {
		return nil, fmt.Errorf("error assembling cipher suite: %v", err)
	}

	// Deserialize the recipient's private key
	skR, err := suite.KEM.DeserializePrivateKey(recipientPrivKey)
	if err != nil {
		return nil, fmt.Errorf("error deserializing private key: %v", err)
	}

	// Setup the HPKE receiver context using SetupBaseR
	ctxR, err := hpke.SetupBaseR(suite, skR, claims.Params.PkEM, info)
	if err != nil {
		return nil, fmt.Errorf("error setting up receiver context: %v", err)
	}

	plainText, err := ctxR.Open(nil, claims.Data) // No associated data
	if err != nil {
		return nil, fmt.Errorf("error decrypting ciphertext: %v", err)
	}

	// Print or process the decrypted plaintext as needed
	fmt.Printf("Decrypted text: %s\n", base64.URLEncoding.EncodeToString(plainText))

	return plainText, nil
}
