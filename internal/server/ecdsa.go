package server

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// PEM形式で秘密鍵を書き出す関数
func writePEMFile(privateKey *ecdsa.PrivateKey, filename string) error {
	// 秘密鍵をDER形式にエンコード
	derBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return err
	}

	// PEMブロックを作成
	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derBytes,
	}

	// ファイルに書き出す
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, pemBlock)
}

// PEM形式から秘密鍵を読み込む関数
func readPEMFile(filename string) (*ecdsa.PrivateKey, error) {
	// ファイルを読み込む
	pemBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// PEMブロックをデコード
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("PEMブロックが見つかりません")
	}

	// 秘密鍵を解析
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// 証明書をPEM形式で書き出す関数
func writeCertificatePEM(cert *x509.Certificate, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// 証明書をPEM形式から読み込む関数
func readCertificatePEM(filename string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("PEMブロックが見つかりません")
	}

	return x509.ParseCertificate(block.Bytes)
}
