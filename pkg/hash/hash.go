package hash

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

func Digest(message []byte, alg string) []byte {
	var hasher hash.Hash
	switch alg {
	case "SHA-256":
		hasher = sha256.New()
	// case "SHA-384":
	// 	hasher = sha384.New()
	case "SHA-512":
		hasher = sha512.New()
	}
	hasher.Write(message)
	return hasher.Sum(nil)
}
