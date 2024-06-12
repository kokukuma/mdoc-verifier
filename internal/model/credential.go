package model

import "github.com/go-webauthn/webauthn/webauthn"

type Credential struct {
	Transport []string
	webauthn.Credential
}
