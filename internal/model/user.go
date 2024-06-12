package model

import (
	"encoding/base64"
	"errors"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/ory/go-convenience/stringslice"
)

type Users struct {
	mu    sync.RWMutex
	users map[string]*User
}

func (u *Users) GetUserByID(userID string) (*User, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	for _, user := range u.users {
		if user.id == userID {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

func (u *Users) GetUser(name string) (*User, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	user, ok := u.users[name]
	if !ok {
		return nil, errors.New("user not found")
	}
	return user, nil
}

func (u *Users) AddUser(name, displayName string) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	id, err := uuid.NewUUID()
	if err != nil {
		return err
	}
	u.users[name] = &User{
		id:          id.String(),
		name:        name,
		displayName: displayName,
	}
	return nil
}

func NewUsers() *Users {
	return &Users{
		users: make(map[string]*User),
	}
}

type User struct {
	id          string
	name        string
	displayName string
	keys        []Key
}

type Key struct {
	Name            string `json:"name"`
	ID              string `json:"id"`
	AttestationType string `json:"attestation_type"`
	AAGUID          string `json:"aaguid"`
	credential      webauthn.Credential
	DPK             []string
}

var _ webauthn.User = (*User)(nil)

func (u *User) WebAuthnID() []byte {
	return []byte(u.id)
}

func (u *User) WebAuthnName() string {
	return "username:" + u.name
}

func (u *User) WebAuthnDisplayName() string {
	return "display:" + u.displayName
}

func (u *User) WebAuthnIcon() string {
	return "https://pics.com/avatar.png"
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
	var creds []webauthn.Credential
	for _, key := range u.keys {
		creds = append(creds, key.credential)
	}
	return creds
}

func (u *User) CredentialExcludeList() []protocol.CredentialDescriptor {

	credentialExcludeList := []protocol.CredentialDescriptor{}
	for _, key := range u.keys {
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: key.credential.ID,
			Transport:    key.credential.Transport,
		}
		credentialExcludeList = append(credentialExcludeList, descriptor)
	}

	return credentialExcludeList
}

func (u *User) AddCredential(cred webauthn.Credential, name string, pdpk *ParsedAttObjForDevicePublicKey) error {
	uuid, err := uuid.FromBytes(cred.Authenticator.AAGUID)
	if err != nil {
		return err
	}

	var dpk string
	if pdpk != nil {
		dpk = base64.RawURLEncoding.EncodeToString(pdpk.DPK)
	}

	u.keys = append(u.keys, Key{
		Name:            name,
		ID:              base64.RawURLEncoding.EncodeToString(cred.ID),
		AttestationType: cred.AttestationType,
		AAGUID:          uuid.String(),
		credential:      cred,
		DPK:             []string{dpk},
	})
	return nil
}

func (u *User) AddDPK(cred webauthn.Credential, pdpk *ParsedAttObjForDevicePublicKey) error {
	// iOS does not support dpk
	if pdpk == nil {
		return nil
	}
	credID := base64.RawURLEncoding.EncodeToString(cred.ID)
	for i, key := range u.keys {
		if key.ID == credID {
			dpk := base64.RawURLEncoding.EncodeToString(pdpk.DPK)
			if stringslice.Has(key.DPK, dpk) {
				return nil
			}
			u.keys[i].DPK = append(key.DPK, dpk)
			return nil
		}
	}
	return errors.New("the credential not found")
}

func (u *User) Keys() []Key {
	return u.keys
}
