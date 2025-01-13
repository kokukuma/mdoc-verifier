package openid4vp

import (
	"crypto/ecdsa"
	"fmt"
	"net/url"

	"github.com/dgrijalva/jwt-go"
	"github.com/kokukuma/mdoc-verifier/internal/cryptoroot"
)

type JWTSecuredAuthorizeRequest struct {
	AuthorizeEndpoint string
	ClientID          string `json:"client_id"`
	RequestURI        string `json:"request_uri"`
}

func (a *JWTSecuredAuthorizeRequest) String() string {
	return fmt.Sprintf(
		"%s?client_id=%s&request_uri=%s",
		a.AuthorizeEndpoint, a.ClientID, url.QueryEscape(a.RequestURI))
}

type RequestObject struct {
	AuthorizationRequest
	jwt.StandardClaims
}

func (c *RequestObject) Sign(sigKey *ecdsa.PrivateKey, certChain []string) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	token.Header["x5c"] = certChain
	token.Header["typ"] = "oauth-authz-req+jwt"
	token.Header["kid"] = cryptoroot.CalcKID(&sigKey.PublicKey, "sha256")

	return token.SignedString(sigKey)
}
