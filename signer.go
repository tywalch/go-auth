package go_auth

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Signer struct {
	store  KeyStore
	policy *Policy
}

func (signer Signer) sign(id string, claims Claims) (string, error) {
	t := jwt.New(jwt.GetSigningMethod(signer.store.GetAlgorithm()))

	key, err := signer.store.GetKey(signer.policy.issuer)
	if err != nil {
		return "", err
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		return "", err
	}

	t.Claims = &jwt.MapClaims{
		"jti": id,
		"ctx": claims,
		"iss": signer.policy.issuer,
		"sub": signer.policy.subject,
		"aud": signer.policy.audience,
		"exp": time.Now().Add(signer.policy.expiresIn).Unix(),
	}

	return t.SignedString(signKey)
}
