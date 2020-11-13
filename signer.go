package go_auth

import (
	"github.com/dgrijalva/jwt-go"
	"time"
)

type Signer struct {
	store  KeyStore
	policy *Policy
}

func (signer Signer) Sign(id string, c interface{}) (string, error) {
	t := jwt.New(jwt.GetSigningMethod(signer.store.GetAlgorithm()))

	key, err := signer.store.GetKey(signer.policy.issuer)
	if err != nil {
		return "", err
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		return "", err
	}

	context, err := toJSON(c)
	if err != nil {
		return "", err
	}

	t.Claims = &TokenClaims{
		Context: context,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(signer.policy.expiresIn).Unix(),
			Issuer:    signer.policy.issuer,
			Subject:   signer.policy.subject,
			Audience:  signer.policy.audience,
			Id:        id,
		},
	}

	return t.SignedString(signKey)
}
