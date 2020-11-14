package gothic

import (
	"github.com/dgrijalva/jwt-go"
	"time"
)

type Signer struct {
	Store  KeyStore
	Policy *Policy
}

func (signer Signer) Sign(id string, c interface{}) (string, error) {
	t := jwt.New(jwt.GetSigningMethod(signer.Store.GetAlgorithm()))

	key, err := signer.Store.GetKey(signer.Policy.Issuer)
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
			ExpiresAt: time.Now().Add(signer.Policy.ExpiresIn).Unix(),
			Issuer:    signer.Policy.Issuer,
			Subject:   signer.Policy.Subject,
			Audience:  signer.Policy.Audience,
			Id:        id,
		},
	}

	return t.SignedString(signKey)
}
