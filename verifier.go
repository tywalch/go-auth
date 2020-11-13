package go_auth

import (
	"errors"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

type Verifier struct {
	store    KeyStore
	policies []*Policy
}

type Token struct {
	Id     string
	Policy Policy
	Claims jwt.MapClaims
}

func (v Verifier) MatchPolicy(issuer, audience, subject string) (Policy, bool) {
	for i := 0; i < len(v.policies); i++ {
		policy := *v.policies[i]
		if match := issuer == policy.issuer && audience == policy.audience && subject == policy.subject; match {
			return policy, match
		}
	}
	return Policy{}, false
}

func (v Verifier) Decode(token string) (jwt.MapClaims, error) {
	parser := new(jwt.Parser)

	decoded, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return jwt.MapClaims{}, err
	}

	claims := decoded.Claims.(jwt.MapClaims)

	return claims, nil
}

func (v Verifier) Deconstruct(token string) (Token, error) {
	claims, err := v.Decode(token)
	if err != nil {
		return Token{}, err
	}

	audience := claims["aud"].(string)
	subject := claims["sub"].(string)
	issuer := claims["iss"].(string)
	id := claims["jid"].(string)

	policy, match := v.MatchPolicy(issuer, audience, subject)
	if !match {
		return Token{}, errors.New("unknown token does not match known policies")
	}

	return Token{id, policy, claims["ctx"].(map[string]interface{})}, nil
}

func (v Verifier) Verify(token string) (Token, error) {
	method := jwt.GetSigningMethod(v.store.GetAlgorithm())
	parts := strings.Split(token, ".")

	deconstructed, err := v.Deconstruct(token)
	if err != nil {
		return Token{}, err
	}

	keyName, err := v.store.GetKey(deconstructed.Policy.issuer)
	if err != nil {
		return Token{}, err
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(keyName)
	if err != nil {
		return Token{}, err
	}

	err = method.Verify(strings.Join(parts[0:2], "."), parts[2], key)
	if err != nil {
		return Token{}, err
	}

	return deconstructed, nil
}
