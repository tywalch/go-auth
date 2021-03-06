package gothic

import (
	"errors"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

type Verifier struct {
	Store    KeyStore
	Policies []*Policy
}

type Token struct {
	Id     string
	Policy Policy
}

func (v Verifier) MatchPolicy(issuer, audience, subject string) (Policy, bool) {
	for i := 0; i < len(v.Policies); i++ {
		policy := *v.Policies[i]
		if match := issuer == policy.Issuer && audience == policy.Audience && subject == policy.Subject; match {
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

func (v Verifier) Deconstruct(token string) (Token, string, error) {
	claims, err := v.Decode(token)
	if err != nil {
		return Token{}, "", err
	}

	audience := claims["aud"].(string)
	subject := claims["sub"].(string)
	issuer := claims["iss"].(string)
	id := claims["jti"].(string)

	policy, match := v.MatchPolicy(issuer, audience, subject)
	if !match {
		return Token{}, "", errors.New("unknown token does not match known policies")
	}

	return Token{id, policy}, claims["ctx"].(string), nil
}

func (v Verifier) Verify(token string, c interface{}) (Token, error) {
	method := jwt.GetSigningMethod(v.Store.GetAlgorithm())
	parts := strings.Split(token, ".")

	deconstructed, claimJSON, err := v.Deconstruct(token)
	if err != nil {
		return Token{}, err
	}

	keyName, err := v.Store.GetKey(deconstructed.Policy.Issuer)
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

	fromJSON(claimJSON, c)
	return deconstructed, nil
}
