package go_auth

import "time"

type Policy struct {
	issuer    string
	audience  string
	subject   string
	expiresIn time.Duration
}

type VerificationPolicy struct {
		issuer    string
		audience  string
		subject   string
		expiresIn time.Duration
}

type Policies []*Policy

type Claims map[string]interface{}

type KeyStore interface {
	GetAlgorithm() string
	GetKey(string) ([]byte, error)
}
