package gothic

import "time"

type Policy struct {
	Issuer    string
	Audience  string
	Subject   string
	ExpiresIn time.Duration
}

type VerificationPolicy struct {
	Issuer    string
	Audience  string
	Subject   string
	ExpiresIn time.Duration
}

type Policies []*Policy

type Claims map[string]interface{}

type KeyStore interface {
	GetAlgorithm() string
	GetKey(string) ([]byte, error)
}
