package gothic

import (
	"encoding/json"
	"time"
)

type Session struct {
	Id    string `json:id`
	Token string `json:token`
}

type SessionStore interface {
	Get(string) ([]byte, error)
	Set(string, []byte, time.Duration) error
}

type Sessionizer struct {
	Store  SessionStore
	Secret *string
}

func (s Sessionizer) Serialize(session Session, ttl time.Duration) (string, error) {
	data, err := json.Marshal(session)
	if err != nil {
		return "", err
	}

	privateKey, err := GenerateRandomString(32)
	if err != nil {
		return "", err
	}

	publicKey := Encrypt(privateKey, *s.Secret)
	if err != nil {
		return "", err
	}

	err = s.Store.Set(privateKey, data, ttl)
	if err != nil {
		return "", err
	}

	return publicKey, nil
}

func (s Sessionizer) Deserialize(id string) (Session, error) {
	session := Session{}
	privateKey := Decrypt(id, *s.Secret)

	data, err := s.Store.Get(privateKey)
	if err != nil {
		return session, err
	}

	err = json.Unmarshal(data, &session)
	if err != nil {
		return session, err
	}

	return session, nil
}
