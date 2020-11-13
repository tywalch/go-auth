package main

import (
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
)

func toJSON(v interface{}) (string, error) {
	jsonByteData, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	jsonStringData := string(jsonByteData)
	return jsonStringData, nil
}

func fromJSON(data string, v interface{}) error {
	return json.Unmarshal([]byte(data), v)
}

type TokenClaims struct {
	Context string `json:"ctx"`
	jwt.StandardClaims
}
