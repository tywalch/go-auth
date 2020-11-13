package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
	"log"
	"time"
)

type ParameterStore struct {
	ssm       *ssm.SSM
	keyType   string
	algorithm string
}

func (store ParameterStore) GetAlgorithm() string {
	return store.algorithm
}

func (store ParameterStore) GetKey(name string) ([]byte, error) {
	keyName := store.formatKeyName(name)
	config := &ssm.GetParameterInput{
		Name:           aws.String(keyName),
		WithDecryption: aws.Bool(true),
	}
	param, err := store.ssm.GetParameter(config)
	if err != nil {
		//if aerr, ok := err.(awserr.Error); ok && aerr.Code() == ssm.ErrCodeParameterNotFound {
		//	return []byte(""), nil
		//}
		return []byte(""), err
	}
	return []byte(*param.Parameter.Value), nil
}

func (store ParameterStore) formatKeyName(name string) string {
	return fmt.Sprintf("jwt_%s_%s", store.keyType, name)
}

func NewParameterStore(algorithm string, keyType string) *ParameterStore {
	session := session.Must(session.NewSession())
	svc := ssm.New(session, aws.NewConfig().WithRegion("us-east-1"))
	return &ParameterStore{
		ssm:       svc,
		keyType:   keyType,
		algorithm: algorithm,
	}
}

type Person struct {
	Name    string   `json:"name"`
	Age     int      `json:"age"`
	Hobbies []string `json:"hobbies"`
}

func main() {
	signerStore := NewParameterStore("RS256", "private")
	verifierStore := NewParameterStore("RS256", "public")
	timeout := time.Hour

	policy := &Policy{"ssmkey", "local", "testing", timeout}
	policies := make(Policies, 1)
	policies[0] = policy

	hobbies := []string{"Cycling", "Cheese", "Techno"}
	session := Person{
		Name:    "George > Michael",
		Age:     40,
		Hobbies: hobbies,
	}

	signer := Signer{*signerStore, policy}
	verifier := Verifier{*verifierStore, policies}

	signedJWT, err := signer.Sign("1234", session)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("signed", signedJWT)

	p := Person{}
	token, err := verifier.Verify(signedJWT, &p)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(token.Id, token.Policy)
	fmt.Println("%+v\n", p.Name)
}
