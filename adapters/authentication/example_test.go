package passwordauthentication_test

import (
	"context"
	"fmt"

	password "github.com/faustbrian/go-password"
	passwordauthentication "github.com/faustbrian/go-password/adapters/authentication"
)

type exampleLookup struct{ hash string }

func (lookup exampleLookup) LookupPassword(context.Context, string) (passwordauthentication.Record, bool, error) {
	return passwordauthentication.Record{Subject: "user-123", EncodedHash: lookup.hash}, true, nil
}

func ExampleAuthenticator() {
	limits := password.DefaultPolicy().Limits()
	bcryptPolicy, err := password.NewPolicy(password.PolicyConfig{Algorithm: password.Bcrypt, BcryptCost: 4, Limits: limits})
	if err != nil {
		panic(err)
	}
	bcryptPasswords, err := password.New(bcryptPolicy)
	if err != nil {
		panic(err)
	}
	current, err := bcryptPasswords.Hash(context.Background(), []byte("synthetic example password"))
	if err != nil {
		panic(err)
	}
	dummy, err := bcryptPasswords.Hash(context.Background(), []byte("synthetic dummy password"))
	if err != nil {
		panic(err)
	}
	passwords, err := password.New(password.DefaultPolicy())
	if err != nil {
		panic(err)
	}
	authenticator, err := passwordauthentication.New(passwordauthentication.Config{
		Passwords: passwords,
		Lookup:    exampleLookup{hash: current.String()},
		DummyHash: dummy.String(),
	})
	if err != nil {
		panic(err)
	}
	result, err := authenticator.Authenticate(context.Background(), "user", []byte("synthetic example password"))
	fmt.Println(err == nil, result.Subject(), result.Upgrade().Required())
	// Output: true user-123 true
}
