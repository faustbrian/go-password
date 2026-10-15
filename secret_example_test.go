package password_test

import (
	"context"
	"fmt"

	password "github.com/faustbrian/go-password/v2"
)

func ExampleNewSecret() {
	secret, err := password.NewSecret([]byte("synthetic example password"))
	if err != nil {
		panic("invalid example input")
	}
	defer secret.Destroy()
	parameters, err := password.NewParameters(password.Parameters{Algorithm: password.Bcrypt, BcryptCost: 4})
	if err != nil {
		panic("invalid example parameters")
	}
	policy, err := password.NewPolicy(password.PolicyConfig{Algorithm: parameters.Algorithm, BcryptCost: parameters.BcryptCost, Limits: password.DefaultPolicy().Limits()})
	if err != nil {
		panic("invalid example policy")
	}
	service, err := password.New(policy)
	if err != nil {
		panic("invalid example service")
	}
	err = secret.Use(func(borrow []byte) error {
		hash, err := service.Hash(context.Background(), borrow)
		if err != nil {
			return err
		}
		result, err := service.Verify(context.Background(), borrow, hash.String())
		if err == nil {
			fmt.Println(result.Match())
		}
		return err
	})
	if err != nil {
		panic("example operation failed")
	}
	secret.Destroy()
	fmt.Println(secret.Len())
	// Output:
	// true
	// 0
}
