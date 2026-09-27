//go:build ignore

package main

import (
	"context"
	"encoding/base64"
	"fmt"

	password "github.com/faustbrian/go-password/v2"
	"golang.org/x/crypto/argon2"
)

func main() {
	parameters := password.DefaultPolicy().Argon2idParameters()
	salt := []byte("aaaaaaaaaaaaaaaa")
	digest := argon2.IDKey([]byte("synthetic password"), salt, parameters.Time, parameters.MemoryKiB, parameters.Parallelism, parameters.OutputLength)
	argonHash := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		parameters.Version,
		parameters.MemoryKiB,
		parameters.Time,
		parameters.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	)
	limits := password.DefaultPolicy().Limits()
	bcryptPolicy, err := password.NewPolicy(password.PolicyConfig{Algorithm: password.Bcrypt, BcryptCost: 10, Limits: limits})
	if err != nil {
		panic(err)
	}
	bcryptService, err := password.New(bcryptPolicy)
	if err != nil {
		panic(err)
	}
	bcryptHash, err := bcryptService.Hash(context.Background(), []byte("synthetic password"))
	if err != nil {
		panic(err)
	}
	fmt.Println(argonHash)
	fmt.Println(bcryptHash.String())
}
