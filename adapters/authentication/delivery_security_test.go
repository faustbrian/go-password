package passwordauthentication_test

import (
	"errors"
	"testing"

	password "github.com/faustbrian/go-password/v2"
	passwordauthentication "github.com/faustbrian/go-password/v2/adapters/authentication"
	"github.com/faustbrian/go-password/v2/passwordtest"
)

func TestDeliveryRejectsCrossAlgorithmDummy(t *testing.T) {
	service, err := password.New(password.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	_, err = passwordauthentication.New(passwordauthentication.Config{
		Passwords: service, Lookup: missingLookup{}, DummyHash: passwordtest.LaravelBcrypt,
	})
	if !errors.Is(err, passwordauthentication.ErrInvalidConfig) {
		t.Fatalf("cross-algorithm dummy accepted: %v", err)
	}
}
