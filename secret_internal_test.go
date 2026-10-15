package password

import (
	"bytes"
	"testing"
)

func TestSecretDestroyClearsOwnedBackingStorage(t *testing.T) {
	s, err := NewSecret([]byte{1, 255, 0, 42})
	if err != nil {
		t.Fatal("construction failed")
	}
	backing := s.state().bytes
	s.Destroy()
	if !bytes.Equal(backing, make([]byte, len(backing))) {
		t.Error("owned storage was not cleared before release")
	}
	if s.state().bytes != nil {
		t.Error("destroyed owner retained storage")
	}
	s.Destroy()
}
