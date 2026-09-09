package passwordauth

import (
	"errors"
	"testing"
)

func TestTranslateErrorPassesThroughUnclassifiedErrors(t *testing.T) {
	source := errors.New("unclassified")
	if got := translateError(source); !errors.Is(got, source) {
		t.Fatalf("translated error = %v", got)
	}
}
