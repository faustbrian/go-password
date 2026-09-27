package password

import (
	"fmt"
	"strings"
	"testing"
)

type deliverySensitiveCause struct{ Detail string }

func (deliverySensitiveCause) Error() string { return "synthetic sensitive detail" }

func TestDeliveryClassifiedErrorRedactsCompositeCause(t *testing.T) {
	err := newError(ErrEntropy, "hash", deliverySensitiveCause{Detail: "synthetic sensitive detail"})
	if strings.Contains(fmt.Sprintf("%#v", err), "synthetic sensitive detail") {
		t.Fatal("Go-syntax error formatting exposed cause fields")
	}
}
