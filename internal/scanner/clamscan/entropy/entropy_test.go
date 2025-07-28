package entropy_test

import (
	"bytes"
	"testing"

	"github.com/accuknox/omniscan/internal/scanner/clamscan/entropy"
)

func TestCalculate(t *testing.T) {
	buf := bytes.NewBuffer([]byte("foo"))
	val, err := entropy.Calculate(buf)
	if err != nil {
		t.Error(err.Error())
	}
	t.Logf("entropy=%.4f", val)
}
