package hash_test

import (
	"bytes"
	"testing"

	"github.com/accuknox/omniscan/internal/scanner/clamscan/hash"
)

func TestCalculate(t *testing.T) {
	buf := bytes.NewBuffer([]byte("foo"))
	hashes, err := hash.Calculate(buf)
	if err != nil {
		t.Error(err.Error())
	}
	t.Logf("md5=%s", hashes.MD5)
	t.Logf("sha1=%s", hashes.SHA1)
	t.Logf("sha256=%s", hashes.SHA256)
	t.Logf("sha512=%s", hashes.SHA512)
}
