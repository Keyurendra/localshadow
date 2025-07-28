package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
)

type Hashes struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
}

func Calculate(r io.Reader) (*Hashes, error) {
	md5h := md5.New()
	sha1h := sha1.New()
	sha256h := sha256.New()
	sha512h := sha512.New()

	multi := io.MultiWriter(md5h, sha1h, sha256h, sha512h)
	if _, err := io.Copy(multi, r); err != nil {
		return nil, fmt.Errorf("copying to hash functions: %w", err)
	}

	return &Hashes{
		MD5:    hex.EncodeToString(md5h.Sum(nil)),
		SHA1:   hex.EncodeToString(sha1h.Sum(nil)),
		SHA256: hex.EncodeToString(sha256h.Sum(nil)),
		SHA512: hex.EncodeToString(sha512h.Sum(nil)),
	}, nil
}
