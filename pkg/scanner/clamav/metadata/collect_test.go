package metadata_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/accuknox/omniscan/pkg/scanner/clamav/metadata"

	"github.com/stretchr/testify/assert"
)

func TestELF(t *testing.T) {
	a := assert.New(t)

	f := openTestELFFile(t)
	if f == nil {
		return
	}
	defer f.Close()

	meta, err := metadata.Collect(f)
	if a.NoError(err) && a.Equal("elf", meta.Extension) {
		toJSON(t, meta)
	}
}

func TestPE(t *testing.T) {
	a := assert.New(t)

	f := openTestPEFile(t)
	if f == nil {
		return
	}
	defer f.Close()

	meta, err := metadata.Collect(f)
	if a.NoError(err) && a.Equal("pe", meta.Extension) {
		toJSON(t, meta)
	}
}

func TestUnknown(t *testing.T) {
	a := assert.New(t)

	f := openTestNotExecutableFile(t)
	if f == nil {
		return
	}
	defer f.Close()

	meta, err := metadata.Collect(f)
	if a.NoError(err) {
		toJSON(t, meta)
	}
}

func openTestELFFile(t *testing.T) *os.File {
	t.Helper()

	path := os.Getenv("POSTSCAN_TEST_ELF_FILE")
	if path == "" {
		t.Skip("POSTSCAN_TEST_ELF_FILE env variable not set...Skipping")
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open test file: %v", err)
	}

	return f
}

func openTestPEFile(t *testing.T) *os.File {
	t.Helper()

	path := os.Getenv("POSTSCAN_TEST_PE_FILE")
	if path == "" {
		t.Skip("POSTSCAN_TEST_PE_FILE env variable not set...Skipping")
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open test file: %v", err)
	}

	return f
}

func openTestNotExecutableFile(t *testing.T) *os.File {
	t.Helper()

	path := os.Getenv("POSTSCAN_TEST_NOT_EXECUTABLE_FILE")
	if path == "" {
		t.Skip(`POSTSCAN_TEST_UNKNOWN_FILE env variable not set...Skipping`)
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open test file: %v", err)
	}

	return f
}

func toJSON(t *testing.T, m *metadata.Metadata) {
	t.Helper()

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("converting metadata to json: %s", err.Error())
	}

	t.Log(string(out))
}
