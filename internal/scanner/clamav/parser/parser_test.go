package parser_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/accuknox/omniscan/internal/scanner/clamav/parser"
)

const log = `
-------------------------------------------------------------------------------

/mnt/win/Users/Administrator/Downloads/theZoo/malware/Binaries/Ransomware.Cerber/cerber.exe: Win.Ransomware.Cerber-6922156-0 FOUND
/mnt/win/Users/Administrator/Downloads/theZoo/malware/Binaries/Ransomware.Cerber/foo.exe: Win.Ransomware.Foo-6922156-0 FOUND
/mnt/win/Users/Administrator/Downloads/theZoo/malware/Binaries/Ransomware.Cerber/bar.exe: OK
ERROR: Can't get file status
Can't get file status: ERROR

----------- SCAN SUMMARY -----------
Known viruses: 8707578
Engine version: 1.4.3
Scanned directories: 1
Scanned files: 5
Infected files: 1
Data scanned: 0.83 MB
Data read: 0.80 MB (ratio 1.04:1)
Time: 23.843 sec (0 m 23 s)
Start Date: 2025:07:09 03:04:34
End Date:   2025:07:09 03:04:57
`

func TestParse(t *testing.T) {
	f := bytes.NewBuffer([]byte(log))
	result, err := parser.New(f).Parse()
	if err != nil {
		t.Error(err.Error())
	}
	output, err := json.MarshalIndent(result, "", `  `)
	if err != nil {
		t.Error("marshaling scan results to json:", err.Error())
	}
	t.Log(string(output))
}
