package metadata

import (
	"debug/elf"
	"debug/pe"
	"fmt"
	"os"

	"github.com/h2non/filetype"
)

type Metadata struct {
	Filesize   int64               `json:"filesize"`
	Mimetype   string              `json:"mimetype"`
	Extension  string              `json:"extension"`
	Executable *ExecutableMetadata `json:"executable,omitempty"`
}

type ExecutableMetadata struct {
	Format     ExecutableFormat `json:"format"`
	Arch       string           `json:"arch"`
	Entrypoint uint64           `json:"entrypoint"`
	Sections   []SectionMeta    `json:"sections,omitempty"`
	Imports    []string         `json:"imports,omitempty"`
	Symbols    []string         `json:"symbols,omitempty"`
}

type ExecutableFormat string

const (
	ExecutableFormatELF = "ELF"
	ExecutableFormatPE  = "PE"
)

type SectionMeta struct {
	Name  string `json:"name"`
	Size  uint64 `json:"size"`
	Flags string `json:"flags"`
}

func Collect(f *os.File) (*Metadata, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("given file is a directory")
	}

	typ, err := filetype.MatchReader(f)
	if err != nil {
		return nil, fmt.Errorf("reading MIME type: %w", err)
	}

	metadata := Metadata{
		Filesize:  info.Size(),
		Mimetype:  typ.MIME.Value,
		Extension: typ.Extension,
	}

	switch typ.MIME.Value {
	case "application/x-executable":
		if elfFile, err := elf.NewFile(f); err == nil {
			metadata.Executable = parseELF(elfFile)
		}
	case "application/vnd.microsoft.portable-executable":
		if peFile, err := pe.NewFile(f); err == nil {
			metadata.Executable = parsePE(peFile)
		}
	}

	return &metadata, nil
}
