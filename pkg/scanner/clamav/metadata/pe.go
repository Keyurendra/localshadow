package metadata

import (
	"debug/pe"
	"fmt"
	"strings"
)

func parsePE(f *pe.File) *ExecutableMetadata {
	meta := &ExecutableMetadata{
		Format: ExecutableFormatPE,
		Arch:   fmt.Sprintf("%d", f.Machine),
	}

	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		meta.Entrypoint = uint64(oh.AddressOfEntryPoint)
	case *pe.OptionalHeader64:
		meta.Entrypoint = uint64(oh.AddressOfEntryPoint)
	}

	for _, sec := range f.Sections {
		meta.Sections = append(meta.Sections, SectionMeta{
			Name:  strings.Trim(sec.Name, "\x00"),
			Size:  uint64(sec.Size),
			Flags: fmt.Sprintf("0x%X", sec.Characteristics),
		})
	}

	if syms, err := f.ImportedSymbols(); err == nil {
		meta.Imports = syms
	}

	return meta
}
