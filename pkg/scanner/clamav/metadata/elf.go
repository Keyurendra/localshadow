package metadata

import "debug/elf"

func parseELF(f *elf.File) *ExecutableMetadata {
	meta := &ExecutableMetadata{
		Format:     ExecutableFormatELF,
		Arch:       f.Machine.String(),
		Entrypoint: f.Entry,
	}

	for _, sec := range f.Sections {
		meta.Sections = append(meta.Sections, SectionMeta{
			Name:  sec.Name,
			Size:  sec.Size,
			Flags: sec.Flags.String(),
		})
	}

	if libs, err := f.ImportedLibraries(); err == nil {
		meta.Imports = libs
	}

	if syms, err := f.Symbols(); err == nil {
		for _, s := range syms {
			meta.Symbols = append(meta.Symbols, s.Name)
		}
	}

	return meta
}
