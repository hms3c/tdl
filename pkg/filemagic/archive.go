package filemagic

// Archive signature-based identification, embedded at build time.
// Optimized for simple prefix/offset checks on small header buffers.
//
// If you need to extend this list, add entries here and rebuild.

type Signature struct {
	Bytes  []byte
	Offset int // default 0
}

type ArchiveKind struct {
	Type        string
	Description string
	Extensions  []string
	Signatures  []Signature
}

var ArchiveSignatures = []ArchiveKind{
	{
		Type:        "ZIP",
		Description: "ZIP Archive",
		Extensions:  []string{".zip", ".jar", ".apk", ".docx", ".xlsx"},
		Signatures: []Signature{
			{Bytes: []byte{'P', 'K', 0x03, 0x04}}, // Local file header
			{Bytes: []byte{'P', 'K', 0x05, 0x06}}, // Empty archive
			{Bytes: []byte{'P', 'K', 0x07, 0x08}}, // Spanned archive
		},
	},
	{
		Type:        "RAR",
		Description: "RAR Archive",
		Extensions:  []string{".rar"},
		Signatures: []Signature{
			{Bytes: []byte{'R', 'a', 'r', '!', 0x1A, 0x07, 0x00}},       // RAR 1.5+
			{Bytes: []byte{'R', 'a', 'r', '!', 0x1A, 0x07, 0x01, 0x00}}, // RAR 5.0+
		},
	},
	{
		Type:        "7Z",
		Description: "7-Zip Archive",
		Extensions:  []string{".7z"},
		Signatures: []Signature{
			{Bytes: []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}},
		},
	},
	{
		Type:        "GZIP",
		Description: "GZIP Compressed",
		Extensions:  []string{".gz", ".tgz"},
		Signatures: []Signature{
			{Bytes: []byte{0x1F, 0x8B, 0x08}},
		},
	},
	{
		Type:        "TAR",
		Description: "TAR Archive",
		Extensions:  []string{".tar"},
		Signatures: []Signature{
			{Bytes: []byte{'u', 's', 't', 'a', 'r', 0x00}, Offset: 257},
			{Bytes: []byte{'u', 's', 't', 'a', 'r', 0x20, 0x20, 0x00}, Offset: 257},
		},
	},
}

type Match struct {
	Type        string
	Description string
	Extensions  []string
	Signature   []byte
	Offset      int
}

// Identify tries to match the given header bytes against known archive signatures.
// Returns (match, true) if a known type is detected.
func Identify(header []byte) (Match, bool) {
	for _, kind := range ArchiveSignatures {
		for _, sig := range kind.Signatures {
			off := sig.Offset
			if off < 0 {
				off = 0
			}
			end := off + len(sig.Bytes)
			if end > len(header) {
				continue
			}
			ok := true
			for i := 0; i < len(sig.Bytes); i++ {
				if header[off+i] != sig.Bytes[i] {
					ok = false
					break
				}
			}
			if ok {
				return Match{
					Type:        kind.Type,
					Description: kind.Description,
					Extensions:  kind.Extensions,
					Signature:   sig.Bytes,
					Offset:      off,
				}, true
			}
		}
	}
	return Match{}, false
}
