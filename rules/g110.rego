# SPDX-License-Identifier: Apache-2.0
# Detect potential decompression bomb via unbounded io.Copy with decompressor.

package vulnetix.rules.gosec_g110

import rego.v1

metadata := {
	"id": "GOSEC-G110",
	"name": "Decompression bomb via io.Copy",
	"description": "io.Copy is used with a decompressor (gzip, zlib, flate, lzw, etc.) without limiting the output size. A malicious compressed input could expand to exhaust memory or disk (decompression bomb).",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/decompression-bomb.go",
	"languages": ["go"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [409],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "decompression", "dos"],
}

decompressor_imports := {
	`"compress/gzip"`,
	`"compress/zlib"`,
	`"compress/flate"`,
	`"compress/lzw"`,
	`"compress/bzip2"`,
	`"archive/zip"`,
	`"archive/tar"`,
}

file_uses_decompressor(content) if {
	some imp in decompressor_imports
	contains(content, imp)
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	content := input.file_contents[path]
	file_uses_decompressor(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "io.Copy(")
	not contains(line, "io.LimitReader")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "io.Copy with decompressor — wrap the reader with io.LimitReader to prevent decompression bombs",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
