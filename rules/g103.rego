# SPDX-License-Identifier: Apache-2.0
# Detect use of the unsafe package.

package vulnetix.rules.gosec_g103

import rego.v1

metadata := {
	"id": "GOSEC-G103",
	"name": "Use of unsafe block",
	"description": "The unsafe package allows programs to bypass Go's type safety and memory safety guarantees. Use of unsafe can lead to memory corruption, undefined behaviour, and security vulnerabilities.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/unsafe.go",
	"languages": ["go"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [242],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "unsafe"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`"unsafe"`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Import of unsafe package bypasses Go type and memory safety",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "unsafe.Pointer")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Use of unsafe.Pointer bypasses Go type safety",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
