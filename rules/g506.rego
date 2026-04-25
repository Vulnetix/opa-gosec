# SPDX-License-Identifier: Apache-2.0
# Detect import of golang.org/x/crypto/md4.

package vulnetix.rules.gosec_g506

import rego.v1

metadata := {
	"id": "GOSEC-G506",
	"name": "Import of golang.org/x/crypto/md4",
	"description": "The golang.org/x/crypto/md4 package is imported. MD4 is cryptographically broken with practical collision attacks. Use SHA-256 or stronger.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/blocklist.go",
	"languages": ["go"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "cryptography", "hashing", "import-blocklist"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "golang.org/x/crypto/md4")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Import of golang.org/x/crypto/md4 — MD4 is cryptographically broken; use SHA-256 or stronger",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
