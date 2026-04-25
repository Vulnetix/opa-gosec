# SPDX-License-Identifier: Apache-2.0
# Detect import of golang.org/x/crypto/ripemd160.

package vulnetix.rules.gosec_g507

import rego.v1

metadata := {
	"id": "GOSEC-G507",
	"name": "Import of golang.org/x/crypto/ripemd160",
	"description": "The golang.org/x/crypto/ripemd160 package is imported. RIPEMD-160 is deprecated for most security-sensitive applications. Use SHA-256 or SHA-3 for new code.",
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
	contains(line, "golang.org/x/crypto/ripemd160")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Import of golang.org/x/crypto/ripemd160 — RIPEMD-160 is deprecated; use SHA-256 or SHA-3",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
