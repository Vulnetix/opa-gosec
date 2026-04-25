# SPDX-License-Identifier: Apache-2.0
# Detect use of weak hashing algorithms MD5 or SHA1.

package vulnetix.rules.gosec_g401

import rego.v1

metadata := {
	"id": "GOSEC-G401",
	"name": "Use of weak hashing algorithm (MD5 or SHA1)",
	"description": "MD5 or SHA1 hashing functions are used. Both algorithms are cryptographically broken and should not be used for security-sensitive purposes such as password hashing or data integrity verification. Use SHA-256 or stronger.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/crypto.go",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [328],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "cryptography", "hashing"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(md5\.(New|Sum)|sha1\.(New|Sum))\s*\(`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Use of weak hashing algorithm (MD5/SHA1) — use SHA-256 or SHA-3 for security-sensitive hashing",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
