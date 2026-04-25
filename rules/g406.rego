# SPDX-License-Identifier: Apache-2.0
# Detect use of deprecated or weak hash functions MD4 and RIPEMD160.

package vulnetix.rules.gosec_g406

import rego.v1

metadata := {
	"id": "GOSEC-G406",
	"name": "Use of deprecated/weak hash (MD4 or RIPEMD160)",
	"description": "MD4 or RIPEMD160 hash functions from golang.org/x/crypto are used. These algorithms have known weaknesses and are not recommended for new security-sensitive applications. Use SHA-256 or SHA-3.",
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
	regex.match(`(md4\.New|ripemd160\.New)\s*\(`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Use of MD4 or RIPEMD160 hash — use SHA-256 or stronger for security-sensitive operations",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
