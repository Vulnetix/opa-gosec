# SPDX-License-Identifier: Apache-2.0
# Detect RSA key generation with a key size smaller than 2048 bits.

package vulnetix.rules.gosec_g403

import rego.v1

metadata := {
	"id": "GOSEC-G403",
	"name": "Weak RSA key length (< 2048 bits)",
	"description": "rsa.GenerateKey is called with a key size smaller than 2048 bits. Keys smaller than 2048 bits are considered weak and may be factored with sufficient computing resources.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/rsa.go",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [310],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "cryptography", "rsa"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "rsa.GenerateKey(")
	# Match key sizes less than 2048: 512, 1024, 1536 as explicit literals
	regex.match(`rsa\.GenerateKey\s*\([^,]+,\s*(512|768|1024|1280|1536|1792)\s*\)`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "RSA key size is less than 2048 bits — use 2048 or 4096 bits for adequate security",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
