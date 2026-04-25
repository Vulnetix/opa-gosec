# SPDX-License-Identifier: Apache-2.0
# Detect use of the insecure math/rand package for security-sensitive randomness.

package vulnetix.rules.gosec_g404

import rego.v1

metadata := {
	"id": "GOSEC-G404",
	"name": "Use of weak/insecure PRNG (math/rand)",
	"description": "math/rand is used for generating random numbers. The math/rand package is not cryptographically secure and must not be used for security-sensitive purposes such as token generation, nonces, or key material. Use crypto/rand instead.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/rand.go",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [338],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "cryptography", "randomness"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, `"math/rand"`)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Import of math/rand — use crypto/rand for security-sensitive random number generation",
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
	regex.match(`rand\.(New|Intn|Int63|Float64|Seed)\s*\(`, line)
	# Ensure it's not crypto/rand (which uses .Read, not .Intn etc.)
	not contains(line, "crypto/rand")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "math/rand function used — use crypto/rand for security-sensitive random number generation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
