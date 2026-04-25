# SPDX-License-Identifier: Apache-2.0
# Detect hardcoded or zeroed IV/nonce in cipher initialization.

package vulnetix.rules.gosec_g407

import rego.v1

metadata := {
	"id": "GOSEC-G407",
	"name": "Hardcoded IV/nonce",
	"description": "A cipher or HMAC is initialized with a hardcoded or all-zero IV/nonce. Reusing the same IV with the same key breaks cipher security guarantees. Generate a fresh random IV for each encryption operation.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/hardcoded_iv.go",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [1204],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "cryptography", "iv", "nonce"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	# []byte{0, 0, ...} patterns — all-zero IV
	regex.match(`\[\]byte\s*\{\s*0\s*(,\s*0\s*)+\}`, line)
	# Must be used near cipher operations
	content := input.file_contents[path]
	regex.match(`(aes\.|cipher\.|gcm\.|NewCFBEncrypter|NewCFBDecrypter|NewCTR|NewOFB|Seal|Open)\s*\(`, content)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "All-zero byte slice used as IV/nonce — generate a fresh random IV using crypto/rand for each operation",
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
	# make([]byte, N) immediately used as IV without crypto/rand.Read
	contains(line, "make([]byte,")
	content := input.file_contents[path]
	not contains(content, "rand.Read")
	regex.match(`(cipher\.|gcm\.|Seal|Open|NewCFB|NewCTR|NewOFB)\s*\(`, content)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Byte slice allocated for IV/nonce without crypto/rand.Read — fill IV with cryptographically random bytes",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
