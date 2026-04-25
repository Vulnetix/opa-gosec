# SPDX-License-Identifier: Apache-2.0
# Detect use of weak symmetric cipher algorithms (DES, 3DES, RC4).

package vulnetix.rules.gosec_g405

import rego.v1

metadata := {
	"id": "GOSEC-G405",
	"name": "Use of weak cipher algorithm (DES/3DES/RC4)",
	"description": "DES, Triple-DES (3DES), or RC4 cipher functions are used. These algorithms are cryptographically weak and should be replaced with AES-GCM or ChaCha20-Poly1305.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/crypto.go",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "cryptography", "cipher"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(des\.(NewCipher|NewTripleDESCipher)|rc4\.NewCipher)\s*\(`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Weak cipher algorithm (DES/3DES/RC4) — use AES-GCM or ChaCha20-Poly1305 instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
