# SPDX-License-Identifier: Apache-2.0
# Detect import of crypto/rc4.

package vulnetix.rules.gosec_g503

import rego.v1

metadata := {
	"id": "GOSEC-G503",
	"name": "Import of crypto/rc4",
	"description": "The crypto/rc4 package is imported. RC4 has serious cryptographic weaknesses including key biases and is prohibited in TLS since RFC 7465. Use AES-GCM or ChaCha20-Poly1305.",
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
	"tags": ["go", "gosec", "cryptography", "cipher", "import-blocklist"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, `"crypto/rc4"`)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Import of crypto/rc4 — RC4 is cryptographically broken; use AES-GCM or ChaCha20-Poly1305",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
