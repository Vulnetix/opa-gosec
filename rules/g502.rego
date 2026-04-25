# SPDX-License-Identifier: Apache-2.0
# Detect import of crypto/des.

package vulnetix.rules.gosec_g502

import rego.v1

metadata := {
	"id": "GOSEC-G502",
	"name": "Import of crypto/des",
	"description": "The crypto/des package is imported. DES and 3DES are considered insecure due to short key lengths and known cryptanalytic attacks. Use AES-GCM or ChaCha20-Poly1305.",
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
	contains(line, `"crypto/des"`)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Import of crypto/des — DES/3DES is insecure; use AES-GCM or ChaCha20-Poly1305",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
