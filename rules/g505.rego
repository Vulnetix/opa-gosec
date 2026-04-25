# SPDX-License-Identifier: Apache-2.0
# Detect import of crypto/sha1.

package vulnetix.rules.gosec_g505

import rego.v1

metadata := {
	"id": "GOSEC-G505",
	"name": "Import of crypto/sha1",
	"description": "The crypto/sha1 package is imported. SHA-1 has known collision vulnerabilities (SHAttered attack) and is deprecated for security-sensitive use. Use crypto/sha256 or crypto/sha512.",
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
	contains(line, `"crypto/sha1"`)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Import of crypto/sha1 — SHA-1 is deprecated for security use; use crypto/sha256 or crypto/sha512",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
