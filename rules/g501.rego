# SPDX-License-Identifier: Apache-2.0
# Detect import of crypto/md5.

package vulnetix.rules.gosec_g501

import rego.v1

metadata := {
	"id": "GOSEC-G501",
	"name": "Import of crypto/md5",
	"description": "The crypto/md5 package is imported. MD5 is a cryptographically broken hash algorithm and must not be used for security-sensitive operations. Use crypto/sha256 or crypto/sha512.",
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
	contains(line, `"crypto/md5"`)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Import of crypto/md5 — MD5 is cryptographically broken; use crypto/sha256 or crypto/sha512",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
