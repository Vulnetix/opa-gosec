# SPDX-License-Identifier: Apache-2.0
# Detect use of ssh.InsecureIgnoreHostKey which disables SSH host verification.

package vulnetix.rules.gosec_g106

import rego.v1

metadata := {
	"id": "GOSEC-G106",
	"name": "SSH InsecureIgnoreHostKey",
	"description": "ssh.InsecureIgnoreHostKey disables host key verification for SSH connections, making the connection vulnerable to man-in-the-middle attacks.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/ssh.go",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [322],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "ssh", "cryptography"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "InsecureIgnoreHostKey")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "ssh.InsecureIgnoreHostKey disables host key verification, enabling MITM attacks",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
