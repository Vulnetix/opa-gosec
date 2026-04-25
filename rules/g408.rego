# SPDX-License-Identifier: Apache-2.0
# Detect SSH PublicKeyCallback patterns that may skip host verification.

package vulnetix.rules.gosec_g408

import rego.v1

metadata := {
	"id": "GOSEC-G408",
	"name": "SSH PublicKeyCallback may skip host key verification",
	"description": "SSH HostKeyCallback is set to ssh.InsecureIgnoreHostKey or a custom callback that may not properly verify the host key. This can allow man-in-the-middle attacks.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/ssh.go",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [287],
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
	contains(line, "PublicKeyCallback")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "SSH PublicKeyCallback set — ensure callback properly validates host identity",
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
	contains(line, "HostKeyCallback")
	contains(line, "nil")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "SSH HostKeyCallback set to nil disables host key verification — use ssh.FixedHostKey or verify manually",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
