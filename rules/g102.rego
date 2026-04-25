# SPDX-License-Identifier: Apache-2.0
# Detect binding to all network interfaces (0.0.0.0).

package vulnetix.rules.gosec_g102

import rego.v1

metadata := {
	"id": "GOSEC-G102",
	"name": "Bind to all interfaces",
	"description": "The application binds to all network interfaces (0.0.0.0 or empty host). This exposes the service on all available interfaces, including external ones, which may not be intended.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/bind.go",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [200],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "network"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "0.0.0.0")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Binding to all interfaces via 0.0.0.0",
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
	# net.Listen("tcp", ":PORT") — empty host means all interfaces
	regex.match(`net\.Listen\s*\(\s*"[^"]+"\s*,\s*":[0-9]`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "net.Listen with empty host binds to all interfaces",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
