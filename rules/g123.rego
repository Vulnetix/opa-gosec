# SPDX-License-Identifier: Apache-2.0
# Detect TLS session ticket key reuse via hardcoded SessionTicketKey.

package vulnetix.rules.gosec_g123

import rego.v1

metadata := {
	"id": "GOSEC-G123",
	"name": "TLS session ticket key reuse",
	"description": "tls.Config is initialized with a hardcoded SessionTicketKey. Reusing the same session ticket key across restarts or instances breaks forward secrecy for resumed TLS sessions.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/tls_config.go",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [295],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "tls", "cryptography"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "SessionTicketKey")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "tls.Config.SessionTicketKey is set — hardcoded or reused keys break forward secrecy",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
