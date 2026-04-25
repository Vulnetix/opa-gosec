# SPDX-License-Identifier: Apache-2.0
# Detect HTTP request smuggling via conflicting Transfer-Encoding and Content-Length headers.

package vulnetix.rules.gosec_g113

import rego.v1

metadata := {
	"id": "GOSEC-G113",
	"name": "HTTP request smuggling via conflicting headers",
	"description": "Setting both Transfer-Encoding and Content-Length headers on an HTTP response enables request smuggling attacks. Intermediaries may interpret message boundaries differently, allowing an attacker to poison shared connection pools.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/http_smuggling.go",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [444],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "http", "request-smuggling"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	content := input.file_contents[path]
	# Both conflicting headers are set in the same file
	contains(content, "Transfer-Encoding")
	contains(content, "Content-Length")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "Transfer-Encoding")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Both Transfer-Encoding and Content-Length headers set — conflicting headers enable HTTP request smuggling",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
