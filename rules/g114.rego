# SPDX-License-Identifier: Apache-2.0
# Detect use of net/http serve functions without context or timeout configuration.

package vulnetix.rules.gosec_g114

import rego.v1

metadata := {
	"id": "GOSEC-G114",
	"name": "Use of net/http serve function without timeout",
	"description": "http.ListenAndServe, http.ListenAndServeTLS, or http.Serve are called without a custom http.Server that configures timeouts. This can leave the server vulnerable to resource exhaustion.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/http_serve.go",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [676],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "http", "timeout"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`http\.(ListenAndServe|ListenAndServeTLS|Serve)\s*\(`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "http.ListenAndServe/Serve called — use a custom http.Server with ReadTimeout, WriteTimeout, and IdleTimeout",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
