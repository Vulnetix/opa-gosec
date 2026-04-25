# SPDX-License-Identifier: Apache-2.0
# Detect HTTP handlers that use context.Background() instead of request context.

package vulnetix.rules.gosec_g118

import rego.v1

metadata := {
	"id": "GOSEC-G118",
	"name": "Context propagation failure",
	"description": "context.Background() is used inside what appears to be an HTTP handler or goroutine context where the request's context (r.Context()) should be propagated instead. This prevents proper cancellation and deadline propagation.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/context.go",
	"languages": ["go"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [400],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "context", "http"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	content := input.file_contents[path]
	# File has HTTP handler signatures
	contains(content, "http.ResponseWriter")
	contains(content, "*http.Request")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "context.Background()")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "context.Background() used in HTTP handler — use r.Context() to propagate request cancellation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
