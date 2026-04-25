# SPDX-License-Identifier: Apache-2.0
# Detect permissive CORS configuration allowing all origins.

package vulnetix.rules.gosec_g121

import rego.v1

metadata := {
	"id": "GOSEC-G121",
	"name": "CORS AllowAll or wildcard origin",
	"description": "CORS is configured to allow all origins via AllowAll() or a wildcard (*). This disables the Same-Origin Policy protection for this endpoint, potentially exposing APIs to cross-site request forgery.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/cors.go",
	"languages": ["go"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [346],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "cors", "http"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "AllowAll()")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "CORS AllowAll() permits requests from any origin — restrict to known origins",
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
	regex.match(`AllowOrigins?\s*:.*"\*"`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "CORS configured with wildcard origin '*' — restrict to known origins",
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
	contains(line, `"Access-Control-Allow-Origin"`)
	contains(line, `"*"`)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Access-Control-Allow-Origin set to '*' — restrict to known origins",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
