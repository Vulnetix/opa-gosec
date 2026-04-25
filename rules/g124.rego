# SPDX-License-Identifier: Apache-2.0
# Detect cookies set without Secure or HttpOnly flags.

package vulnetix.rules.gosec_g124

import rego.v1

metadata := {
	"id": "GOSEC-G124",
	"name": "Insecure cookie — missing Secure or HttpOnly flags",
	"description": "An HTTP cookie is created without setting the Secure and/or HttpOnly flags. Missing Secure allows the cookie to be transmitted over plain HTTP; missing HttpOnly exposes it to JavaScript access.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/cookie.go",
	"languages": ["go"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [614],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "cookie", "http"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	content := input.file_contents[path]
	contains(content, "http.Cookie{")
	# File uses Cookie but doesn't set Secure: true
	not contains(content, "Secure: true")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "http.Cookie{")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "http.Cookie created without Secure: true — cookie may be sent over unencrypted connections",
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
	content := input.file_contents[path]
	contains(content, "http.Cookie{")
	# File uses Cookie but doesn't set HttpOnly: true
	not contains(content, "HttpOnly: true")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "http.Cookie{")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "http.Cookie created without HttpOnly: true — cookie is accessible to JavaScript",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
