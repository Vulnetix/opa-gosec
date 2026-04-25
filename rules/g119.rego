# SPDX-License-Identifier: Apache-2.0
# Detect unsafe HTTP redirects with user-controlled target URLs.

package vulnetix.rules.gosec_g119

import rego.v1

metadata := {
	"id": "GOSEC-G119",
	"name": "Unsafe redirect policy",
	"description": "http.Redirect is called with a URL that appears to come from user input (request parameters, form values, etc.). Open redirects can be abused for phishing attacks.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/redirect.go",
	"languages": ["go"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [200],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "redirect", "http"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "http.Redirect(")
	# URL argument is a variable (contains r. or req. suggesting user input)
	regex.match(`http\.Redirect\s*\([^,]+,\s*[^,]+,\s*(r\.|req\.|request\.)`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "http.Redirect with user-controlled URL — validate against an allowlist to prevent open redirects",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
