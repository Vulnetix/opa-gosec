# SPDX-License-Identifier: Apache-2.0
# Detect unsafe redirect policies that propagate sensitive headers across origins.

package vulnetix.rules.gosec_g119

import rego.v1

metadata := {
	"id": "GOSEC-G119",
	"name": "Unsafe redirect policy propagates sensitive headers",
	"description": "The http.Client CheckRedirect function copies all headers from a previous request to the redirected request, including Authorization and Cookie headers. This leaks credentials to the redirect target if it is on a different origin.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/redirect_policy.go",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [601],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "redirect", "http", "header-leakage"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	# CheckRedirect callback that copies all headers from previous request via the via slice
	regex.match(`req\.Header\s*=\s*via\[`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "CheckRedirect copies all headers from previous request — sensitive headers (Authorization, Cookie) leak to redirect targets on other origins",
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
