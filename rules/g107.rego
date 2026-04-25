# SPDX-License-Identifier: Apache-2.0
# Detect HTTP requests with URLs derived from user-controlled input (SSRF risk).

package vulnetix.rules.gosec_g107

import rego.v1

metadata := {
	"id": "GOSEC-G107",
	"name": "URL provided to HTTP request as taint input",
	"description": "The URL passed to an HTTP client method appears to be derived from user-controlled or external input. This can lead to Server-Side Request Forgery (SSRF) if not validated.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/ssrf.go",
	"languages": ["go"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [88],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "ssrf", "http"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	# http.Get/Post/Head/Do with a variable (not a string literal)
	regex.match(`http\.(Get|Post|Head)\s*\(\s*[^"]`, line)
	not regex.match(`http\.(Get|Post|Head)\s*\(\s*"`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "HTTP request URL is derived from a variable — validate or allowlist to prevent SSRF",
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
	# http.NewRequest with variable URL
	regex.match(`http\.NewRequest\s*\([^,]+,\s*[^"]`, line)
	not regex.match(`http\.NewRequest\s*\([^,]+,\s*"`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "HTTP request URL is derived from a variable — validate or allowlist to prevent SSRF",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
