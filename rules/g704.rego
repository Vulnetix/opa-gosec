# SPDX-License-Identifier: Apache-2.0
# Detect SSRF via taint: user input flowing into HTTP client calls.

package vulnetix.rules.gosec_g704

import rego.v1

metadata := {
	"id": "GOSEC-G704",
	"name": "SSRF — server-side request forgery (taint analysis)",
	"description": "User-controlled input appears to flow into an HTTP client request. Without URL validation, an attacker can cause the server to make requests to arbitrary internal or external systems.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/ssrf_taint.go",
	"languages": ["go"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [918],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "ssrf", "taint", "http"],
}

user_input_patterns := [
	"r.URL.Query()",
	"r.FormValue(",
	"r.PostFormValue(",
	"r.Form[",
	"r.Header.Get(",
	"req.URL.Query()",
]

http_client_patterns := [
	"http.Get(",
	"http.Post(",
	"http.Head(",
	"http.NewRequest(",
	"client.Get(",
	"client.Post(",
	"client.Do(",
]

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	content := input.file_contents[path]
	some src in user_input_patterns
	contains(content, src)
	lines := split(content, "\n")
	some i, line in lines
	some sink in http_client_patterns
	contains(line, sink)
	# URL argument is not a literal string
	not regex.match(`http\.(Get|Post|Head)\s*\(\s*"https?://`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Potential SSRF: user input may flow into HTTP client URL — validate against an allowlist",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
