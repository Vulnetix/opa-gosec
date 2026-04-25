# SPDX-License-Identifier: Apache-2.0
# Detect XSS via taint: user input written to HTTP response without escaping.

package vulnetix.rules.gosec_g705

import rego.v1

metadata := {
	"id": "GOSEC-G705",
	"name": "XSS — cross-site scripting (taint analysis)",
	"description": "User-controlled input appears to flow into an HTTP response writer (fmt.Fprintf(w,...), w.Write, template execution) without HTML escaping. This can enable Cross-Site Scripting attacks.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/xss_taint.go",
	"languages": ["go"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [79],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "xss", "taint", "http"],
}

user_input_patterns := [
	"r.URL.Query()",
	"r.FormValue(",
	"r.PostFormValue(",
	"r.Form[",
	"r.Header.Get(",
	"r.URL.Path",
]

response_sink_patterns := [
	"fmt.Fprintf(w,",
	"fmt.Fprint(w,",
	"w.Write(",
	"io.WriteString(w,",
]

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	content := input.file_contents[path]
	some src in user_input_patterns
	contains(content, src)
	# Not using html/template for escaping
	not contains(content, `"html/template"`)
	not contains(content, "html.EscapeString(")
	lines := split(content, "\n")
	some i, line in lines
	some sink in response_sink_patterns
	contains(line, sink)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Potential XSS: user input may flow into HTTP response without HTML escaping — use html/template or html.EscapeString",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
