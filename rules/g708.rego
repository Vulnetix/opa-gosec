# SPDX-License-Identifier: Apache-2.0
# Detect server-side template injection via taint: user input in template execution.

package vulnetix.rules.gosec_g708

import rego.v1

metadata := {
	"id": "GOSEC-G708",
	"name": "Server-side template injection (taint analysis)",
	"description": "User-controlled input appears to flow into a template Parse or Execute call. In text/template, this can result in arbitrary code execution. Use html/template and avoid passing untrusted content as template source.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/template_injection.go",
	"languages": ["go"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [94],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "ssti", "template", "taint"],
}

user_input_patterns := [
	"r.URL.Query()",
	"r.FormValue(",
	"r.PostFormValue(",
	"r.Form[",
	"r.Body",
]

template_sink_patterns := [
	"template.Must(",
	"template.New(",
	"tmpl.Parse(",
	"t.Execute(",
	"t.ExecuteTemplate(",
	".Parse(",
]

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	content := input.file_contents[path]
	contains(content, `"text/template"`)
	some src in user_input_patterns
	contains(content, src)
	lines := split(content, "\n")
	some i, line in lines
	some sink in template_sink_patterns
	contains(line, sink)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Potential SSTI: user input in text/template — use html/template and never parse user-controlled template strings",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
