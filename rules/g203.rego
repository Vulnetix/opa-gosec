# SPDX-License-Identifier: Apache-2.0
# Detect use of unescaped data in HTML templates (XSS risk).

package vulnetix.rules.gosec_g203

import rego.v1

metadata := {
	"id": "GOSEC-G203",
	"name": "Use of unescaped data in HTML template",
	"description": "template.HTML, template.JS, template.CSS, or template.URL are used to bypass the html/template auto-escaping. Inserting unescaped user data this way creates Cross-Site Scripting (XSS) vulnerabilities.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/templates.go",
	"languages": ["go"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [79],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "xss", "templates"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`template\.(HTML|JS|CSS|URL|HTMLAttr)\s*\(`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "template.HTML/JS/CSS/URL used to bypass auto-escaping — ensure value is trusted or properly sanitized",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
