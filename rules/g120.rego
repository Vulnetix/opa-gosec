# SPDX-License-Identifier: Apache-2.0
# Detect ParseMultipartForm called without a reasonable size limit.

package vulnetix.rules.gosec_g120

import rego.v1

metadata := {
	"id": "GOSEC-G120",
	"name": "ParseMultipartForm called without size limit",
	"description": "r.ParseMultipartForm is called, which buffers uploaded files in memory. Without a carefully chosen maxMemory argument, very large uploads could exhaust server memory.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/multipart.go",
	"languages": ["go"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [400],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "dos", "upload", "http"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "ParseMultipartForm(")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "ParseMultipartForm called — ensure maxMemory argument enforces a reasonable upload size limit",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
