# SPDX-License-Identifier: Apache-2.0
# Detect path traversal via taint: user input flowing into file operations.

package vulnetix.rules.gosec_g703

import rego.v1

metadata := {
	"id": "GOSEC-G703",
	"name": "Path traversal (taint analysis)",
	"description": "User-controlled input appears to flow into a file path operation without sanitization. An attacker can use '../' sequences to access files outside the intended directory.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/readfile_taint.go",
	"languages": ["go"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [22],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "path-traversal", "taint", "file"],
}

user_input_patterns := [
	"r.URL.Query()",
	"r.FormValue(",
	"r.PostFormValue(",
	"r.URL.Path",
	"mux.Vars(",
	"chi.URLParam(",
]

file_sink_patterns := [
	"os.Open(",
	"os.ReadFile(",
	"ioutil.ReadFile(",
	"os.Create(",
	"os.OpenFile(",
	"filepath.Join(",
]

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	content := input.file_contents[path]
	some src in user_input_patterns
	contains(content, src)
	# Must not have path cleaning
	not contains(content, "filepath.Clean")
	not contains(content, "strings.HasPrefix")
	lines := split(content, "\n")
	some i, line in lines
	some sink in file_sink_patterns
	contains(line, sink)
	not regex.match(`\((os\.|ioutil\.)(Open|ReadFile|Create|OpenFile)\s*\(\s*"[^"]*"\s*\)`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Potential path traversal: user input may reach file operation — sanitize path with filepath.Clean and validate prefix",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
