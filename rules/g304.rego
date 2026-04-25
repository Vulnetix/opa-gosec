# SPDX-License-Identifier: Apache-2.0
# Detect file path provided as taint input to file open operations.

package vulnetix.rules.gosec_g304

import rego.v1

metadata := {
	"id": "GOSEC-G304",
	"name": "File path provided as taint input",
	"description": "os.Open, os.ReadFile, ioutil.ReadFile, or similar functions are called with a file path that may come from user input. Unvalidated paths can lead to directory traversal and unauthorized file access.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/readfile.go",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [22],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "path-traversal", "file"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(os\.Open|os\.ReadFile|ioutil\.ReadFile|os\.Stat)\s*\(\s*[^"]`, line)
	not regex.match(`(os\.Open|os\.ReadFile|ioutil\.ReadFile|os\.Stat)\s*\(\s*"`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "File operation with variable path — validate and sanitize the path to prevent directory traversal",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
