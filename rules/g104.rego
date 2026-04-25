# SPDX-License-Identifier: Apache-2.0
# Detect errors that are silently discarded with blank identifier.

package vulnetix.rules.gosec_g104

import rego.v1

metadata := {
	"id": "GOSEC-G104",
	"name": "Errors unhandled",
	"description": "Error return values are explicitly discarded using the blank identifier. Unhandled errors can hide failures and lead to unexpected program states or security issues.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/errors.go",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [703],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "error-handling"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	# _, err = or val, _ = patterns where the error is discarded
	regex.match(`^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,\s*_\s*[:=]+`, line)
	not startswith(trim_space(line), "//")
	not contains(line, "range ")
	finding := {
		"rule_id": metadata.id,
		"message": "Error return value is explicitly discarded",
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
	# _ = someFunc() where result is discarded entirely
	regex.match(`^\s*_\s*=\s*[a-zA-Z]`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Return value (possibly error) is explicitly discarded",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
