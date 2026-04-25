# SPDX-License-Identifier: Apache-2.0
# Detect implicit memory aliasing in range loops (pre-Go 1.22 semantics).

package vulnetix.rules.gosec_g601

import rego.v1

metadata := {
	"id": "GOSEC-G601",
	"name": "Implicit memory aliasing in range loop",
	"description": "In Go versions before 1.22, the loop variable in a range loop is reused across iterations. Taking the address of the loop variable (&v) or passing it to a goroutine captures the same memory address, causing all iterations to see the last value. Use a local copy inside the loop body.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/implicit_aliasing.go",
	"languages": ["go"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [118],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "range-loop", "aliasing"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	content := input.file_contents[path]
	# File contains a range loop
	regex.match(`for\s+\w+\s*,\s*\w+\s*:=\s*range\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	# Taking address of a variable — word boundary ensures we don't match operator &^
	regex.match(`&\s*[a-zA-Z_][a-zA-Z0-9_]*\b`, line)
	not startswith(trim_space(line), "//")
	# One of the nearby preceding lines (up to 5 back) is the range statement
	j := numbers.range(max([0, i - 5]), i)[_]
	regex.match(`for\s+\w+\s*,\s*\w+\s*:=\s*range\b`, lines[j])
	finding := {
		"rule_id": metadata.id,
		"message": "Address of loop variable taken inside range loop — in Go < 1.22 all iterations share the same address; copy the variable first",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
