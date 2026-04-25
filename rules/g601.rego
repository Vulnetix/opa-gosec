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
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	# Taking address of the range variable — classic aliasing pattern
	regex.match(`&\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[,\)]`, line)
	# Previous lines within nearby context contain a range statement
	i > 0
	prev_line := lines[i - 1]
	regex.match(`for\s+\w+\s*,\s*\w+\s*:=\s*range\b`, prev_line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Address of range loop variable taken — in Go < 1.22 this aliases to the same memory; copy the variable first",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
