# SPDX-License-Identifier: Apache-2.0
# Detect potential integer overflow when converting strconv.Atoi result to int32/int16.

package vulnetix.rules.gosec_g109

import rego.v1

metadata := {
	"id": "GOSEC-G109",
	"name": "Potential integer overflow from strconv.Atoi",
	"description": "strconv.Atoi returns an int sized for the platform (64-bit on 64-bit systems). Converting the result directly to int32 or int16 can overflow and produce unexpected values.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/integer_overflow_conversion.go",
	"languages": ["go"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [190],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "integer-overflow"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "strconv.Atoi")
	regex.match(`int(32|16)\s*\(`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "strconv.Atoi result cast to int32/int16 may overflow; use strconv.ParseInt with explicit bit size",
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
	content := input.file_contents[path]
	# File uses strconv.Atoi and elsewhere narrows to a smaller integer type
	contains(content, "strconv.Atoi")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\bint(32|16)\s*\([a-zA-Z_][a-zA-Z0-9_]*\)`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "int32/int16 narrowing in file that uses strconv.Atoi — result may overflow; use strconv.ParseInt with explicit bit size",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
