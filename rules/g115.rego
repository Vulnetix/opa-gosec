# SPDX-License-Identifier: Apache-2.0
# Detect potential integer overflow from numeric type conversions.

package vulnetix.rules.gosec_g115

import rego.v1

metadata := {
	"id": "GOSEC-G115",
	"name": "Potential integer overflow in type conversion",
	"description": "Conversion of a numeric value to a smaller integer type (int32, int16, uint32, uint16, uint8) may silently overflow if the source value exceeds the target type's range.",
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
	regex.match(`\b(int32|int16|uint32|uint16|uint8)\s*\(\s*[a-zA-Z]`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Numeric type conversion to smaller integer type may overflow — add bounds check",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
