# SPDX-License-Identifier: Apache-2.0
# Detect potential slice bounds check bypass patterns.

package vulnetix.rules.gosec_g602

import rego.v1

metadata := {
	"id": "GOSEC-G602",
	"name": "Slice bounds out of range",
	"description": "A slice is accessed with an index or bounds expression that may exceed the slice capacity. This can cause a runtime panic or, in unsafe code, out-of-bounds memory access.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/slice_bounds.go",
	"languages": ["go"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [118],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "bounds-check", "slice"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	# Slice expression with arithmetic on the upper bound like s[:n+1] or s[n-1:]
	regex.match(`\w+\s*\[\s*\w+\s*[+-]\s*\d+\s*\]`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Slice index uses arithmetic expression — verify bounds to prevent out-of-range panic",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
