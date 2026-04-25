# SPDX-License-Identifier: Apache-2.0
# Detect TOCTOU (time-of-check/time-of-use) patterns: Stat then Open on same path.

package vulnetix.rules.gosec_g122

import rego.v1

metadata := {
	"id": "GOSEC-G122",
	"name": "TOCTOU race condition",
	"description": "A file is checked with os.Stat and then opened or modified with os.Open/os.Create. Between the check and use, another process could change the file, creating a TOCTOU race condition.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/toctou.go",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [367],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "toctou", "race-condition"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	content := input.file_contents[path]
	contains(content, "os.Stat(")
	contains(content, "os.Open(")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "os.Stat(")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "os.Stat followed by os.Open on the same file — potential TOCTOU race condition",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
