# SPDX-License-Identifier: Apache-2.0
# Detect Trojan Source bidirectional Unicode control characters in source files.

package vulnetix.rules.gosec_g116

import rego.v1

metadata := {
	"id": "GOSEC-G116",
	"name": "Trojan source — bidirectional control characters",
	"description": "Bidirectional Unicode control characters (e.g., U+202A–U+202E, U+2066–U+2069, U+200F) in source code can visually reorder tokens in ways that mislead code reviewers while the compiler sees different logic.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/trojan_source.go",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [838],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "trojan-source", "unicode"],
}

# Bidirectional control characters as hex-escaped patterns
bidi_chars := [
	"‪", "‫", "‬", "‭", "‮",
	"⁦", "⁧", "⁨", "⁩", "‏",
]

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some ch in bidi_chars
	contains(line, ch)
	finding := {
		"rule_id": metadata.id,
		"message": "Bidirectional Unicode control character detected — potential Trojan Source attack",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
