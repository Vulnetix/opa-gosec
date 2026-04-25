# SPDX-License-Identifier: Apache-2.0
# Detect sensitive struct fields exposed through JSON marshaling.

package vulnetix.rules.gosec_g117

import rego.v1

metadata := {
	"id": "GOSEC-G117",
	"name": "Sensitive struct field exposed via JSON marshaling",
	"description": "A struct field with a sensitive name (Password, Secret, Token, Key, etc.) has a json struct tag that will cause it to be marshaled into JSON output, potentially exposing credentials.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/struct_tag.go",
	"languages": ["go"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [499],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "credentials", "json", "information-disclosure"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	# Field declaration with sensitive name AND json tag that is not excluded ("-")
	# Match: SensitiveName TypeName `json:"fieldname"` (not json:"-")
	regex.match(`(?i)(Password|Secret|Token|ApiKey|Api_Key|PrivateKey|AccessKey)\s+\w+`, line)
	contains(line, `json:"`)
	not contains(line, `json:"-"`)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Sensitive struct field has json tag — use json:\"-\" to exclude from marshaling",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
