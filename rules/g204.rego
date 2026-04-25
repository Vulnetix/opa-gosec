# SPDX-License-Identifier: Apache-2.0
# Detect subprocess execution via exec.Command with potentially user-controlled arguments.

package vulnetix.rules.gosec_g204

import rego.v1

metadata := {
	"id": "GOSEC-G204",
	"name": "Subprocess launched with variable arguments",
	"description": "exec.Command or exec.CommandContext is called with arguments that may be user-controlled. This can lead to command injection if the arguments are not validated and sanitized.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/subprocess.go",
	"languages": ["go"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "command-injection", "subprocess"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`exec\.(Command|CommandContext)\s*\(`, line)
	# At least one argument is a variable (not a bare string literal)
	not regex.match(`exec\.(Command|CommandContext)\s*\(\s*"[^"]+"\s*\)`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "exec.Command invoked with variable arguments — validate all inputs to prevent command injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
