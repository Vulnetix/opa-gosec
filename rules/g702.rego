# SPDX-License-Identifier: Apache-2.0
# Detect command injection via taint: user input flowing into exec.Command.

package vulnetix.rules.gosec_g702

import rego.v1

metadata := {
	"id": "GOSEC-G702",
	"name": "Command injection (taint analysis)",
	"description": "User-controlled input appears to flow into exec.Command or exec.CommandContext. If user input reaches the command name or its arguments without sanitization, an attacker can execute arbitrary commands.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/cmd_injection.go",
	"languages": ["go"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "command-injection", "taint"],
}

user_input_patterns := [
	"r.URL.Query()",
	"r.FormValue(",
	"r.PostFormValue(",
	"r.Form[",
	"r.Header.Get(",
	"os.Args[",
	"flag.",
]

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	content := input.file_contents[path]
	some src in user_input_patterns
	contains(content, src)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`exec\.(Command|CommandContext)\s*\(`, line)
	not regex.match(`exec\.(Command|CommandContext)\s*\(\s*"[^"]*"\s*\)`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Potential command injection: user input may reach exec.Command — validate and sanitize all arguments",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
