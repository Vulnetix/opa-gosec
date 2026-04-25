# SPDX-License-Identifier: Apache-2.0
# Detect log injection via taint: user input written to log calls without sanitization.

package vulnetix.rules.gosec_g706

import rego.v1

metadata := {
	"id": "GOSEC-G706",
	"name": "Log injection (taint analysis)",
	"description": "User-controlled input appears to flow into a log statement. Unsanitized user data in logs can enable log injection attacks, where an attacker injects fake log entries or exploits log parsers.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/log_injection.go",
	"languages": ["go"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [117],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "log-injection", "taint"],
}

user_input_patterns := [
	"r.URL.Query()",
	"r.FormValue(",
	"r.PostFormValue(",
	"r.Form[",
	"r.Header.Get(",
	"r.URL.Path",
	"os.Args[",
]

log_sink_patterns := [
	"log.Print(",
	"log.Println(",
	"log.Printf(",
	"log.Fatal(",
	"log.Fatalf(",
	"log.Panic(",
	"log.Panicf(",
	"slog.Info(",
	"slog.Warn(",
	"slog.Error(",
	"zap.",
	"logrus.",
]

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	content := input.file_contents[path]
	some src in user_input_patterns
	contains(content, src)
	lines := split(content, "\n")
	some i, line in lines
	some sink in log_sink_patterns
	contains(line, sink)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Potential log injection: user input may flow into log statement — sanitize newlines and special characters",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
