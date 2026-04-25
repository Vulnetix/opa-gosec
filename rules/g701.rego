# SPDX-License-Identifier: Apache-2.0
# Detect SQL injection via taint: user input flowing into database query execution.

package vulnetix.rules.gosec_g701

import rego.v1

metadata := {
	"id": "GOSEC-G701",
	"name": "SQL injection (taint analysis)",
	"description": "User-controlled input appears to flow into a SQL query execution function (db.Query, db.Exec, db.QueryRow). Use parameterized queries or prepared statements to prevent SQL injection.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/sql_taint.go",
	"languages": ["go"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [89],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "sql-injection", "taint", "database"],
}

# User input sources
user_input_patterns := [
	"r.URL.Query()",
	"r.FormValue(",
	"r.PostFormValue(",
	"r.Form[",
	"r.PostForm[",
	"r.Header.Get(",
	"req.URL.Query()",
	"req.FormValue(",
]

# Database sink patterns
db_sink_patterns := [
	"db.Query(",
	"db.Exec(",
	"db.QueryRow(",
	"db.QueryContext(",
	"db.ExecContext(",
	"db.QueryRowContext(",
	".Query(",
	".Exec(",
	".QueryRow(",
]

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	content := input.file_contents[path]
	# File has both user input and db sinks
	some src in user_input_patterns
	contains(content, src)
	lines := split(content, "\n")
	some i, line in lines
	some sink in db_sink_patterns
	contains(line, sink)
	# The query argument looks like a variable (not a plain string literal)
	not regex.match(`\.(Query|Exec|QueryRow)\s*\(\s*"[^"]*"\s*(,|\))`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Potential SQL injection: user input may flow into database query — use parameterized queries",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
