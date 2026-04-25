# SPDX-License-Identifier: Apache-2.0
# Detect SQL queries built with fmt.Sprintf.

package vulnetix.rules.gosec_g201

import rego.v1

metadata := {
	"id": "GOSEC-G201",
	"name": "SQL query formatted with Sprintf",
	"description": "A SQL query string is constructed using fmt.Sprintf. If any of the format arguments originate from user input, this is a SQL injection vulnerability. Use parameterized queries or prepared statements instead.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/sql.go",
	"languages": ["go"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [89],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "sql-injection", "database"],
}

sql_keywords := ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "EXEC", "UNION"]

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "fmt.Sprintf(")
	some kw in sql_keywords
	contains(upper(line), kw)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "SQL query built with fmt.Sprintf — use parameterized queries to prevent SQL injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
