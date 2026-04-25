# SPDX-License-Identifier: Apache-2.0
# Detect SQL queries built by string concatenation.

package vulnetix.rules.gosec_g202

import rego.v1

metadata := {
	"id": "GOSEC-G202",
	"name": "SQL query built with string concatenation",
	"description": "A SQL statement string is assembled using the + operator. Concatenating user-controlled values into SQL queries creates SQL injection vulnerabilities. Use parameterized queries instead.",
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

sql_keywords := ["SELECT ", "INSERT ", "UPDATE ", "DELETE ", "DROP ", "CREATE ", "ALTER ", "UNION "]

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some kw in sql_keywords
	contains(upper(line), kw)
	# Line has a + operator suggesting concatenation
	contains(line, " + ")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "SQL query constructed by string concatenation — use parameterized queries to prevent SQL injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
