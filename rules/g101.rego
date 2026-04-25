# SPDX-License-Identifier: Apache-2.0
# Detect hardcoded credentials (passwords, secrets, keys) assigned to variables.

package vulnetix.rules.gosec_g101

import rego.v1

metadata := {
	"id": "GOSEC-G101",
	"name": "Hardcoded credentials",
	"description": "Hardcoded passwords, secrets, or API keys were found in source code. These credentials may be exposed in version control and should be loaded from environment variables or a secrets manager instead.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/hardcoded_credentials.go",
	"languages": ["go"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [798],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "credentials", "secrets"],
}

# Patterns for variable names that suggest credential storage
credential_patterns := [
	"password",
	"passwd",
	"secret",
	"apikey",
	"api_key",
	"token",
	"auth_token",
	"authtoken",
	"private_key",
	"privatekey",
	"access_key",
	"accesskey",
]

# Match lines where a credential-named variable is assigned a non-empty string literal
findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	lower_line := lower(line)
	some pattern in credential_patterns
	contains(lower_line, pattern)
	# Must look like an assignment with a string literal value (double-quoted)
	regex.match(`(?i)(password|passwd|secret|api_?key|token|auth_?token|private_?key|access_?key)\s*(=|:=|:)\s*"[^"]{3,}"`, line)
	# Exclude test/example values and empty strings
	not contains(lower_line, "os.getenv")
	not contains(lower_line, "os.lookupenv")
	not contains(lower_line, "// ")
	finding := {
		"rule_id": metadata.id,
		"message": "Potential hardcoded credential detected in variable assignment",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
