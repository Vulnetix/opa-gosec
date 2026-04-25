# SPDX-License-Identifier: Apache-2.0
# Detect file writes with world-readable or world-writable permissions.

package vulnetix.rules.gosec_g306

import rego.v1

metadata := {
	"id": "GOSEC-G306",
	"name": "File write with insecure permissions",
	"description": "os.WriteFile or ioutil.WriteFile is called with permissions that allow world-readable (0644, 0666) or world-writable (0777) access. Sensitive files should use 0600.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/file_permissions.go",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [276],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "file-permissions"],
}

permissive_write_perms := ["0777", "0666", "0664", "0644", "0640"]

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(os\.WriteFile|ioutil\.WriteFile)\s*\(`, line)
	some perm in permissive_write_perms
	contains(line, perm)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("File written with permissive mode %s — use 0600 for files containing sensitive data", [perm]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
