# SPDX-License-Identifier: Apache-2.0
# Detect files created or chmod'd with overly permissive modes.

package vulnetix.rules.gosec_g302

import rego.v1

metadata := {
	"id": "GOSEC-G302",
	"name": "File created with excessive permissions",
	"description": "os.Chmod, os.OpenFile, or os.Create is called with permissions that allow world-readable or world-writable access (e.g., 0666, 0777). Sensitive files should use 0600 or 0640.",
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

permissive_file_perms := ["0777", "0666", "0664", "0660", "0646", "0676", "0767"]

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`os\.(Chmod|OpenFile|Create)\s*\(`, line)
	some perm in permissive_file_perms
	contains(line, perm)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("File operation with permissive mode %s — use 0600 or 0640 for sensitive files", [perm]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
