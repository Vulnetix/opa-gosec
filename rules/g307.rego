# SPDX-License-Identifier: Apache-2.0
# Detect os.Create calls that create files with default permissions (0666 before umask).

package vulnetix.rules.gosec_g307

import rego.v1

metadata := {
	"id": "GOSEC-G307",
	"name": "Defer on file close may mask errors",
	"description": "os.Create creates files with permissions 0666 (before umask), which may be more permissive than intended. Prefer os.OpenFile with explicit permission bits (e.g. 0600) to enforce least-privilege file access.",
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
	"tags": ["go", "gosec", "file-permissions", "least-privilege"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	# os.Create uses default permissions 0666 (subject to umask)
	regex.match(`os\.Create\s*\(`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "os.Create uses default permissions 0666 — use os.OpenFile with explicit 0600 or stricter permissions",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
