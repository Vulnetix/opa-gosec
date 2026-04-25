# SPDX-License-Identifier: Apache-2.0
# Detect directories created with excessive permissions.

package vulnetix.rules.gosec_g301

import rego.v1

metadata := {
	"id": "GOSEC-G301",
	"name": "Directory created with excessive permissions",
	"description": "os.Mkdir or os.MkdirAll is called with permissions that allow world execution (e.g., 0755, 0777). Prefer 0750 or 0700 to restrict access to the owner and group only.",
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

# Matches 0755, 0777, 0766, 0775, etc. — world-executable or world-writable
permissive_dir_perms := ["0777", "0755", "0775", "0766", "0776", "0757", "0757"]

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`os\.(Mkdir|MkdirAll)\s*\(`, line)
	some perm in permissive_dir_perms
	contains(line, perm)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Directory created with permissive mode %s — use 0750 or 0700 instead", [perm]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
