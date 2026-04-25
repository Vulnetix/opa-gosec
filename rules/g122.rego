# SPDX-License-Identifier: Apache-2.0
# Detect filepath.Walk/WalkDir TOCTOU symlink races and os.Stat+Open TOCTOU patterns.

package vulnetix.rules.gosec_g122

import rego.v1

metadata := {
	"id": "GOSEC-G122",
	"name": "filepath.Walk TOCTOU symlink traversal",
	"description": "A filesystem operation inside a filepath.Walk or filepath.WalkDir callback uses the callback's path argument directly in a destructive or access sink (os.Remove, os.Open, os.Rename, etc.). Between the walk and the operation a symlink can be swapped in, redirecting the operation to an unintended target.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/filepath_walk_toctou.go",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [362],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "toctou", "race-condition", "symlink"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	content := input.file_contents[path]
	# File uses filepath.Walk or filepath.WalkDir
	regex.match(`filepath\.Walk(Dir)?\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	# Walk callback uses the path parameter in a file system sink
	regex.match(`os\.(Remove|Open|Create|Rename|Chmod|Chown|Lstat|Stat)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\b`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Filesystem operation inside Walk/WalkDir callback uses the path argument — symlink TOCTOU race possible; use os.Root-scoped APIs",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	content := input.file_contents[path]
	contains(content, "os.Stat(")
	contains(content, "os.Open(")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "os.Stat(")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "os.Stat followed by os.Open on the same file — potential TOCTOU race condition",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
