# SPDX-License-Identifier: Apache-2.0
# Detect file traversal vulnerability in archive extraction (zip/tar).

package vulnetix.rules.gosec_g305

import rego.v1

metadata := {
	"id": "GOSEC-G305",
	"name": "File traversal when extracting zip/tar archive",
	"description": "Archive entries are extracted without sanitizing the file path. An archive containing entries with '../' path components can write files outside the intended extraction directory.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/archive.go",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [22],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "path-traversal", "archive"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	content := input.file_contents[path]
	# Uses archive extraction
	regex.match(`(zip\.NewReader|tar\.NewReader|archive/zip|archive/tar)`, content)
	lines := split(content, "\n")
	some i, line in lines
	# Opens or creates files from archive entry name without cleaning the path
	regex.match(`(os\.(Open|Create|OpenFile|MkdirAll)|filepath\.Join)\s*\(.*\.Name`, line)
	not contains(line, "filepath.Clean")
	not contains(line, "strings.HasPrefix")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Archive entry path used without sanitization — check for '../' traversal sequences before extraction",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
