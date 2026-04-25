# SPDX-License-Identifier: Apache-2.0
# Detect http.FileServer serving from a directory derived from user input or root.

package vulnetix.rules.gosec_g111

import rego.v1

metadata := {
	"id": "GOSEC-G111",
	"name": "Potentially traversable file server path",
	"description": "http.FileServer is used with a path that may expose more of the filesystem than intended. Using http.Dir(\"/\") or a path derived from user input can allow directory traversal.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/file_server.go",
	"languages": ["go"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [22],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "path-traversal", "http"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "http.FileServer")
	# http.Dir("/") or http.Dir(".") serve too broadly
	regex.match(`http\.Dir\s*\(\s*"[/\.]"`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "http.FileServer serving from root or current directory — restrict to a specific subdirectory",
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
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "http.FileServer")
	# http.FileServer with a variable path (not a literal)
	regex.match(`http\.FileServer\s*\(\s*http\.Dir\s*\(\s*[^"]`, line)
	not regex.match(`http\.FileServer\s*\(\s*http\.Dir\s*\(\s*"`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "http.FileServer uses a variable path — ensure the path is validated and restricted",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
