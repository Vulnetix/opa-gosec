# SPDX-License-Identifier: Apache-2.0
# Detect use of predictable temporary file paths.

package vulnetix.rules.gosec_g303

import rego.v1

metadata := {
	"id": "GOSEC-G303",
	"name": "Creating tempfile using a predictable path",
	"description": "os.CreateTemp or ioutil.TempFile is called with an empty directory argument, which defaults to os.TempDir(). Using predictable temp file locations can enable symlink attacks. Use a private directory.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/tempfiles.go",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [377],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "tempfile", "symlink"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(os\.CreateTemp|ioutil\.TempFile)\s*\(\s*""`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Temp file created in default system temp dir — use a private subdirectory to avoid symlink attacks",
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
	regex.match(`(os\.CreateTemp|ioutil\.TempFile)\s*\(\s*os\.TempDir\(\)`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Temp file created in os.TempDir() — use a private subdirectory to avoid symlink attacks",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
