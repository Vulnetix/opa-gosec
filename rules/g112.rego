# SPDX-License-Identifier: Apache-2.0
# Detect http.Server structs missing ReadHeaderTimeout (slowloris vulnerability).

package vulnetix.rules.gosec_g112

import rego.v1

metadata := {
	"id": "GOSEC-G112",
	"name": "Potential slowloris attack — ReadHeaderTimeout not configured",
	"description": "An http.Server is created without setting ReadHeaderTimeout. Without this timeout, connections can be held open indefinitely by slow clients, enabling a slowloris denial-of-service attack.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/slowloris.go",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [400],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "dos", "slowloris", "http"],
}

# Detect http.Server literal blocks that lack ReadHeaderTimeout
findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	content := input.file_contents[path]
	contains(content, "http.Server{")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "http.Server{")
	not startswith(trim_space(line), "//")
	# The struct literal block does not contain ReadHeaderTimeout
	not contains(content, "ReadHeaderTimeout")
	finding := {
		"rule_id": metadata.id,
		"message": "http.Server initialized without ReadHeaderTimeout — set a timeout to prevent slowloris attacks",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
