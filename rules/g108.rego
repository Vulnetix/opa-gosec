# SPDX-License-Identifier: Apache-2.0
# Detect profiling endpoint (pprof) exposed in production HTTP servers.

package vulnetix.rules.gosec_g108

import rego.v1

metadata := {
	"id": "GOSEC-G108",
	"name": "Profiling endpoint enabled",
	"description": "The net/http/pprof package is imported, which registers profiling endpoints under /debug/pprof/. Exposing these in production leaks runtime internals and can be used by attackers for reconnaissance.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/pprof.go",
	"languages": ["go"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [200],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "pprof", "information-disclosure"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, `"net/http/pprof"`)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Import of net/http/pprof registers profiling endpoints — remove from production builds",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
