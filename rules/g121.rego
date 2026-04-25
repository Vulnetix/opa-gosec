# SPDX-License-Identifier: Apache-2.0
# Detect overbroad CrossOriginProtection bypass patterns and permissive CORS configuration.

package vulnetix.rules.gosec_g121

import rego.v1

metadata := {
	"id": "GOSEC-G121",
	"name": "Overbroad cross-origin protection bypass",
	"description": "AddInsecureBypassPattern is called with an overly broad path pattern (e.g. \"/\"), disabling cross-origin protections for all or too many routes. Restrict bypass patterns to the minimum necessary paths.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/cross_origin_bypass.go",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "cors", "http", "csrf"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	# Overbroad bypass pattern — root or wildcard path disables protection for everything
	contains(line, "AddInsecureBypassPattern")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "AddInsecureBypassPattern disables cross-origin protections — use a narrowly scoped path instead of '/' or wildcards",
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
	contains(line, "AllowAll()")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "CORS AllowAll() permits requests from any origin — restrict to known origins",
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
	regex.match(`AllowOrigins?\s*:.*"\*"`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "CORS configured with wildcard origin '*' — restrict to known origins",
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
	contains(line, `"Access-Control-Allow-Origin"`)
	contains(line, `"*"`)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Access-Control-Allow-Origin set to '*' — restrict to known origins",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
