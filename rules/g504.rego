# SPDX-License-Identifier: Apache-2.0
# Detect import of net/http/cgi.

package vulnetix.rules.gosec_g504

import rego.v1

metadata := {
	"id": "GOSEC-G504",
	"name": "Import of net/http/cgi",
	"description": "The net/http/cgi package is imported. CGI applications may be vulnerable to the HTTPoxy attack (CVE-2016-5386) where HTTP_PROXY environment variable can be controlled by the attacker via the Proxy header.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/blocklist.go",
	"languages": ["go"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "cgi", "httpoxy", "import-blocklist"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, `"net/http/cgi"`)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Import of net/http/cgi — CGI is vulnerable to HTTPoxy; prefer fastcgi or a standard HTTP handler",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
