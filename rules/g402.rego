# SPDX-License-Identifier: Apache-2.0
# Detect bad TLS configuration: InsecureSkipVerify, weak protocol versions, or weak ciphers.

package vulnetix.rules.gosec_g402

import rego.v1

metadata := {
	"id": "GOSEC-G402",
	"name": "TLS InsecureSkipVerify or weak TLS configuration",
	"description": "TLS is configured with InsecureSkipVerify:true, a minimum version below TLS 1.2, or deprecated cipher suites. This weakens transport security and may allow MITM attacks.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/tls_config.go",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [295],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "tls", "cryptography"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "InsecureSkipVerify")
	contains(line, "true")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "TLS InsecureSkipVerify:true disables certificate verification — remove in production",
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
	# MinVersion set to TLS 1.0 or 1.1
	regex.match(`MinVersion\s*:\s*tls\.(VersionTLS10|VersionTLS11|VersionSSL30)`, line)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "TLS MinVersion is set below TLS 1.2 — set tls.VersionTLS12 or higher",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
