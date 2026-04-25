# SPDX-License-Identifier: Apache-2.0
# Detect tls.Config using VerifyPeerCertificate without VerifyConnection, which is bypassed on session resumption.

package vulnetix.rules.gosec_g123

import rego.v1

metadata := {
	"id": "GOSEC-G123",
	"name": "TLS VerifyPeerCertificate bypassed on session resumption",
	"description": "tls.Config sets VerifyPeerCertificate but not VerifyConnection. When a TLS session is resumed, VerifyPeerCertificate is not called, allowing the custom certificate check to be silently skipped. Set VerifyConnection to enforce the check on every connection including resumptions.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/tls_verify_peer_cert.go",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [295],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "tls", "cryptography", "session-resumption"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	content := input.file_contents[path]
	# VerifyPeerCertificate is set but VerifyConnection is absent
	contains(content, "VerifyPeerCertificate")
	not contains(content, "VerifyConnection")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "VerifyPeerCertificate")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "tls.Config.VerifyPeerCertificate set without VerifyConnection — custom cert check is bypassed on TLS session resumption",
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
	contains(line, "SessionTicketKey")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "tls.Config.SessionTicketKey is set — hardcoded or reused keys break forward secrecy",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
