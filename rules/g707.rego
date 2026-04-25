# SPDX-License-Identifier: Apache-2.0
# Detect SMTP injection via taint: user input in email headers or body.

package vulnetix.rules.gosec_g707

import rego.v1

metadata := {
	"id": "GOSEC-G707",
	"name": "SMTP injection (taint analysis)",
	"description": "User-controlled input may flow into SMTP message construction (smtp.SendMail, gomail, etc.). Unsanitized newlines in email headers can inject extra headers or body content.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/smtp_taint.go",
	"languages": ["go"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [93],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "smtp-injection", "taint", "email"],
}

user_input_patterns := [
	"r.URL.Query()",
	"r.FormValue(",
	"r.PostFormValue(",
	"r.Form[",
]

smtp_sink_patterns := [
	"smtp.SendMail(",
	"smtp.PlainAuth(",
	"gomail.",
	"mail.Send(",
	"msg.SetHeader(",
	"msg.SetBody(",
]

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	content := input.file_contents[path]
	some src in user_input_patterns
	contains(content, src)
	lines := split(content, "\n")
	some i, line in lines
	some sink in smtp_sink_patterns
	contains(line, sink)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Potential SMTP injection: user input may flow into email construction — sanitize header values by removing newlines",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
