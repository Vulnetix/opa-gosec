# SPDX-License-Identifier: Apache-2.0
# Detect unsafe deserialization: user input flowing into decode/unmarshal functions.

package vulnetix.rules.gosec_g709

import rego.v1

metadata := {
	"id": "GOSEC-G709",
	"name": "Unsafe deserialization (taint analysis)",
	"description": "User-controlled input appears to flow into a deserialization function (gob.Decode, xml.Unmarshal, yaml.Unmarshal, etc.). Deserializing untrusted data can lead to object injection, denial of service, or remote code execution depending on the format and libraries used.",
	"help_uri": "https://github.com/securego/gosec/blob/master/rules/deserialization.go",
	"languages": ["go"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [502],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "gosec", "deserialization", "taint"],
}

user_input_patterns := [
	"r.Body",
	"r.URL.Query()",
	"r.FormValue(",
	"os.Stdin",
	"ioutil.ReadAll(",
	"io.ReadAll(",
]

deserialization_sink_patterns := [
	"gob.NewDecoder(",
	"xml.Unmarshal(",
	"xml.NewDecoder(",
	"yaml.Unmarshal(",
	"yaml.NewDecoder(",
	"json.NewDecoder(",
	"json.Unmarshal(",
	".Decode(",
	"msgpack.Unmarshal(",
]

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".go")
	content := input.file_contents[path]
	some src in user_input_patterns
	contains(content, src)
	lines := split(content, "\n")
	some i, line in lines
	some sink in deserialization_sink_patterns
	contains(line, sink)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Potential unsafe deserialization: user input flows into decoder — validate input schema and use safe deserializers",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
