# opa-gosec

OPA/Rego rules for the [Vulnetix CLI](https://github.com/Vulnetix/cli) SAST engine — a clean-room, text-pattern-based implementation of [gosec](https://github.com/securego/gosec) security checks.

Each rule is an independent `.rego` file under `rules/` that is auto-discovered by the CLI. Rules receive `input.file_contents` (a `map[string]string` of filepath → content) and emit a `findings` set.

## Usage

```bash
vulnetix sast --rule Vulnetix/opa-gosec /path/to/go/project
```

Disable built-in rules and run only these:

```bash
vulnetix sast --rule Vulnetix/opa-gosec --disable-default-rules /path/to/go/project
```

## Rules

| Rule ID | File | Severity | CWE | Description |
|---------|------|----------|-----|-------------|
| GOSEC-G101 | g101.rego | critical | CWE-798 | Hardcoded credentials |
| GOSEC-G102 | g102.rego | medium | CWE-200 | Bind to all interfaces |
| GOSEC-G103 | g103.rego | low | CWE-242 | Use of unsafe block |
| GOSEC-G104 | g104.rego | medium | CWE-703 | Errors unhandled |
| GOSEC-G106 | g106.rego | high | CWE-322 | SSH InsecureIgnoreHostKey |
| GOSEC-G107 | g107.rego | critical | CWE-88 | URL provided to HTTP request as taint input |
| GOSEC-G108 | g108.rego | low | CWE-200 | Profiling endpoint (pprof) enabled |
| GOSEC-G109 | g109.rego | low | CWE-190 | strconv.Atoi converted to int32/int16 |
| GOSEC-G110 | g110.rego | low | CWE-409 | Decompression bomb via io.Copy |
| GOSEC-G111 | g111.rego | low | CWE-22 | Traversable file server path |
| GOSEC-G112 | g112.rego | medium | CWE-400 | ReadHeaderTimeout not configured (slowloris) |
| GOSEC-G114 | g114.rego | medium | CWE-676 | HTTP serve without timeout |
| GOSEC-G115 | g115.rego | low | CWE-190 | Integer overflow in type conversion |
| GOSEC-G116 | g116.rego | medium | CWE-838 | Trojan Source bidirectional control characters |
| GOSEC-G117 | g117.rego | low | CWE-499 | Sensitive struct field exposed via JSON |
| GOSEC-G118 | g118.rego | low | CWE-400 | context.Background() in HTTP handler |
| GOSEC-G119 | g119.rego | low | CWE-200 | Unsafe redirect with user-controlled URL |
| GOSEC-G120 | g120.rego | low | CWE-400 | ParseMultipartForm without size limit |
| GOSEC-G121 | g121.rego | low | CWE-346 | CORS AllowAll / wildcard origin |
| GOSEC-G122 | g122.rego | medium | CWE-367 | TOCTOU race condition |
| GOSEC-G123 | g123.rego | high | CWE-295 | TLS session ticket key reuse |
| GOSEC-G124 | g124.rego | low | CWE-614 | Insecure cookie (no Secure/HttpOnly) |
| GOSEC-G201 | g201.rego | critical | CWE-89 | SQL query formatted with Sprintf |
| GOSEC-G202 | g202.rego | critical | CWE-89 | SQL query built with string concatenation |
| GOSEC-G203 | g203.rego | critical | CWE-79 | Unescaped data in HTML template |
| GOSEC-G204 | g204.rego | critical | CWE-78 | Command execution via subprocess |
| GOSEC-G301 | g301.rego | medium | CWE-276 | Directory created with excessive permissions |
| GOSEC-G302 | g302.rego | medium | CWE-276 | File created with excessive permissions |
| GOSEC-G303 | g303.rego | medium | CWE-377 | Predictable tempfile path |
| GOSEC-G304 | g304.rego | high | CWE-22 | File path provided as taint input |
| GOSEC-G305 | g305.rego | high | CWE-22 | File traversal in archive extraction |
| GOSEC-G306 | g306.rego | medium | CWE-276 | File write with insecure permissions |
| GOSEC-G401 | g401.rego | high | CWE-328 | Use of weak hash (MD5/SHA1) |
| GOSEC-G402 | g402.rego | medium | CWE-295 | Bad TLS configuration |
| GOSEC-G403 | g403.rego | medium | CWE-310 | Weak RSA key length (< 2048 bits) |
| GOSEC-G404 | g404.rego | medium | CWE-338 | Weak/insecure PRNG (math/rand) |
| GOSEC-G405 | g405.rego | high | CWE-327 | Weak cipher (DES/3DES/RC4) |
| GOSEC-G406 | g406.rego | high | CWE-328 | Deprecated hash (MD4/RIPEMD160) |
| GOSEC-G407 | g407.rego | high | CWE-1204 | Hardcoded IV/nonce |
| GOSEC-G408 | g408.rego | high | CWE-287 | SSH HostKeyCallback nil or PublicKeyCallback |
| GOSEC-G501 | g501.rego | critical | CWE-327 | Import of crypto/md5 |
| GOSEC-G502 | g502.rego | critical | CWE-327 | Import of crypto/des |
| GOSEC-G503 | g503.rego | critical | CWE-327 | Import of crypto/rc4 |
| GOSEC-G504 | g504.rego | critical | CWE-327 | Import of net/http/cgi |
| GOSEC-G505 | g505.rego | critical | CWE-327 | Import of crypto/sha1 |
| GOSEC-G506 | g506.rego | critical | CWE-327 | Import of golang.org/x/crypto/md4 |
| GOSEC-G507 | g507.rego | critical | CWE-327 | Import of golang.org/x/crypto/ripemd160 |
| GOSEC-G601 | g601.rego | low | CWE-118 | Implicit memory aliasing in range loop |
| GOSEC-G602 | g602.rego | low | CWE-118 | Slice bounds out of range |
| GOSEC-G701 | g701.rego | critical | CWE-89 | SQL injection (taint analysis) |
| GOSEC-G702 | g702.rego | critical | CWE-78 | Command injection (taint analysis) |
| GOSEC-G703 | g703.rego | critical | CWE-22 | Path traversal (taint analysis) |
| GOSEC-G704 | g704.rego | critical | CWE-918 | SSRF (taint analysis) |
| GOSEC-G705 | g705.rego | critical | CWE-79 | XSS (taint analysis) |
| GOSEC-G706 | g706.rego | low | CWE-117 | Log injection (taint analysis) |
| GOSEC-G707 | g707.rego | low | CWE-93 | SMTP injection (taint analysis) |
| GOSEC-G708 | g708.rego | low | CWE-94 | Server-side template injection (taint analysis) |
| GOSEC-G709 | g709.rego | low | CWE-502 | Unsafe deserialization (taint analysis) |

## Input Model

Rules receive:

```json
{
  "file_contents": {
    "path/to/file.go": "package main\n..."
  },
  "file_set": {
    "path/to/file.go": true
  }
}
```

## Finding Schema

Each finding in the `findings` set:

```json
{
  "rule_id": "GOSEC-G101",
  "message": "Human-readable description",
  "artifact_uri": "path/to/file.go",
  "severity": "critical",
  "level": "error",
  "start_line": 42,
  "snippet": "  password := \"hunter2\""
}
```

## Design Notes

Rules use text-pattern matching (not AST analysis) so they work on raw Go source files without requiring a Go toolchain. This means:

- Some rules may produce false positives on commented-out code or string constants that happen to match patterns
- Taint analysis rules (G7xx) are heuristic: they check whether user-input source patterns and dangerous sink patterns both appear in the same file
- Rules skip lines that begin with `//` to reduce noise from commented code

## License

Apache License 2.0. See [LICENSE](LICENSE).

These rules are a clean-room implementation. They are not derived from the gosec source code. The gosec rule identifiers and descriptions are referenced for interoperability only.
