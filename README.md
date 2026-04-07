# Payload & Polyglot Lists

> **Research is ongoing.** This project is under active development and will be updated regularly with new payloads, vulnerability classes, and validation improvements.

> **Disclaimer:** These payloads are provided for authorized security testing, education, and research purposes only. The authors assume no responsibility or liability for any misuse or downstream effects. Use entirely at your own risk. By using this project you accept full responsibility for your actions.

> **License:** MIT - see [LICENSE](LICENSE)

1,204 validated injection payloads covering 15 vulnerability classes, 31 deserialization frameworks, and 14 template engines. Every payload produces a detectable signal. Zero theoretical payloads.

Validation: **1,204 tested / 1,204 fire / 0 failures / 0 skipped** against 29 Docker testbed stacks.

---

## Concept

### The Problem with Traditional Payload Lists

Most publicly available payload lists are organized by vulnerability type: one list for SQL injection, another for XSS, another for command injection, and so on. A tester picks the list they think matches the target, loads it into an intruder tool, and runs it against a parameter. If they guess wrong about the vulnerability class, the entire scan produces nothing. If the backend is an uncommon database, a non-standard template engine, or a language the list didn't account for, the payloads silently fail. The tester moves on thinking the parameter is clean.

This approach has two fundamental problems. First, it requires the tester to know what vulnerability exists before they've found it. Second, most payloads in circulation are theoretical -- copied between projects and blog posts without ever being tested against a real parser. They look right. They might even be syntactically valid. But they don't actually trigger a detectable response from the target.

### Polyglot-First, Signal-Guaranteed

This project takes a different approach. The primary unit of work is the **polyglot** -- a single payload string engineered to be valid (or meaningfully invalid) across as many injection contexts as possible simultaneously. One polyglot breaks out of single quotes, double quotes, parentheses, block comments, HTML attributes, template delimiters, and backtick contexts all at once. Instead of needing to know what the vulnerability is, the tester fires polyglots at every parameter and watches for signals.

Every payload in this collection is built around **detection pillars** -- observable responses that confirm a vulnerability exists without requiring access to server logs, source code, or filesystem:

- **Error**: the payload causes the backend to throw an exception, parser error, or stack trace visible in the response.
- **Math**: the payload includes an arithmetic expression like `7*191` that evaluates to `1337`. If that number appears in the response, the backend executed the expression.
- **Timing**: the payload forces a delay (5+ seconds). If the response is slow, the backend executed a sleep or CPU-intensive operation.
- **OOB (Out-of-Band)**: the payload forces the backend to make an outbound HTTP, DNS, or TCP connection to a callback server the tester controls. Confirms execution even when the response is completely opaque.

If a payload doesn't produce at least one of these signals when tested against its target context, it doesn't belong in the list. Every one of the 1,204 payloads here has been validated against purpose-built Docker testbeds. Zero are theoretical.

### Built-ins Over Shell Commands

Traditional OOB and timing payloads rely on shell commands: `curl`, `nslookup`, `ping`, `sleep`. These break constantly. They depend on the target OS, the available PATH, which shell interprets the command, and whether the process has permission to spawn subprocesses. A `curl`-based OOB payload that works on Ubuntu fails on Alpine (no curl), fails on Windows (no curl), and fails inside a restricted container (no outbound process execution).

This project replaces shell commands with language-native built-ins wherever possible. Python payloads use `urllib.request.urlopen()` and `time.sleep()`. Java payloads use `java.net.URL.openStream()` and `Thread.sleep()`. Ruby uses `Net::HTTP.get()` and `Kernel.sleep`. PHP uses `file_get_contents()` and `sleep()`. These functions exist in every standard installation of their respective language -- no PATH lookup, no subprocess, no OS dependency.

Where even standard library imports might be blocked (sandboxed eval, restricted exec), the payloads fall back to import-free alternatives: CPU spin loops for timing (`sum(range(500000000))` in Python, `Atomics.wait()` in Node) and raw socket connections for OOB (`__import__('socket').create_connection()`, `fsockopen()`, `TCPSocket.new()`).

### Where Polyglots Don't Reach

Not everything can be a polyglot. Template engines use fundamentally incompatible syntax -- `{{}}` in Jinja2 means nothing to ERB's `<%= %>`, and neither parses as Freemarker's `${}`). Deserialization formats are binary or structured data specific to one framework. For these categories, the project uses per-engine payloads organized under the same detection pillar system, covering 14 template engines and 31 deserialization frameworks across 7 languages.

The result is a single corpus where polyglots handle the contexts they can (SQLi, OS command injection, XSS, code injection) and purpose-built per-engine payloads handle the rest, all validated, all producing detectable signals, all ready for line-by-line injection tools.

---

## Quick Start

```bash
# 1. Prepare payloads with your callback domain
#    Replaces {domain} placeholder in all OOB payloads with your server
./tools/payloadctl prepare YOUR_CALLBACK.oastify.com

# 2. Load into Burp Intruder, ffuf, or any line-by-line injection tool
#    All output goes to ready/ (gitignored, contains your domain)
```

After running `prepare`, your ready-to-use files are:

| File | What | Count |
|------|------|-------|
| `ready/payloads-only.txt` | Full list, one payload per line | 1,204 |
| `ready/by-category/sqli.txt` | SQL injection only | 204 |
| `ready/by-category/ssti.txt` | Template injection only | 168 |
| `ready/by-category/deserialization.txt` | Deserialization only | 116 |
| `ready/by-category/os-cmd-injection.txt` | OS command injection only | 116 |
| `ready/by-category/code-injection.txt` | Code injection only | 101 |
| `ready/by-category/ssrf.txt` | SSRF only | 117 |
| `ready/by-category/path-traversal.txt` | Path traversal only | 98 |
| `ready/by-category/xss.txt` | XSS only | 49 |
| `ready/by-category/nosql.txt` | NoSQL injection only | 26 |
| `ready/by-category/format-string.txt` | Format string only | 33 |
| `ready/by-category/el-injection.txt` | Expression language only | 18 |
| `ready/by-category/header-crlf.txt` | CRLF/header injection only | 14 |
| `ready/by-category/prototype-pollution.txt` | Prototype pollution only | 10 |
| `ready/by-category/xxe.txt` | XXE only | 8 |
| `ready/by-category/polyglots.txt` | Cross-context polyglots | 213 |
| `ready/by-pillar/error-payloads-only.txt` | Error-based payloads | 289 |
| `ready/by-pillar/timing-payloads-only.txt` | Timing-based (blind) | 213 |
| `ready/by-pillar/oob-payloads-only.txt` | Out-of-band callback | 190 |
| `ready/by-pillar/math-payloads-only.txt` | Math canary (1337) | 163 |
| `ready/by-pillar/reflected-payloads-only.txt` | Reflected/edge-case | 350 |
| `ready/encoded/url-encoded/full.txt` | URL-encoded variant | 1,204 |
| `ready/encoded/base64/full.txt` | Base64 variant | 1,204 |
| `ready/encoded/json-safe/full.txt` | JSON-safe variant | 1,204 |
| `ready/encoded/double-url-encoded/full.txt` | Double URL-encoded | 1,204 |
| `ready/encoded/html-entity/full.txt` | HTML entity encoded | 1,204 |
| `ready/encoded/hex-escaped/full.txt` | Hex-escaped variant | 1,204 |
| `ready/encoded/unicode-escaped/full.txt` | Unicode-escaped variant | 1,204 |

Custom output directory:

```bash
./tools/payloadctl prepare YOUR_CALLBACK.oastify.com -o /path/to/engagement/payloads
```

Raw templates with `{domain}` placeholder (for scripted substitution) are in `payloads/dist/`.

---

## Detection Pillars

Every payload produces at least one of these signals. Grep for these in your responses:

| Pillar | Payloads | What to look for | Use when |
|--------|----------|-----------------|----------|
| **Error** | 289 | Exception text, stack trace, parser error in response | App reflects errors |
| **Timing** | 213 | Response takes >4.5 seconds | Blind - no output, no errors |
| **OOB** | 190 | Outbound HTTP/DNS/TCP to your callback server | Blind + async - timing unreliable |
| **Math** | 163 | `1337` literal in response body | Output reflected but no errors |
| **Reflected** | 350 | Input value echoed back in response | Fuzzing for parser anomalies |
| **File-read** | (subset) | `root:` or `[extensions]` content in response | Path traversal, XXE file read |

Canary values: `1337` (primary, from `7*191`) and `7331` (secondary). Detection is a simple grep.

---

## Payload Coverage

### By Vulnerability Class

| Category | Count | Pillars | Coverage |
|----------|-------|---------|----------|
| SQLi | 204 | error, math, timing, oob | MySQL, PostgreSQL, Oracle, MSSQL, SQLite, CockroachDB. UNION, error, timing, OOB. Context breakouts: `'`, `"`, `)`, `))`, `*/`, numeric. |
| SSTI | 168 | error, math, timing, oob | Jinja2, Mako, Tornado, EJS, Nunjucks, Pug, Twig, Smarty, Blade, ERB, Slim, Haml, Thymeleaf, Pebble, Freemarker, Velocity, Razor, Go template, Mustache, Liquid. All use language built-ins. |
| Deserialization | 116 | error, math, timing, oob | 31 frameworks / 7 languages. Python (pickle P0/P2/P4, YAML, jsonpickle), PHP (unserialize), Node (node-serialize, js-yaml, funcster, cryo), Ruby (YAML, Marshal, Oj), Java (Jackson, Fastjson, XStream, SnakeYAML, XMLDecoder, Hessian, JNDI/Log4Shell, ObjectInputStream, ysoserial URLDNS), .NET (Json.NET, BinaryFormatter, SoapFormatter, XmlSerializer, JavaScriptSerializer, LosFormatter, ViewState, ObjectStateFormatter), Perl (Storable, YAML). |
| OS Cmd Injection | 116 | error, math, timing, oob | Bash, CMD, PowerShell. Breakouts: `;`, `\|`, `\|\|`, `&&`, `$()`, backticks. IFS bypass, glob bypass, hex encoding. |
| Code Injection | 101 | error, math, timing, oob | Python, Node, PHP, Ruby, Perl, Lua, Java ScriptEngine. Import-free CPU spin, socket-level OOB. |
| SSRF | 117 | error, math, timing, oob | Cloud metadata (AWS/GCP/Azure), IP bypass, protocol schemes, DNS rebinding, internal service probes. |
| Path Traversal | 98 | error, math, timing, oob | Linux + Windows, encoding bypass, null byte, PHP wrappers, UNC, NTFS ADS, 8.3 short names. |
| XSS | 49 | error, math, oob | Cross-context polyglots (20+ contexts), event handlers, filter evasion, DOM clobbering, mutation XSS, SVG, OOB. |
| Format String | 33 | error, math | C/C++ (`%s%n%x`), Python (`{0.__class__}`), .NET (`{0:X}`). |
| NoSQL | 26 | error, math, timing, oob | MongoDB operator injection, `$where` timing, OOB, Redis commands. |
| EL Injection | 18 | error, math, timing, oob | SpEL, OGNL, Unified EL. OOB via `java.net.URL`. |
| CRLF/Header | 14 | error, math, oob | Response splitting, header injection, OOB via Host header. |
| Prototype Pollution | 10 | error, math | `__proto__`, `constructor.prototype`, JSON and query string variants. |
| XXE | 8 | error, timing, oob | External entities, XInclude, parameter entities, Billion Laughs. |
| Polyglots/Edge Cases | 213 | error, math, timing, oob | Cross-context polyglots + buffer overflow, integer boundary, type confusion, null byte. |

10 of 15 categories have all 4 pillars. The 5 that don't (XSS, Format String, Prototype Pollution, CRLF, XXE) have architectural reasons - you can't do timing-based CRLF or OOB format strings. Where cross-pillar IS possible, the polyglots section covers it.

### Encoded Variants

7 encoding formats, each with all 1,204 payloads:

| Encoding | Use case |
|----------|----------|
| URL-encoded | Standard query/form parameters |
| Double-URL-encoded | WAF bypass, double-decode vulns |
| Base64 | API bodies, JWT, serialized params |
| JSON-safe | JSON request bodies (escaped quotes) |
| HTML entity | HTML attribute injection |
| Hex-escaped | Binary protocols, low-level injection |
| Unicode-escaped | Unicode normalization bypass |

---

## Design Principles

**Minimum payloads, maximum context coverage.** See [SPEC.md](SPEC.md) for the full technical specification with per-engine pillar tables and exact payload syntax.

1. **Polyglots first.** One payload breaks out of `'`, `"`, `)`, `*/`, `-->`, backticks, and template delimiters simultaneously. Polyglot sections lead the master list.

2. **Per-engine where polyglots can't reach.** SSTI delimiters and deserialization formats are fundamentally incompatible across engines.

3. **Built-in over shell.** OOB and timing payloads use language-native libraries:

   | Language | OOB Built-in | Timing Built-in |
   |----------|-------------|-----------------|
   | Python | `urllib.request.urlopen()` | `time.sleep(5)` |
   | Java | `java.net.URL.openStream()` | `Thread.sleep(5000)` |
   | Node | `require('http').get()` | CPU spin: `for(var i=0;i<5e9;i++){}` |
   | PHP | `file_get_contents()`, `fsockopen()` | `sleep(5)` |
   | Ruby | `Net::HTTP.get()`, `TCPSocket.new()` | `sleep(5)` |
   | Perl | `IO::Socket::INET` | `select(undef,undef,undef,5)` |
   | .NET | `System.Net.WebClient` | `Thread.Sleep(5000)` |

   Shell commands (`curl`, `nslookup`) depend on OS and PATH. Built-ins work everywhere.

4. **Import-free where possible.** CPU spin timing works even when imports are blocked:
   - Python: `sum(range(500000000))` (~7s, no imports)
   - Node: `Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,5000)` (precise 5s)
   - Ruby: `99999999.times{1+1}`

5. **Socket-level OOB as fallback.** When HTTP libraries are blocked: `__import__('socket').create_connection()`, `fsockopen()`, `TCPSocket.new()`, `new java.net.Socket()`.

---

## CLI Tool (`payloadctl`)

```bash
# USAGE: prepare payloads for an engagement
./tools/payloadctl prepare abc123.oastify.com          # output -> ready/
./tools/payloadctl prepare abc123.oastify.com -o /tmp/payloads  # custom dir

# DEVELOPMENT: build, distribute, validate, generate
./tools/payloadctl build              # sources/ -> payloads/full.txt
./tools/payloadctl dist               # full.txt -> payloads/dist/ (categories, pillars, encodings)
./tools/payloadctl validate           # test all 1,204 payloads against 29 testbed stacks
./tools/payloadctl generate           # regenerate computed payloads (deser, ssti, sqli, misc)
./tools/payloadctl generate deser     # deserialization only
./tools/payloadctl generate ssti      # SSTI only
```

### Typical Development Workflow

```bash
# 1. Edit source files
vim payloads/sources/sqli.txt

# 2. Rebuild
./tools/payloadctl build       # rebuild full.txt from sources
./tools/payloadctl dist        # regenerate dist/ (categories, pillars, encodings)

# 3. Validate (requires Docker testbeds running)
cd testbed && ./testbed up sqli-sqlite && cd ..
./tools/payloadctl validate    # expect: N FIRE / 0 NO-FIRE / 0 SKIPPED

# 4. Prepare for use
./tools/payloadctl prepare YOUR_CALLBACK.oastify.com
```

---

## Repository Structure

```
.
├── README.md                          # This file
├── SPEC.md                            # Technical spec - per-engine pillars, payload syntax, coverage
│
├── tools/                             # CLI and generators
│   ├── payloadctl                     # CLI entry point
│   ├── cmd_build.py                   # Build full.txt from source files
│   ├── cmd_dist.py                    # Generate dist/ directory
│   ├── cmd_validate.py                # Validate payloads against testbeds
│   ├── cmd_generate.py                # Run payload generators
│   ├── cmd_prepare.py                 # Prepare payloads with callback domain
│   ├── generate-deser-final.py        # Deserialization generator (31 frameworks)
│   ├── generate-ssti-missing.py       # SSTI generator (14 engines)
│   ├── generate-sqli-code-missing.py  # SQLi and code injection generator
│   └── generate-misc-missing.py       # XXE, XSS, SSRF, path traversal generator
│
├── payloads/
│   ├── full.txt                       # Master list (1,204 payloads, with ## headers)
│   ├── sources/                       # Source files (edit these, all validated)
│   │   ├── polyglots-condensed.txt    # Cross-context polyglots (first in master)
│   │   ├── sqli.txt                   # SQL injection (204)
│   │   ├── ssti.txt                   # Template injection (168)
│   │   ├── deserialization.txt        # Deserialization (116, 31 frameworks)
│   │   ├── os-cmd-injection.txt       # OS command injection (116)
│   │   ├── code-injection.txt         # Code injection (101)
│   │   ├── ssrf.txt                   # SSRF (117)
│   │   ├── path-traversal.txt         # Path traversal (98)
│   │   ├── xss.txt                    # XSS (49)
│   │   ├── format-string.txt          # Format string (33)
│   │   ├── nosql.txt                  # NoSQL (26)
│   │   ├── el-injection.txt           # Expression language (18)
│   │   ├── header-crlf.txt            # CRLF/header (14)
│   │   ├── prototype-pollution.txt    # Prototype pollution (10)
│   │   └── xxe.txt                    # XXE (8)
│   └── dist/                          # Generated (don't edit, use payloadctl dist)
│       ├── full.txt
│       ├── payloads-only.txt          # Raw lines for Burp Intruder
│       ├── by-category/               # 15 category files
│       ├── by-pillar/                 # 5 pillar files (with -payloads-only variants)
│       └── encoded/                   # 7 encoding variants
│
├── ready/                             # Output from payloadctl prepare (gitignored)
│
└── testbed/                           # Docker validation infrastructure
    ├── testbed                        # CLI: ./testbed up <stack>
    ├── docker-compose.oob.yml         # OOB callback catcher (port 9999)
    ├── shared/oob-catcher/            # HTTP + TCP callback server
    └── stacks/                        # 29 vulnerable application stacks
```

---

## Adding Payloads

### Add a payload to an existing category

1. Edit the source file in `payloads/sources/`. One payload per line under a `##Header##` section.
2. Every payload must produce a detectable signal (error, math 1337, timing >4.5s, OOB, reflection).
3. Rebuild and validate:
   ```bash
   ./tools/payloadctl build && ./tools/payloadctl dist
   ./tools/payloadctl validate    # 0 NO-FIRE required
   ```

### Add a new vulnerability category

1. Create `payloads/sources/<category>.txt` with `##` headers for each pillar (error, math, timing, OOB).
2. Add the file to `tools/cmd_build.py` `SOURCE_FILES` and `tools/cmd_dist.py` `CATEGORY_SOURCES`.
3. Create a testbed stack in `testbed/stacks/<category>/` (Dockerfile + server exposing `POST /<endpoint>` with `input=<payload>` returning `{"output": "...", "error": "...", "time_ms": N}`).
4. Add endpoint routing in `tools/cmd_validate.py` (`ENDPOINTS` dict and `_get_endpoints()` function).
5. Validate: `./tools/payloadctl validate`

### Add a new deserialization framework

1. Edit `tools/generate-deser-final.py` - add a function that outputs payloads (error, math, timing, OOB).
2. Run `./tools/payloadctl generate deser && ./tools/payloadctl build`
3. Add testbed endpoint and routing if needed.

### Add a new SSTI engine

1. Edit `payloads/sources/ssti.txt` - add `##EngineName (Language) - Pillar##` sections. Use language built-ins for timing/OOB.
2. Add testbed endpoint in the matching `ssti-<language>` stack.
3. Add routing in `tools/cmd_validate.py` `ENGINE_MAP`.

### Payload format rules

- One payload per line (multi-line YAML uses literal `\n`)
- `{domain}` placeholder for OOB callback URLs
- `1337` canary for all math payloads
- `##Header##` sections group by category and pillar
- No duplicates (build step deduplicates automatically)

---

## Validation

The validator tests every payload against real vulnerable applications:

```bash
# Start testbeds (Docker required)
cd testbed
./testbed up sqli-sqlite
./testbed up ssti-python
./testbed up deserialization-java
# ... (29 stacks total)

# Run validation
cd ..
./tools/payloadctl validate
# Output: 1,204 FIRE / 0 NO-FIRE / 0 SKIPPED / 1,204 TOTAL
```

How it works:
1. Reads `payloads/full.txt` and routes each `##` section to matching testbed endpoint(s)
2. POSTs `input=<payload>` to endpoint(s), checks response for signals
3. A payload fires if ANY endpoint returns: error text, `1337` in output, >4.5s delay, OOB callback, file-read signature, or reflected input

### Testbed stacks (29 total)

| Stack | Port | Language | Endpoints |
|-------|------|----------|-----------|
| sqli-sqlite | 8001 | Python | `/sqli`, `/sqli-numeric` |
| sqli-postgres | 8030 | Python | `/sqli` |
| ssti-python | 8003 | Python | `/jinja2`, `/mako`, `/tornado` |
| ssti-node | 8011 | Node | `/ejs`, `/nunjucks`, `/pug` |
| ssti-php | 8020 | PHP | `/twig`, `/smarty`, `/blade` |
| ssti-ruby | 8025 | Ruby | `/erb`, `/slim`, `/haml` |
| ssti-java | 8040 | Java | `/freemarker`, `/velocity`, `/pebble`, `/thymeleaf` |
| os-cmd-injection | 8002 | Python | `/system`, `/popen` |
| code-injection-python | 8004 | Python | `/eval` |
| code-injection-node | 8012 | Node | `/eval` |
| code-injection-php | 8021 | PHP | `/eval` |
| code-injection-ruby | 8026 | Ruby | `/eval`, `/yaml`, `/marshal`, `/oj` |
| code-injection-perl | 8031 | Perl | `/eval`, `/storable`, `/yaml` |
| xss | 8010 | Node | `/reflected` |
| xxe | 8008 | Python | `/parse`, `/xinclude` |
| ssrf | 8007 | Python | `/fetch` |
| path-traversal | 8006 | Python | `/read` |
| nosql-redis | 8015 | Node | `/eval` |
| el-injection-java | 8041 | Java | `/spel`, `/ognl` |
| prototype-pollution | 8013 | Node | `/merge` |
| deserialization-python | 8005 | Python | `/pickle`, `/yaml`, `/jsonpickle` |
| deserialization-node | 8014 | Node | `/unserialize`, `/yaml`, `/funcster` |
| deserialization-php | 8022 | PHP | `/unserialize`, `/unserialize-b64`, `/phar` |
| deserialization-java | 8042 | Java | `/deserialize`, `/yaml`, `/jackson`, `/fastjson`, `/xstream`, `/xmldecoder`, `/hessian` |
| deserialization-dotnet | 8045 | .NET | `/jsonnet`, `/binaryformatter`, `/xmlserializer`, `/losformatter`, `/javascriptserializer` |
| log4j-jndi | 8046 | Java | `/log` |
| sqli-mysql | 8050 | Python | `/sqli`, `/sqli-numeric` |
| nosql-mongo | 8051 | Node | `/find`, `/where`, `/aggregate` |
| ssi-esi | 8035 | Apache/Varnish | SSI + ESI endpoints |

OOB catcher on port 9999 (HTTP + TCP). Every endpoint accepts `POST /<sink>` with `input=<payload>` and returns `{"output": "...", "error": "...|null", "time_ms": N}`.

---

## Credits

Payloads researched and developed by [Grom Hacks](https://github.com/gromhacks). Built on work from the security research community including PayloadsAllTheThings, HackTricks, PortSwigger Web Security Academy, and individual researchers. All payloads validated against real vulnerable applications.
