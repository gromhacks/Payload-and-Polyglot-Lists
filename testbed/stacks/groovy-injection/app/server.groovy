import com.sun.net.httpserver.HttpServer
import com.sun.net.httpserver.HttpExchange
import groovy.json.JsonOutput
import java.net.URLDecoder

def server = HttpServer.create(new InetSocketAddress("0.0.0.0", 8080), 0)

server.createContext("/health") { HttpExchange exchange ->
    def response = JsonOutput.toJson([status: "ok"])
    exchange.responseHeaders.set("Content-Type", "application/json")
    exchange.sendResponseHeaders(200, response.bytes.length)
    exchange.responseBody.write(response.bytes)
    exchange.responseBody.close()
}

server.createContext("/eval") { HttpExchange exchange ->
    if (exchange.requestMethod != "POST") {
        def err = JsonOutput.toJson([output: "", error: "Method not allowed", time_ms: 0])
        exchange.responseHeaders.set("Content-Type", "application/json")
        exchange.sendResponseHeaders(405, err.bytes.length)
        exchange.responseBody.write(err.bytes)
        exchange.responseBody.close()
        return
    }

    def body = exchange.requestBody.text
    def params = [:]
    if (body) {
        body.split("&").each { param ->
            def parts = param.split("=", 2)
            if (parts.length == 2) {
                params[URLDecoder.decode(parts[0], "UTF-8")] = URLDecoder.decode(parts[1], "UTF-8")
            }
        }
    }

    def input = params.get("input", "")
    def start = System.currentTimeMillis()
    def response

    try {
        def binding = new Binding()
        def shell = new GroovyShell(binding)
        def result = shell.evaluate(input)
        def elapsed = System.currentTimeMillis() - start
        response = JsonOutput.toJson([output: result?.toString() ?: "", error: null, time_ms: elapsed])
    } catch (Exception e) {
        def elapsed = System.currentTimeMillis() - start
        response = JsonOutput.toJson([output: "", error: e.toString(), time_ms: elapsed])
    }

    exchange.responseHeaders.set("Content-Type", "application/json")
    exchange.sendResponseHeaders(200, response.bytes.length)
    exchange.responseBody.write(response.bytes)
    exchange.responseBody.close()
}

server.executor = null
server.start()
println "Groovy injection testbed running on port 8080"

// Keep the script alive
Thread.currentThread().join()
