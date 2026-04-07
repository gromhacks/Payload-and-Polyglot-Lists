package testbed;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.beans.XMLDecoder;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.yaml.snakeyaml.Yaml;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import com.alibaba.fastjson.JSON;
import com.thoughtworks.xstream.XStream;
import com.caucho.hessian.io.HessianInput;

public class Server {

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);

        server.createContext("/health", exchange -> {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendJson(exchange, 405, null, "Method not allowed", 0);
                return;
            }
            byte[] resp = "ok".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/plain");
            exchange.sendResponseHeaders(200, resp.length);
            exchange.getResponseBody().write(resp);
            exchange.getResponseBody().close();
        });

        server.createContext("/deserialize", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJson(exchange, 405, null, "Method not allowed", 0);
                return;
            }
            Map<String, String> params = parseForm(exchange);
            String input = params.getOrDefault("input", "");
            long start = System.nanoTime();
            try {
                byte[] bytes = Base64.getDecoder().decode(input);
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
                Object obj = ois.readObject();
                ois.close();
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, obj.getClass().getName() + ": " + obj.toString(), null, timeMs);
            } catch (Exception e) {
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, null, e.getClass().getName() + ": " + e.getMessage(), timeMs);
            }
        });

        server.createContext("/gadget-probe", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJson(exchange, 405, null, "Method not allowed", 0);
                return;
            }
            Map<String, String> params = parseForm(exchange);
            String input = params.getOrDefault("input", "");
            long start = System.nanoTime();
            try {
                byte[] bytes = Base64.getDecoder().decode(input);
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
                Object obj = ois.readObject();
                ois.close();
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, obj.getClass().getName() + ": " + obj.toString(), null, timeMs);
            } catch (ClassNotFoundException e) {
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, null, "ClassNotFoundException: " + e.getMessage(), timeMs);
            } catch (Exception e) {
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, null, e.getClass().getName() + ": " + e.getMessage(), timeMs);
            }
        });

        // SnakeYAML endpoint - unsafe Yaml.load()
        server.createContext("/yaml", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJson(exchange, 405, null, "Method not allowed", 0);
                return;
            }
            Map<String, String> params = parseForm(exchange);
            String input = params.getOrDefault("input", "");
            long start = System.nanoTime();
            try {
                Yaml yaml = new Yaml();
                Object obj = yaml.load(input);
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                String out = obj == null ? "null" : obj.getClass().getName() + ": " + obj.toString();
                sendJson(exchange, 200, out, null, timeMs);
            } catch (Exception e) {
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, null, e.getClass().getName() + ": " + e.getMessage(), timeMs);
            }
        });

        // Jackson endpoint - polymorphic type handling enabled
        server.createContext("/jackson", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJson(exchange, 405, null, "Method not allowed", 0);
                return;
            }
            Map<String, String> params = parseForm(exchange);
            String input = params.getOrDefault("input", "");
            long start = System.nanoTime();
            try {
                ObjectMapper mapper = new ObjectMapper();
                mapper.activateDefaultTyping(
                    LaissezFaireSubTypeValidator.instance,
                    ObjectMapper.DefaultTyping.NON_FINAL
                );
                Object obj = mapper.readValue(input, Object.class);
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                String out = obj == null ? "null" : obj.getClass().getName() + ": " + obj.toString();
                sendJson(exchange, 200, out, null, timeMs);
            } catch (Exception e) {
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, null, e.getClass().getName() + ": " + e.getMessage(), timeMs);
            }
        });

        // Fastjson endpoint - autoType enabled (vulnerable config)
        server.createContext("/fastjson", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJson(exchange, 405, null, "Method not allowed", 0);
                return;
            }
            Map<String, String> params = parseForm(exchange);
            String input = params.getOrDefault("input", "");
            long start = System.nanoTime();
            try {
                // Fastjson 1.2.24 has autoType enabled by default
                Object obj = JSON.parse(input);
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                String out = obj == null ? "null" : obj.getClass().getName() + ": " + obj.toString();
                sendJson(exchange, 200, out, null, timeMs);
            } catch (Exception e) {
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, null, e.getClass().getName() + ": " + e.getMessage(), timeMs);
            }
        });

        // XStream endpoint - no security framework (vulnerable config)
        server.createContext("/xstream", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJson(exchange, 405, null, "Method not allowed", 0);
                return;
            }
            Map<String, String> params = parseForm(exchange);
            String input = params.getOrDefault("input", "");
            long start = System.nanoTime();
            try {
                XStream xstream = new XStream();
                Object obj = xstream.fromXML(input);
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                String out = obj == null ? "null" : obj.getClass().getName() + ": " + obj.toString();
                sendJson(exchange, 200, out, null, timeMs);
            } catch (Throwable e) {
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, null, e.getClass().getName() + ": " + e.getMessage(), timeMs);
            }
        });

        // XMLDecoder endpoint - captures process output if result is Process/ProcessBuilder
        server.createContext("/xmldecoder", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJson(exchange, 405, null, "Method not allowed", 0);
                return;
            }
            Map<String, String> params = parseForm(exchange);
            String input = params.getOrDefault("input", "");
            long start = System.nanoTime();
            try {
                XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)));
                Object obj = decoder.readObject();
                decoder.close();
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                String out;
                if (obj instanceof Process) {
                    Process p = (Process) obj;
                    p.waitFor();
                    String stdout = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                    String stderr = new String(p.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
                    out = "exit=" + p.exitValue() + " stdout=" + stdout.trim() + " stderr=" + stderr.trim();
                    timeMs = (System.nanoTime() - start) / 1_000_000.0;
                } else if (obj instanceof ProcessBuilder) {
                    Process p = ((ProcessBuilder) obj).start();
                    p.waitFor();
                    String stdout = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                    String stderr = new String(p.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
                    out = "exit=" + p.exitValue() + " stdout=" + stdout.trim() + " stderr=" + stderr.trim();
                    timeMs = (System.nanoTime() - start) / 1_000_000.0;
                } else {
                    out = obj == null ? "null" : obj.getClass().getName() + ": " + obj.toString();
                }
                sendJson(exchange, 200, out, null, timeMs);
            } catch (Exception e) {
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, null, e.getClass().getName() + ": " + e.getMessage(), timeMs);
            }
        });

        // Hessian endpoint - binary deserialization
        server.createContext("/hessian", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJson(exchange, 405, null, "Method not allowed", 0);
                return;
            }
            Map<String, String> params = parseForm(exchange);
            String input = params.getOrDefault("input", "");
            long start = System.nanoTime();
            try {
                byte[] bytes = Base64.getDecoder().decode(input);
                HessianInput hi = new HessianInput(new ByteArrayInputStream(bytes));
                Object obj = hi.readObject();
                hi.close();
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                String out = obj == null ? "null" : obj.getClass().getName() + ": " + obj.toString();
                sendJson(exchange, 200, out, null, timeMs);
            } catch (Exception e) {
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, null, e.getClass().getName() + ": " + e.getMessage(), timeMs);
            }
        });

        server.setExecutor(null);
        System.out.println("Deserialization Java testbed listening on :8080");
        server.start();
    }

    private static Map<String, String> parseForm(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        if (body.isEmpty()) return params;
        for (String pair : body.split("&")) {
            String[] kv = pair.split("=", 2);
            String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
            String value = kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";
            params.put(key, value);
        }
        return params;
    }

    private static void sendJson(HttpExchange exchange, int status, String output, String error, double timeMs) throws IOException {
        StringBuilder json = new StringBuilder("{");
        json.append("\"output\":").append(output == null ? "null" : jsonString(output));
        json.append(",\"error\":").append(error == null ? "null" : jsonString(error));
        json.append(",\"time_ms\":").append(String.format("%.2f", timeMs));
        json.append("}");
        byte[] resp = json.toString().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, resp.length);
        exchange.getResponseBody().write(resp);
        exchange.getResponseBody().close();
    }

    private static String jsonString(String s) {
        return "\"" + s.replace("\\", "\\\\")
                       .replace("\"", "\\\"")
                       .replace("\n", "\\n")
                       .replace("\r", "\\r")
                       .replace("\t", "\\t") + "\"";
    }
}
