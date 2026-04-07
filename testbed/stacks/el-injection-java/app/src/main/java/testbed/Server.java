package testbed;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.springframework.expression.spel.standard.SpelExpressionParser;

import ognl.Ognl;

import org.mvel2.MVEL;

import jakarta.el.ELProcessor;
import jakarta.el.ExpressionFactory;
import jakarta.el.StandardELContext;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

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

        server.createContext("/spel", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJson(exchange, 405, null, "Method not allowed", 0);
                return;
            }
            Map<String, String> params = parseForm(exchange);
            String input = params.getOrDefault("input", "");
            long start = System.nanoTime();
            try {
                SpelExpressionParser parser = new SpelExpressionParser();
                Object result = parser.parseExpression(input).getValue();
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, String.valueOf(result), null, timeMs);
            } catch (Exception e) {
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, null, e.getClass().getName() + ": " + e.getMessage(), timeMs);
            }
        });

        server.createContext("/ognl", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJson(exchange, 405, null, "Method not allowed", 0);
                return;
            }
            Map<String, String> params = parseForm(exchange);
            String input = params.getOrDefault("input", "");
            long start = System.nanoTime();
            try {
                Object result = Ognl.getValue(input, new HashMap<>());
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, String.valueOf(result), null, timeMs);
            } catch (Exception e) {
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, null, e.getClass().getName() + ": " + e.getMessage(), timeMs);
            }
        });

        server.createContext("/mvel", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJson(exchange, 405, null, "Method not allowed", 0);
                return;
            }
            Map<String, String> params = parseForm(exchange);
            String input = params.getOrDefault("input", "");
            long start = System.nanoTime();
            try {
                Object result = MVEL.eval(input);
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, String.valueOf(result), null, timeMs);
            } catch (Exception e) {
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, null, e.getClass().getName() + ": " + e.getMessage(), timeMs);
            }
        });

        server.createContext("/el", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJson(exchange, 405, null, "Method not allowed", 0);
                return;
            }
            Map<String, String> params = parseForm(exchange);
            String input = params.getOrDefault("input", "");
            long start = System.nanoTime();
            try {
                ExpressionFactory factory = ExpressionFactory.newInstance();
                StandardELContext context = new StandardELContext(factory);
                Object result = factory.createValueExpression(context, input, Object.class).getValue(context);
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, String.valueOf(result), null, timeMs);
            } catch (Exception e) {
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, null, e.getClass().getName() + ": " + e.getMessage(), timeMs);
            }
        });

        server.setExecutor(null);
        System.out.println("EL Injection Java testbed listening on :8080");
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
