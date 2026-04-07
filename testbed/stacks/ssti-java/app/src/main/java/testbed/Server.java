package testbed;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import freemarker.template.Configuration;
import freemarker.template.Template;

import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.app.Velocity;
import org.apache.velocity.VelocityContext;

import org.springframework.expression.spel.standard.SpelExpressionParser;

import io.pebbletemplates.pebble.PebbleEngine;
import io.pebbletemplates.pebble.loader.StringLoader;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

        server.createContext("/freemarker", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJson(exchange, 405, null, "Method not allowed", 0);
                return;
            }
            Map<String, String> params = parseForm(exchange);
            String input = params.getOrDefault("input", "");
            long start = System.nanoTime();
            try {
                Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);
                Map<String, Object> model = new HashMap<>();
                model.put("name", "World");
                StringWriter writer = new StringWriter();
                Template template = new Template("test", new StringReader(input), cfg);
                template.process(model, writer);
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, writer.toString(), null, timeMs);
            } catch (Exception e) {
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, null, e.getClass().getName() + ": " + e.getMessage(), timeMs);
            }
        });

        server.createContext("/velocity", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJson(exchange, 405, null, "Method not allowed", 0);
                return;
            }
            Map<String, String> params = parseForm(exchange);
            String input = params.getOrDefault("input", "");
            long start = System.nanoTime();
            try {
                VelocityEngine ve = new VelocityEngine();
                ve.init();
                VelocityContext context = new VelocityContext();
                context.put("name", "World");
                StringWriter writer = new StringWriter();
                Velocity.evaluate(context, writer, "test", input);
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, writer.toString(), null, timeMs);
            } catch (Exception e) {
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, null, e.getClass().getName() + ": " + e.getMessage(), timeMs);
            }
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

        server.createContext("/pebble", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJson(exchange, 405, null, "Method not allowed", 0);
                return;
            }
            Map<String, String> params = parseForm(exchange);
            String input = params.getOrDefault("input", "");
            long start = System.nanoTime();
            try {
                PebbleEngine engine = new PebbleEngine.Builder()
                        .loader(new StringLoader())
                        .build();
                io.pebbletemplates.pebble.template.PebbleTemplate template = engine.getTemplate(input);
                StringWriter writer = new StringWriter();
                Map<String, Object> context = new HashMap<>();
                context.put("name", "World");
                template.evaluate(writer, context);
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, writer.toString(), null, timeMs);
            } catch (Exception e) {
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, null, e.getClass().getName() + ": " + e.getMessage(), timeMs);
            }
        });

        server.createContext("/thymeleaf", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJson(exchange, 405, null, "Method not allowed", 0);
                return;
            }
            Map<String, String> params = parseForm(exchange);
            String input = params.getOrDefault("input", "");
            long start = System.nanoTime();
            try {
                // Simulate Thymeleaf inline expression processing
                // Handles [[${expr}]], [(${expr})], *{expr}, ~{expr}
                SpelExpressionParser spelParser = new SpelExpressionParser();
                String result = input;

                // Process [[${...}]] (escaped inline)
                Pattern p1 = Pattern.compile("\\[\\[\\$\\{(.+?)\\}\\]\\]");
                Matcher m1 = p1.matcher(result);
                StringBuilder sb1 = new StringBuilder();
                while (m1.find()) {
                    Object val = spelParser.parseExpression(m1.group(1)).getValue();
                    m1.appendReplacement(sb1, Matcher.quoteReplacement(String.valueOf(val)));
                }
                m1.appendTail(sb1);
                result = sb1.toString();

                // Process [(${...})] (unescaped inline)
                Pattern p2 = Pattern.compile("\\[\\(\\$\\{(.+?)\\}\\)\\]");
                Matcher m2 = p2.matcher(result);
                StringBuilder sb2 = new StringBuilder();
                while (m2.find()) {
                    Object val = spelParser.parseExpression(m2.group(1)).getValue();
                    m2.appendReplacement(sb2, Matcher.quoteReplacement(String.valueOf(val)));
                }
                m2.appendTail(sb2);
                result = sb2.toString();

                // Process ${...} (standard expression)
                Pattern p3 = Pattern.compile("\\$\\{(.+?)\\}");
                Matcher m3 = p3.matcher(result);
                StringBuilder sb3 = new StringBuilder();
                while (m3.find()) {
                    Object val = spelParser.parseExpression(m3.group(1)).getValue();
                    m3.appendReplacement(sb3, Matcher.quoteReplacement(String.valueOf(val)));
                }
                m3.appendTail(sb3);
                result = sb3.toString();

                // Process *{...} (selection expression - treat as SpEL)
                Pattern p4 = Pattern.compile("\\*\\{(.+?)\\}");
                Matcher m4 = p4.matcher(result);
                StringBuilder sb4 = new StringBuilder();
                while (m4.find()) {
                    Object val = spelParser.parseExpression(m4.group(1)).getValue();
                    m4.appendReplacement(sb4, Matcher.quoteReplacement(String.valueOf(val)));
                }
                m4.appendTail(sb4);
                result = sb4.toString();

                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, result, null, timeMs);
            } catch (Exception e) {
                double timeMs = (System.nanoTime() - start) / 1_000_000.0;
                sendJson(exchange, 200, null, e.getClass().getName() + ": " + e.getMessage(), timeMs);
            }
        });

        server.setExecutor(null);
        System.out.println("SSTI Java testbed listening on :8080");
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
