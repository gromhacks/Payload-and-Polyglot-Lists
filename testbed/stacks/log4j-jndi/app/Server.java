import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;

public class Server {

    private static final Logger logger = LogManager.getLogger(Server.class);

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/health", new HealthHandler());
        server.createContext("/log", new LogHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Log4j JNDI testbed listening on :8080");
    }

    static class HealthHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            byte[] resp = "ok".getBytes();
            ex.sendResponseHeaders(200, resp.length);
            ex.getResponseBody().write(resp);
            ex.getResponseBody().close();
        }
    }

    static class LogHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
                byte[] resp = "{\"error\":\"method not allowed\"}".getBytes();
                ex.getResponseHeaders().set("Content-Type", "application/json");
                ex.sendResponseHeaders(405, resp.length);
                ex.getResponseBody().write(resp);
                ex.getResponseBody().close();
                return;
            }

            String body = readBody(ex.getRequestBody());
            Map<String, String> params = parseForm(body);
            String input = params.get("input");

            if (input == null) {
                input = "";
            }

            long start = System.currentTimeMillis();
            String output = null;
            String error = null;

            try {
                logger.error(input);
                output = "logged";
            } catch (Exception e) {
                error = e.getClass().getName() + ": " + e.getMessage();
            }

            long elapsed = System.currentTimeMillis() - start;

            String json = "{\"output\":" + jsonStr(output) +
                          ",\"error\":" + jsonStr(error) +
                          ",\"time_ms\":" + elapsed + "}";

            byte[] resp = json.getBytes();
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(200, resp.length);
            ex.getResponseBody().write(resp);
            ex.getResponseBody().close();
        }
    }

    private static String readBody(InputStream is) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] tmp = new byte[4096];
        int n;
        while ((n = is.read(tmp)) != -1) {
            buf.write(tmp, 0, n);
        }
        return buf.toString("UTF-8");
    }

    private static Map<String, String> parseForm(String body) {
        Map<String, String> map = new HashMap<>();
        if (body == null || body.isEmpty()) return map;
        for (String pair : body.split("&")) {
            String[] kv = pair.split("=", 2);
            try {
                String key = URLDecoder.decode(kv[0], "UTF-8");
                String val = kv.length > 1 ? URLDecoder.decode(kv[1], "UTF-8") : "";
                map.put(key, val);
            } catch (UnsupportedEncodingException e) {
                // ignore
            }
        }
        return map;
    }

    private static String jsonStr(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\")
                        .replace("\"", "\\\"")
                        .replace("\n", "\\n")
                        .replace("\r", "\\r")
                        .replace("\t", "\\t") + "\"";
    }
}
