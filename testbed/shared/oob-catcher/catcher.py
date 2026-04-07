#!/usr/bin/env python3
"""
OOB Callback Catcher - HTTP + DNS listener for detecting out-of-band payloads.

HTTP on :9999 - logs any incoming request
DNS on :5353/udp - responds to all queries with 127.0.0.1, logs queried domains

GET  /callbacks  - returns all received callbacks as JSON
POST /clear      - resets callback log
GET  /health     - healthcheck
"""

import json
import socket
import struct
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from datetime import datetime, timezone

callbacks = []
lock = threading.Lock()


def log_callback(cb_type, data):
    entry = {
        'type': cb_type,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'data': data
    }
    with lock:
        callbacks.append(entry)
    print(f"[OOB] {cb_type}: {json.dumps(data)}", flush=True)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class CallbackHandler(BaseHTTPRequestHandler):
    timeout = 5  # Socket read timeout - prevents LDAP/binary connections from blocking

    def log_message(self, format, *args):
        pass  # Suppress default logging

    def handle(self):
        """Override to catch errors from non-HTTP connections (LDAP, etc.)."""
        try:
            self.connection.settimeout(5)
            super().handle()
        except Exception:
            # Non-HTTP binary connection (LDAP, RMI, etc.) - log as callback
            log_callback('tcp', {
                'remote': self.client_address[0],
                'note': 'non-HTTP connection (possibly LDAP/RMI/binary)'
            })

    def parse_request(self):
        """Override to log bad requests as callbacks (e.g. LDAP binary protocol)."""
        result = super().parse_request()
        if not result:
            # Bad request = non-HTTP protocol connection (LDAP, JNDI, etc.)
            log_callback('tcp', {
                'remote': self.client_address[0],
                'raw_requestline': self.raw_requestline[:200].decode('utf-8', errors='replace') if self.raw_requestline else '',
                'note': 'non-HTTP protocol (possibly LDAP/RMI/JNDI)'
            })
        return result

    def do_GET(self):
        if self.path == '/callbacks':
            with lock:
                data = list(callbacks)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'ok')
        else:
            # Any other GET is a callback
            body = ''
            log_callback('http', {
                'method': 'GET',
                'path': self.path,
                'headers': dict(self.headers),
                'remote': self.client_address[0],
            })
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'callback received')

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='replace') if content_length else ''

        if self.path == '/clear':
            with lock:
                callbacks.clear()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'cleared')
            print("[OOB] Callbacks cleared", flush=True)
        else:
            log_callback('http', {
                'method': 'POST',
                'path': self.path,
                'headers': dict(self.headers),
                'body': body[:4096],
                'remote': self.client_address[0],
            })
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'callback received')

    # Handle any HTTP method
    do_PUT = do_POST
    do_DELETE = do_GET
    do_PATCH = do_POST
    do_HEAD = do_GET
    do_OPTIONS = do_GET


def build_dns_response(data):
    """Build a minimal DNS response answering with 127.0.0.1."""
    try:
        # Parse the question
        transaction_id = data[:2]
        flags = b'\x81\x80'  # Standard response, no error
        qdcount = struct.unpack('!H', data[4:6])[0]
        ancount = struct.pack('!H', qdcount)

        # Copy the question section
        offset = 12
        domain_parts = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            domain_parts.append(data[offset + 1:offset + 1 + length].decode('ascii', errors='replace'))
            offset += 1 + length

        qtype = data[offset:offset + 2]
        qclass = data[offset + 2:offset + 4]
        question = data[12:offset + 4]
        domain = '.'.join(domain_parts)

        # Log the DNS query
        log_callback('dns', {'domain': domain, 'qtype': struct.unpack('!H', qtype)[0]})

        # Build answer: pointer to question name + A record -> 127.0.0.1
        answer = b'\xc0\x0c'  # Pointer to name in question
        answer += b'\x00\x01'  # Type A
        answer += b'\x00\x01'  # Class IN
        answer += b'\x00\x00\x00\x3c'  # TTL 60
        answer += b'\x00\x04'  # RDLENGTH 4
        answer += b'\x7f\x00\x00\x01'  # 127.0.0.1

        response = transaction_id + flags
        response += struct.pack('!H', qdcount)  # QDCOUNT
        response += ancount  # ANCOUNT
        response += b'\x00\x00'  # NSCOUNT
        response += b'\x00\x00'  # ARCOUNT
        response += question + answer

        return response
    except Exception as e:
        print(f"[OOB] DNS parse error: {e}", flush=True)
        return None


def dns_server(port=5353):
    """Simple UDP DNS server that responds to all queries."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    print(f"[OOB] DNS listener on :{port}/udp", flush=True)

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            response = build_dns_response(data)
            if response:
                sock.sendto(response, addr)
        except Exception as e:
            print(f"[OOB] DNS error: {e}", flush=True)


def main():
    # Start DNS server in background thread
    dns_thread = threading.Thread(target=dns_server, args=(5353,), daemon=True)
    dns_thread.start()

    # Start HTTP server
    http_port = 9999
    server = ThreadingHTTPServer(('0.0.0.0', http_port), CallbackHandler)
    print(f"[OOB] HTTP listener on :{http_port}", flush=True)
    print(f"[OOB] Ready. Endpoints: GET /callbacks, POST /clear, GET /health", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[OOB] Shutting down", flush=True)
        server.server_close()


if __name__ == '__main__':
    main()
