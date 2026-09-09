#!/usr/bin/env python3
import http.client
import http.server
import ssl
import sys

upstream_host, upstream_port, listen_port, cert, key = sys.argv[1:]


class Proxy(http.server.BaseHTTPRequestHandler):
    def proxy(self):
        body = self.rfile.read(int(self.headers.get("content-length", "0")))
        connection = http.client.HTTPConnection(
            upstream_host, int(upstream_port), timeout=15
        )
        headers = {
            name: value
            for name, value in self.headers.items()
            if name.lower() not in {"host", "connection", "content-length"}
        }
        headers["Host"] = "localhost"
        headers["Content-Length"] = str(len(body))
        connection.request(self.command, self.path, body, headers)
        response = connection.getresponse()
        data = response.read()

        self.send_response(response.status)
        content_type = response.getheader("Content-Type", "")
        if content_type.startswith("application/json"):
            self.send_header("Content-Type", "application/json")
        elif content_type.startswith("text/event-stream"):
            self.send_header("Content-Type", "text/event-stream")
        else:
            self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = proxy
    do_POST = proxy

    def log_message(self, *_args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", int(listen_port)), Proxy)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain(cert, key)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
