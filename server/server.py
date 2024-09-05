import ssl
from http.server import SimpleHTTPRequestHandler, HTTPServer
from server.encryption import AESCipher
import os
import urllib.parse

class MyHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.cipher = AESCipher(os.urandom(32))
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("static/index.html", "rb") as file:
                self.wfile.write(file.read())
        elif self.path.startswith('/encrypt?'):
            query = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(query)
            message = params.get('message', [None])[0]
            if message:
                encrypted_message = self.cipher.encrypt(message)
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(encrypted_message.hex().encode())
            else:
                self.send_error(400, "Bad Request: message parameter is missing")
        elif self.path.startswith('/decrypt?'):
            query = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(query)
            ciphertext = params.get('ciphertext', [None])[0]
            if ciphertext:
                try:
                    decrypted_message = self.cipher.decrypt(bytes.fromhex(ciphertext))
                    self.send_response(200)
                    self.send_header("Content-type", "text/plain")
                    self.end_headers()
                    self.wfile.write(decrypted_message.encode())
                except Exception as e:
                    self.send_error(400, f"Bad Request: {str(e)}")
            else:
                self.send_error(400, "Bad Request: ciphertext parameter is missing")

def run_https(server_class=HTTPServer, handler_class=MyHandler, port=8443):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)

    # SSL
    httpd.socket = ssl.wrap_socket(httpd.socket,
                                   keyfile="key.pem",
                                   certfile="cert.pem",
                                   server_side=True)

    print(f"Starting https server on port {port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run_https()
