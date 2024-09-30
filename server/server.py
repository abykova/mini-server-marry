import ssl
from http.server import SimpleHTTPRequestHandler, HTTPServer
from server.encryption import AESCipher
import os
import urllib.parse
from urllib.parse import parse_qs, urlparse
from server.auth import AuthManager
import logging

# Настройка логирования
logging.basicConfig(filename='server.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

class MyHandler(SimpleHTTPRequestHandler):
    auth_manager = AuthManager()
    
    def __init__(self, *args, **kwargs):
        # Инициализация шифровальщика при создании сервера
        self.cipher = AESCipher(os.urandom(32))
        super().__init__(*args, **kwargs)

    def do_GET(self):
        logging.info(f"Received GET request: {self.path}")
        
        # Обработка главной страницы
        if self.path == '/':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("static/index.html", "rb") as file:
                self.wfile.write(file.read())

        # Обработка маршрута для шифрования
        elif self.path.startswith('/encrypt'):
            self.handle_encrypt()

        # Обработка маршрута для дешифрования
        elif self.path.startswith('/decrypt'):
            self.handle_decrypt()

        # Обработка регистрации пользователей
        elif self.path.startswith('/register'):
            self.handle_register()

        # Обработка входа пользователей
        elif self.path.startswith('/login'):
            self.handle_login()

        else:
            self.send_error(404, "Endpoint not found")

    def handle_encrypt(self):
        """Метод для обработки запросов на шифрование текста"""
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

    def handle_decrypt(self):
        """Метод для обработки запросов на дешифрование текста"""
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        ciphertext = params.get('ciphertext', [None])[0]

        if ciphertext:
            try:
                logging.info(f"Ciphertext decrypted: {ciphertext}")
                decrypted_message = self.cipher.decrypt(bytes.fromhex(ciphertext))
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(decrypted_message.encode())
            except Exception as e:
                logging.error(f"Decryption failed: {str(e)}")
                self.send_error(400, f"Decryption failed: {str(e)}")
        else:
            logging.error("Decryption failed: Ciphertext parameter is missing")
            self.send_error(400, "Bad Request: ciphertext parameter is missing")

    def handle_register(self):
        """Метод для регистрации пользователей"""
        query_components = parse_qs(urlparse(self.path).query)
        username = query_components.get('username', [None])[0]
        password = query_components.get('password', [None])[0]

        if username and password:
            success, message = self.auth_manager.register(username, password)
            logging.info(f"User registration attempt: {username} - {'Success' if success else 'Failure'}")
            self.send_response(200 if success else 400)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(message.encode())
        else:
            logging.error("Registration failed: Username and password required")
            self.send_error(400, "Username and password required")

    def handle_login(self):
        """Метод для обработки логина пользователей"""
        query_components = parse_qs(urlparse(self.path).query)
        username = query_components.get('username', [None])[0]
        password = query_components.get('password', [None])[0]

        if username and password:
            success, message = self.auth_manager.login(username, password)
            logging.info(f"User login attempt: {username} - {'Success' if success else 'Failure'}")
            self.send_response(200 if success else 400)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(message.encode())
        else:
            logging.error("Login failed: Username and password required")
            self.send_error(400, "Username and password required")

def run_https(server_class=HTTPServer, handler_class=MyHandler, port=8443):
    """Функция для запуска HTTPS-сервера"""
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)

    # Настройка SSL для безопасного соединения
    httpd.socket = ssl.wrap_socket(httpd.socket,
                                   keyfile="key.pem",
                                   certfile="cert.pem",
                                   server_side=True)

    logging.info(f"Starting HTTPS server on port {port}")
    print(f"Starting HTTPS server on port {port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run_https()
