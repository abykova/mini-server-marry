# mini-server-marry
MiniServerMerry — это простой проект на Python. Он включает в себя небольшой сервер и функции шифрования

## Features

- Simple HTTP server with encryption and decryption functionality
- HTTPS support using SSL certificates for secure connections
- **NEW**: User authentication system with password encryption (bcrypt)
- Secure storage of passwords using salted hashes


# Запуск проекта
1. Установите зависимости:
```
pip install -r requirements.txt
```

2. Generate SSL certificates (for development):
```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

3. Запустите сервер:

```
python main.py
```

4. Откройте браузер и перейдите по адресу `http://localhost:8443` для проверки работы сервера.

# Encrypt/Decrypt Endpoints
To encrypt a message:
```
https://localhost:8443/encrypt?message=your_message
```

To decrypt a message:
```
https://localhost:8443/decrypt?ciphertext=your_ciphertext
```

# Authentication Endpoints

To register a new user:
```
https://localhost:8443/register?username=your_username&password=your_password
```

To log in:
```
https://localhost:8443/login?username=your_username&password=your_password
```

# Dependencies

- Python 3.x
- cryptography library for encryption
- bcrypt library for password hashing
- SSL certificates
