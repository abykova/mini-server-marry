import bcrypt
import json
import os

class AuthManager:
    def __init__(self, user_file='users.json'):
        self.user_file = user_file
        if not os.path.exists(self.user_file):
            with open(self.user_file, 'w') as file:
                json.dump({}, file)

    def _load_users(self):
        with open(self.user_file, 'r') as file:
            return json.load(file)

    def _save_users(self, users):
        with open(self.user_file, 'w') as file:
            json.dump(users, file)

    def register(self, username, password):
        users = self._load_users()

        if username in users:
            return False, "User already exists"

        # Hash password with salt
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode(), salt)
        users[username] = hashed_password.decode()
        self._save_users(users)
        return True, "User registered successfully"

    def login(self, username, password):
        users = self._load_users()

        if username not in users:
            return False, "User not found"

        hashed_password = users[username].encode()
        if bcrypt.checkpw(password.encode(), hashed_password):
            return True, "Login successful"
        else:
            return False, "Incorrect password"
