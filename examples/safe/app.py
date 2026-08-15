import hashlib
import hmac
import sqlite3
import subprocess


def find_user(username: str):
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cursor.fetchall()


def ping_host(host: str):
    return subprocess.run(["ping", "-c", "1", host], shell=False, check=False)


def strong_hash(password: str, salt: bytes):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)


def compare_token(expected: str, actual: str):
    return hmac.compare_digest(expected, actual)
