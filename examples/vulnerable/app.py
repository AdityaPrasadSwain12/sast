import hashlib
import os
import pickle
import sqlite3
import subprocess

API_KEY = "sk_test_1234567890abcdef"


def find_user(username: str):
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchall()


def ping_host(host: str):
    return subprocess.run(f"ping -c 1 {host}", shell=True, check=False)


def load_session(raw: bytes):
    return pickle.loads(raw)


def insecure_hash(password: str):
    return hashlib.md5(password.encode()).hexdigest()


def delete_path(path: str):
    os.system(f"rm -rf {path}")
