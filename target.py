import os
import hashlib
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class SystemManager:
    # VULN 1: Hardcoded secrets
    # A static API key stored in plaintext inside the source code.
    API_KEY = "abc123-def456-ghi789-jkl101112"

    def __init__(self, user, pwd):
        self.user = user
        self.pwd = pwd

    def generate_hash(self):
        # VULN 2: Use of MD5 (weak cryptographic hash)
        # MD5 is fast and collision-prone; unsuitable for password storage.
        return hashlib.md5(self.pwd.encode()).hexdigest()

    def run_backup(self, backup_location):
        # VULN 3: Command Injection
        # User-supplied 'backup_location' is directly interpolated into a shell command.
        command = f"tar -czf {backup_location}.tar.gz ./important_data"
        os.system(command)

    def authenticate(self):
        hash_val = self.generate_hash()
        # VULN 4: Sensitive-data logging
        # The password hash (or raw password) is written to logs, exposing it to anyone
        # who can read the log files.
        logging.info(f"Attempting login for user '{self.user}' with hash '{hash_val}'")
        # Simulate checking against a stored hash (hardcoded "admin" password)
        if hash_val == hashlib.md5("admin".encode()).hexdigest():
            return True
        return False

    def delete_temp_files(self, pattern):
        try:
            # Another command injection point (same VULN 3, but we only count it once)
            os.system(f"rm -rf ./temp/{pattern}")
        except:
            # VULN 5: Empty exception handler
            # All exceptions are silently swallowed with no logging, debugging, or recovery.
            pass


def main():
    print("=== System Management Tool ===")
    username = input("Enter username: ")
    password = input("Enter password: ")

    manager = SystemManager(username, password)

    if manager.authenticate():
        print("Authentication successful!")
    else:
        print("Authentication failed.")

    backup_name = input("Enter backup archive name: ")
    manager.run_backup(backup_name)

    delete_pattern = input("Enter pattern to delete (e.g., *.tmp): ")
    manager.delete_temp_files(delete_pattern)


if __name__ == "__main__":
    main()