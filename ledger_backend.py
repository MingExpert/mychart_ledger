import sqlite3
import logging
from cryptography.fernet import Fernet
import secrets
from datetime import datetime, timedelta

class LedgerBackend:
    def __init__(self, db_path="secure_ledger.db"):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("LedgerBackend")

        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        self.db_path = db_path
        self.setup_database()

    def setup_database(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS user_credentials (
                user_id TEXT PRIMARY KEY,
                encrypted_username TEXT,
                encrypted_password TEXT,
                hint TEXT,
                biometric_enabled BOOLEAN
            )
        ''')
        conn.commit()
        conn.close()
        self.logger.info("Database setup complete.")

    def store_credentials(self, user_id, username, password, hint=""):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        enc_username = self.cipher_suite.encrypt(username.encode("utf-8"))
        enc_password = self.cipher_suite.encrypt(password.encode("utf-8"))
        c.execute('''
            INSERT OR REPLACE INTO user_credentials (
                user_id, encrypted_username, encrypted_password, hint, biometric_enabled
            ) VALUES (?, ?, ?, ?, ?)
        ''', (user_id, enc_username, enc_password, hint, False))
        conn.commit()
        conn.close()
        self.logger.info(f"Stored credentials for user: {user_id}")

    def retrieve_credentials(self, user_id):
        """
        Retrieve decrypted username and password for a given user_id.
        Returns dict or None if not found.
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            """SELECT encrypted_username, encrypted_password, hint, biometric_enabled
               FROM user_credentials WHERE user_id=?""",
            (user_id,)
        )
        row = c.fetchone()
        conn.close()

        if not row:
            return None

        dec_username = self.cipher_suite.decrypt(row[0]).decode("utf-8")
        dec_password = self.cipher_suite.decrypt(row[1]).decode("utf-8")
        return {
            "username": dec_username,
            "password": dec_password,
            "hint": row[2],
            "biometric_enabled": row[3]
        }

    def reset_password(self, user_id):
        """Generate a reset token and expiry for a user."""
        try:
            # Confirm user exists
            existing = self.retrieve_credentials(user_id)
            if not existing:
                self.logger.warning(f"No user found for {user_id}")
                return None

            reset_token = secrets.token_urlsafe(32)
            expiry = datetime.now() + timedelta(hours=24)
            # For demo, store token in 'hint' field. Not recommended for production.
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("UPDATE user_credentials SET hint=? WHERE user_id=?", (f"{reset_token}|{expiry}", user_id))
            conn.commit()
            conn.close()

            return {
                "token": reset_token,
                "expiry": expiry
            }
        except Exception as e:
            self.logger.error(f"Password reset failed: {e}")
            return None

    def verify_reset_token(self, user_id, token):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT hint FROM user_credentials WHERE user_id=?", (user_id,))
        row = c.fetchone()
        conn.close()

        if not row or not row[0]:
            return False

        stored = row[0].split("|")
        if len(stored) != 2:
            return False

        stored_token, expiry_str = stored
        try:
            expiry_time = datetime.fromisoformat(expiry_str)
        except ValueError:
            return False

        if token == stored_token and datetime.now() < expiry_time:
            return True
        return False
