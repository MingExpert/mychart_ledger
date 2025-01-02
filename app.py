import sys
import os
import sqlite3
import secrets
import logging
from datetime import datetime, timedelta

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QFrame,
    QPushButton, QLabel, QLineEdit, QMessageBox, QInputDialog,
    QSizePolicy
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QPixmap
from cryptography.fernet import Fernet

# -------------------------------------------------------------------
#                     Minimal Ledger Backend
# -------------------------------------------------------------------
class LedgerBackend:
    """
    Basic credential storage + password reset in SQLite,
    with encryption via Fernet.
    """
    def __init__(self, db_path="secure_ledger.db"):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("LedgerBackend")

        # For production, store the key somewhere safer than in-memory!
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
        """
        Insert or replace a user’s credentials (encrypted).
        """
        enc_username = self.cipher_suite.encrypt(username.encode("utf-8"))
        enc_password = self.cipher_suite.encrypt(password.encode("utf-8"))

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
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
        Return {username, password, hint, biometric_enabled} or None if not found.
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            SELECT encrypted_username, encrypted_password, hint, biometric_enabled
            FROM user_credentials WHERE user_id=?
        ''', (user_id,))
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
        """
        Generate a reset token/expiry and store it in 'hint' for demo.
        """
        # Check if user exists first
        creds = self.retrieve_credentials(user_id)
        if not creds:
            self.logger.warning(f"No user found for {user_id}")
            return None

        try:
            reset_token = secrets.token_urlsafe(32)
            expiry = datetime.now() + timedelta(hours=24)

            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('''
                UPDATE user_credentials
                SET hint=?
                WHERE user_id=?
            ''', (f"{reset_token}|{expiry}", user_id))
            conn.commit()
            conn.close()

            return {"token": reset_token, "expiry": expiry}
        except Exception as e:
            self.logger.error(f"Password reset failed: {e}")
            return None

    def verify_reset_token(self, user_id, token):
        """
        Example usage, not integrated in the UI above:
        Check if a stored token matches and not expired.
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            SELECT hint FROM user_credentials WHERE user_id=?
        ''', (user_id,))
        row = c.fetchone()
        conn.close()

        if not row or not row[0]:
            return False

        stored_hint = row[0]
        if '|' not in stored_hint:
            return False

        stored_token, expiry_str = stored_hint.split('|', 1)
        try:
            expiry_time = datetime.fromisoformat(expiry_str)
        except ValueError:
            return False

        if token == stored_token and datetime.now() < expiry_time:
            return True
        return False


# -------------------------------------------------------------------
#                   PyQt Kiosk-Style UI
# -------------------------------------------------------------------
class MyChartLedgerKiosk(QWidget):
    """
    A kiosk-like UI:
     - Uses a background image (prelogin.png).
     - Loads a logo (logo.png).
     - Fullscreen mode (press Esc or click "Exit Fullscreen" to leave).
     - Large text, user-friendly for seniors.
    """
    def __init__(self, backend: LedgerBackend):
        super().__init__()
        self.backend = backend
        self.setWindowTitle("MyChart Ledger Kiosk")

        # We'll define absolute paths to our images to avoid path issues.
        SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
        self.BACKGROUND_IMAGE_PATH = os.path.join(SCRIPT_DIR, "images", "prelogin.png")
        self.LOGO_IMAGE_PATH       = os.path.join(SCRIPT_DIR, "images", "logo.png")

        self.init_ui()
        self.apply_styles()
        self.showFullScreen()  # Kiosk mode

    def init_ui(self):
        # Outer layout
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Background frame
        self.bg_frame = QFrame()
        self.bg_frame.setObjectName("BackgroundFrame")

        # We'll create everything in a V layout with spacing.
        frame_layout = QVBoxLayout()
        frame_layout.setContentsMargins(40, 40, 40, 40)
        frame_layout.setSpacing(20)

        # Top row: logo + title
        top_row = QHBoxLayout()
        top_row.setSpacing(20)

        self.logo_label = QLabel()
        # Load the logo, if it fails, no crash—just no pixmap
        logo_pix = QPixmap(self.LOGO_IMAGE_PATH)
        if not logo_pix.isNull():
            # scale to a decent size
            scaled_logo = logo_pix.scaled(200, 200, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.logo_label.setPixmap(scaled_logo)

        top_row.addWidget(self.logo_label, alignment=Qt.AlignLeft | Qt.AlignVCenter)

        self.title_label = QLabel("MyChart Ledger")
        self.title_label.setObjectName("titleLabel")
        self.title_label.setAlignment(Qt.AlignCenter)
        top_row.addWidget(self.title_label, stretch=1, alignment=Qt.AlignCenter)

        frame_layout.addLayout(top_row)

        # Username field
        self.username_field = QLineEdit()
        self.username_field.setObjectName("loginField")
        self.username_field.setPlaceholderText("Username")
        self._make_expanding(self.username_field, min_height=50)
        frame_layout.addWidget(self.username_field)

        # Password field
        self.password_field = QLineEdit()
        self.password_field.setObjectName("loginField")
        self.password_field.setPlaceholderText("Password")
        self.password_field.setEchoMode(QLineEdit.Password)
        self._make_expanding(self.password_field, min_height=50)
        frame_layout.addWidget(self.password_field)

        # Button row: Login + Forgot Password
        btn_row = QHBoxLayout()
        btn_row.setSpacing(15)

        self.login_btn = QPushButton("Login")
        self.login_btn.setObjectName("mainButton")
        self._make_expanding(self.login_btn, min_height=60)
        self.login_btn.clicked.connect(self.login_action)
        btn_row.addWidget(self.login_btn, stretch=1)

        self.reset_btn = QPushButton("Forgot Password?")
        self.reset_btn.setObjectName("secondaryButton")
        self._make_expanding(self.reset_btn, min_height=60)
        self.reset_btn.clicked.connect(self.reset_action)
        btn_row.addWidget(self.reset_btn, stretch=1)

        frame_layout.addLayout(btn_row)

        # Additional buttons
        self.auto_login_btn = QPushButton("Auto Login (No Typing)")
        self.auto_login_btn.setObjectName("mainButton")
        self._make_expanding(self.auto_login_btn, min_height=60)
        self.auto_login_btn.clicked.connect(self.auto_login)
        frame_layout.addWidget(self.auto_login_btn)

        self.reveal_btn = QPushButton("Show My Credentials")
        self.reveal_btn.setObjectName("secondaryButton")
        self._make_expanding(self.reveal_btn, min_height=60)
        self.reveal_btn.clicked.connect(self.reveal_credentials)
        frame_layout.addWidget(self.reveal_btn)

        self.help_btn = QPushButton("Help")
        self.help_btn.setObjectName("secondaryButton")
        self._make_expanding(self.help_btn, min_height=60)
        self.help_btn.clicked.connect(self.help_action)
        frame_layout.addWidget(self.help_btn)

        # Exit Fullscreen
        self.exit_btn = QPushButton("Exit Fullscreen")
        self.exit_btn.setObjectName("exitButton")
        self._make_expanding(self.exit_btn, min_height=60)
        self.exit_btn.clicked.connect(self.exit_kiosk)
        frame_layout.addWidget(self.exit_btn)

        self.bg_frame.setLayout(frame_layout)
        main_layout.addWidget(self.bg_frame)
        self.setLayout(main_layout)

    def apply_styles(self):
        """
        Style sheet referencing the background and setting fonts/colors.
        """
        # Convert path to forward slashes for Qt
        bg_path = self.BACKGROUND_IMAGE_PATH.replace("\\","/")
        style_sheet = f"""
            #BackgroundFrame {{
                background-image: url('{bg_path}');
                background-repeat: no-repeat;
                background-position: center;
                background-attachment: fixed;
                background-color: #002f55; /* fallback color if image fails */
            }}

            QWidget {{
                color: #ffffff;
                font-family: Arial, sans-serif;
                font-size: 24px;
                background-color: transparent;
            }}

            QLabel#titleLabel {{
                font-size: 50px;
                font-weight: bold;
            }}

            QLineEdit#loginField {{
                background-color: #ffffff;
                color: #000000;
                border: 2px solid #cccccc;
                border-radius: 8px;
                padding: 10px;
                font-size: 22px;
            }}
            QLineEdit#loginField:focus {{
                border: 2px solid #ffcc00;
            }}

            QPushButton {{
                border: none;
                border-radius: 8px;
                margin: 0px;
                padding: 15px 20px;
            }}
            QPushButton#mainButton {{
                background-color: #2ecc71;
                color: #ffffff;
                font-size: 26px;
            }}
            QPushButton#mainButton:hover {{
                background-color: #27ae60;
            }}
            QPushButton#mainButton:pressed {{
                background-color: #1e8449;
            }}

            QPushButton#secondaryButton {{
                background-color: #3498db;
                color: #ffffff;
                font-size: 24px;
            }}
            QPushButton#secondaryButton:hover {{
                background-color: #2980b9;
            }}
            QPushButton#secondaryButton:pressed {{
                background-color: #1f5a7e;
            }}

            QPushButton#exitButton {{
                background-color: #e74c3c;
                color: #ffffff;
                font-size: 24px;
            }}
            QPushButton#exitButton:hover {{
                background-color: #c0392b;
            }}
            QPushButton#exitButton:pressed {{
                background-color: #962d22;
            }}
        """
        self.setStyleSheet(style_sheet)

    # Press Esc to exit fullscreen
    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.showNormal()

    def exit_kiosk(self):
        self.showNormal()

    # Utility: Make widget expand horizontally, with a fixed min height
    def _make_expanding(self, widget, min_height=60):
        size_policy = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        widget.setSizePolicy(size_policy)
        widget.setMinimumHeight(min_height)

    # -----------------------------
    # Button Handlers (login, reset)
    # -----------------------------
    def login_action(self):
        username = self.username_field.text().strip()
        password = self.password_field.text().strip()
        if not username or not password:
            QMessageBox.warning(self, "Login Failed", "Please enter your username and password.")
            return

        creds = self.backend.retrieve_credentials(username)
        if not creds:
            QMessageBox.warning(self, "Login Failed", f"User '{username}' does not exist.")
            return

        if creds["password"] == password:
            QMessageBox.information(self, "Login Successful", "Welcome to MyChart Ledger!")
        else:
            QMessageBox.warning(self, "Login Failed", "Incorrect password. Please try again.")

    def reset_action(self):
        user_id, ok = QInputDialog.getText(self, "Password Reset", "Enter your username:")
        if not ok or not user_id:
            return
        reset_info = self.backend.reset_password(user_id)
        if reset_info:
            token = reset_info["token"]
            expiry = reset_info["expiry"]
            QMessageBox.information(
                self,
                "Reset Token",
                f"Token: {token}\nExpires: {expiry}\nUse it to reset your password."
            )
        else:
            QMessageBox.warning(self, "Reset Failed", f"Could not generate reset token for '{user_id}'.")

    def auto_login(self):
        # Hard-coded user for demonstration
        known_user = "elder1"
        creds = self.backend.retrieve_credentials(known_user)
        if creds:
            QMessageBox.information(
                self, "Auto Login",
                f"Auto-logging in as {known_user}. Password is: {creds['password']}"
            )
        else:
            QMessageBox.warning(
                self, "Auto Login",
                f"No stored credentials found for '{known_user}'."
            )

    def reveal_credentials(self):
        user_id, ok = QInputDialog.getText(self, "Reveal Credentials", "Enter your username:")
        if not ok or not user_id:
            return
        creds = self.backend.retrieve_credentials(user_id)
        if not creds:
            QMessageBox.warning(self, "Not Found", f"No credentials found for '{user_id}'.")
            return
        msg = f"Username: {creds['username']}\nPassword: {creds['password']}"
        QMessageBox.information(self, "Your Credentials", msg)

    def help_action(self):
        help_text = (
            "Need help logging in?\n"
            "Call Bozeman Health support at: 1-800-123-4567\n\n"
            "Or ask a caregiver to assist you."
        )
        QMessageBox.information(self, "Help", help_text)


# -------------------------------------------------------------------
#                      Main Entry Point
# -------------------------------------------------------------------
def main():
    app = QApplication(sys.argv)

    # Initialize the backend
    backend = LedgerBackend()

    # (Optional) Seed the database with a user for testing:
    # backend.store_credentials("elder1", "elder1", "mypassword123")

    window = MyChartLedgerKiosk(backend)
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
