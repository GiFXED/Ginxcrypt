# File Encryption Script v1.0
# Author: GiFXED

# Variables
import base64
import sys
import os
import hashlib
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QFileDialog, QTextEdit, QMessageBox
import qdarkstyle

def generate_fernet_key(key_text):
    sha256 = hashlib.sha256()
    sha256.update(key_text.encode())
    key = base64.urlsafe_b64encode(sha256.digest())
    return key

# Function Table
functions = {
    'generate_fernet_key': generate_fernet_key,
}

class EncryptionApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
    
    def initUI(self):
        self.setWindowTitle("Ginxcrypt")
        self.setGeometry(100, 100, 600, 400)

        self.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())

        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout()

        self.key_label = QLabel("Enter a key of at least 64 characters:")
        self.key_input = QTextEdit()
        self.layout.addWidget(self.key_label)
        self.layout.addWidget(self.key_input)

        self.encrypt_button = QPushButton("Encrypt File")
        self.decrypt_button = QPushButton("Decrypt File")
        self.layout.addWidget(self.encrypt_button)
        self.layout.addWidget(self.decrypt_button)

        self.log_label = QLabel("Log:")
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.layout.addWidget(self.log_label)
        self.layout.addWidget(self.log_output)

        self.encrypt_button.clicked.connect(self.encrypt_file)
        self.decrypt_button.clicked.connect(self.decrypt_file)

        self.central_widget.setLayout(self.layout)

    def encrypt_file(self):
        key_text = self.key_input.toPlainText()
        key = functions['generate_fernet_key'](key_text)

        if len(key) != 44:  # Check if the key is valid
            self.log_output.append("Key length must be at least 64 characters.")
            return

        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if not file_path:
            return

        try:
            with open(file_path, 'rb') as file:
                data = file.read()

            random_bytes = os.urandom(128)
            data = random_bytes + data

            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(data)

            encrypted_file_path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted File", file_path + ".TEEM")
            if not encrypted_file_path:
                return

            with open(encrypted_file_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_data)

            key_file_path = encrypted_file_path + ".key"
            functions['generate_fernet_key'](key_text)
            with open(key_file_path, 'wb') as key_file:
                key_file.write(key)

            self.log_output.append(f"File '{file_path}' encrypted as '{encrypted_file_path}' and key saved as '{key_file_path}'")

        except Exception as e:
            self.log_output.append(f"Error during encryption: {str(e)}")

    def decrypt_file(self):
        key_text = self.key_input.toPlainText()
        key = functions['generate_fernet_key'](key_text)

        if len(key) != 44:
            self.log_output.append("Key length must be at least 64 characters.")
            return

        encrypted_file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt")
        if not encrypted_file_path:
            return

        key_file_path, _ = QFileDialog.getOpenFileName(self, "Select Key File for Decryption")
        if not key_file_path:
            return

        try:
            with open(key_file_path, 'rb') as key_file:
                key = key_file.read()

            with open(encrypted_file_path, 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()

            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data)

            original_data = decrypted_data[128:]

            original_file_path, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File", encrypted_file_path[:-5])
            if not original_file_path:
                return

            with open(original_file_path, 'wb') as original_file:
                original_file.write(original_data)

            self.log_output.append(f"File '{encrypted_file_path}' decrypted to '{original_file_path}'")

        except Exception as e:
            self.log_output.append(f"Error during decryption: {str(e)}")

def main():
    app = QApplication(sys.argv)
    window = EncryptionApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
