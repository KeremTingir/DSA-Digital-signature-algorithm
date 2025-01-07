import sys
import os
import json
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QFileDialog, QTextEdit, QLabel, QVBoxLayout, QWidget, QMessageBox, QInputDialog
)
from DSA2 import generate_keys, generate_certificate, sign_file, read_file, log_event, save_encrypted_private_key, load_encrypted_private_key
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import load_pem_x509_certificate

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DSA Anahtar ve Sertifika Arayüzü")
        self.setGeometry(200, 200, 800, 600)

        # Widget'lar
        self.file_label = QLabel("Seçilen Dosya: Henüz seçilmedi")
        self.key_label = QLabel("Anahtar: Henüz oluşturulmadı")
        self.cert_label = QLabel("Sertifika: Henüz oluşturulmadı")

        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)

        self.select_file_button = QPushButton("Dosya Seç")
        self.select_file_button.clicked.connect(self.select_file)

        self.key_cert_button = QPushButton("Anahtar ve Sertifika Oluştur")
        self.key_cert_button.clicked.connect(self.create_key_and_cert)

        self.sign_file_button = QPushButton("Dosyayı İmzala")
        self.sign_file_button.clicked.connect(self.sign_file)

        self.verify_file_button = QPushButton("İmzayı Doğrula")
        self.verify_file_button.clicked.connect(self.verify_file)

        self.view_key_button = QPushButton("Anahtarı Görüntüle")
        self.view_key_button.clicked.connect(self.view_key)

        self.view_cert_button = QPushButton("Sertifikayı Görüntüle")
        self.view_cert_button.clicked.connect(self.view_cert)

        self.view_logs_button = QPushButton("Logları Görüntüle")
        self.view_logs_button.clicked.connect(self.view_logs)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.file_label)
        layout.addWidget(self.key_label)
        layout.addWidget(self.cert_label)
        layout.addWidget(self.text_area)
        layout.addWidget(self.select_file_button)
        layout.addWidget(self.key_cert_button)
        layout.addWidget(self.sign_file_button)
        layout.addWidget(self.verify_file_button)
        layout.addWidget(self.view_key_button)
        layout.addWidget(self.view_cert_button)
        layout.addWidget(self.view_logs_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        # Değişkenler
        self.file_path = None
        self.private_key = None
        self.public_key = None
        self.certificate = None
        self.timestamp_content = None

    def select_file(self):
        self.file_path, _ = QFileDialog.getOpenFileName(self, "Dosya Seç", "", "Tüm Dosyalar (*)")
        if self.file_path:
            self.file_label.setText(f"Seçilen Dosya: {os.path.basename(self.file_path)}")
            self.clear_text_area()

    def create_key_and_cert(self):
        try:
            self.private_key, self.public_key = generate_keys()
            self.certificate = generate_certificate(self.private_key, self.public_key)
            self.save_key_and_cert()
            self.key_label.setText("Anahtar: encrypted_key.pem kaydedildi")
            self.cert_label.setText("Sertifika: certificate.pem kaydedildi")
            QMessageBox.information(self, "Başarılı", "Anahtar ve sertifika başarıyla oluşturuldu ve kaydedildi!")
        except Exception as e:
             QMessageBox.critical(self, "Hata", f"Anahtar ve sertifika oluşturulurken hata oluştu: {e}")
             self.log_error("Anahtar ve sertifika oluşturma hatası", e)

    def save_key_and_cert(self):
        password, ok = QInputDialog.getText(self, 'Parola Gerekli', 'Lütfen private key\'i şifrelemek için bir parola girin:')
        if ok and password:
          try:
             save_encrypted_private_key(self.private_key,"encrypted_key.pem", password)
             with open("certificate.pem", "wb") as cert_file:
                cert_file.write(self.certificate.public_bytes(serialization.Encoding.PEM))
          except Exception as e:
             QMessageBox.critical(self, "Hata", f"Anahtar ve sertifika dosyaya kaydedilirken hata oluştu: {e}")
             self.log_error("Anahtar ve sertifika kaydetme hatası", e)

    def sign_file(self):
       if not self.file_path:
            QMessageBox.warning(self, "Uyarı", "Lütfen önce bir dosya seçin.")
            return
       try:
            password, ok = QInputDialog.getText(self, 'Parola Gerekli', 'İmzalama için private key parolasını girin:')
            if ok and password:
                loaded_private_key = load_encrypted_private_key("encrypted_key.pem", password)
                with open(self.file_path, "rb") as f:
                    file_data = f.read()
                signature, ts_content = sign_file(loaded_private_key, file_data, self.file_path)
                self.timestamp_content = ts_content
                with open("signature.sig", "wb") as sig_file:
                    sig_file.write(signature)
                with open("timestamp.ts", "wb") as ts_file:
                    ts_file.write(ts_content)
                QMessageBox.information(self, "Başarılı", "Dosya başarıyla imzalandı ve signature.sig dosyasına kaydedildi!")
       except Exception as e:
              QMessageBox.critical(self, "Hata", f"Dosya imzalama hatası: {e}")
              self.log_error("Dosya imzalama hatası", e)

    def verify_file(self):
        if not self.file_path:
            QMessageBox.warning(self, "Uyarı", "Lütfen önce bir dosya seçin.")
            return
        
        signature_file_path, _ = QFileDialog.getOpenFileName(self, "İmza Dosyası Seç", "", "İmza Dosyaları (*.sig)")
        if not signature_file_path:
            QMessageBox.warning(self, "Uyarı", "Lütfen bir imza dosyası seçin.")
            return
        
        timestamp_file_path, _ = QFileDialog.getOpenFileName(self, "Zaman Damgası Dosyası Seç", "", "Zaman Damgası Dosyaları (*.ts)")
        if not timestamp_file_path:
            QMessageBox.warning(self, "Uyarı", "Lütfen bir zaman damgası dosyası seçin.")
            return

        try:
            with open("certificate.pem", "rb") as cert_file:
                cert = load_pem_x509_certificate(cert_file.read())
            with open(signature_file_path, "rb") as sig_file:
                signature = sig_file.read()
            with open(timestamp_file_path, "rb") as ts_file:
                ts_content = ts_file.read()
            with open(self.file_path, "rb") as f:
                file_data = f.read()
            if self.timestamp_content != ts_content:
                QMessageBox.critical(self, "Hata", f"Zaman damgası doğrulanamadı.")
            cert.public_key().verify(signature, ts_content + file_data, hashes.SHA256())
            QMessageBox.information(self, "Başarılı", "Dosya doğrulandı: İmza geçerli!")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Doğrulama başarısız: {e}")
            self.log_error("Dosya doğrulama hatası", e)


    def view_key(self):
        try:
            password, ok = QInputDialog.getText(self, 'Parola Gerekli', 'Private key parolasını girin:')
            if ok and password:
                loaded_private_key = load_encrypted_private_key("encrypted_key.pem", password)
                # Private key'i PEM formatına dönüştür ve metin olarak göster
                pem_key = loaded_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode()
                self.text_area.setText(pem_key)
        except FileNotFoundError as e:
            QMessageBox.warning(self, "Uyarı", f"Anahtar dosyası bulunamadı: {e}")
            self.log_error("Anahtar görüntüleme hatası", e)
        except Exception as e:
            QMessageBox.warning(self, "Uyarı", f"Anahtar görüntülenemedi: {e}")
            self.log_error("Anahtar görüntüleme hatası", e)


    def view_cert(self):
          try:
              with open("certificate.pem", "r") as cert_file:
                  content = cert_file.read()
              self.text_area.setText(content)
          except FileNotFoundError as e:
                QMessageBox.warning(self, "Uyarı", f"Sertifika dosyası bulunamadı: {e}")
                self.log_error("Sertifika görüntüleme hatası", e)
          except Exception as e:
              QMessageBox.warning(self, "Uyarı", f"Sertifika görüntülenemedi: {e}")
              self.log_error("Sertifika görüntüleme hatası", e)

    def view_logs(self):
         try:
             with open("application.log", "r") as log_file:
                 content = log_file.read()
             self.text_area.setText(content)
         except FileNotFoundError as e:
              QMessageBox.warning(self, "Uyarı", f"Log dosyası bulunamadı: {e}")
              self.log_error("Log görüntüleme hatası", e)
         except Exception as e:
              QMessageBox.warning(self, "Uyarı", f"Loglar görüntülenemedi: {e}")
              self.log_error("Log görüntüleme hatası", e)

    def clear_text_area(self):
        self.text_area.clear()

    def log_error(self, message, error):
          log_event("UI_ERROR", status="ERROR", details=message, error=error)
          print(f"Error: {message} - {error}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())