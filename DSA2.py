import json
import logging
from datetime import datetime, timedelta, UTC
import os
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import CertificateBuilder, Name, NameOID, random_serial_number, NameAttribute
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import base64
from cryptography import x509

# Loglama Ayarları
LOG_FILE = "application.log"
LOG_JSON_FILE = "advanced_logs.json"
CERTIFICATE_VALIDITY_DAYS = 365

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Ortak Sertifika Bilgileri
CERTIFICATE_SUBJECT = issuer = Name([
    NameAttribute(NameOID.COUNTRY_NAME, "TR"),
    NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ankara"),
    NameAttribute(NameOID.LOCALITY_NAME, "Ankara"),
    NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
    NameAttribute(NameOID.COMMON_NAME, "test.com"),
])


# Loglama Fonksiyonu
def log_event(event_type, file_name=None, status="SUCCESS", details=None, error=None):
    log_data = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": event_type,
        "file_name": os.path.basename(file_name) if file_name else None,
        "status": status,
        "details": details,
        "error": str(error) if error else None
    }
    try:
      with open(LOG_JSON_FILE, "a") as json_file:
            json.dump(log_data, json_file, indent=4)
            json_file.write(",\n")
    except Exception as e:
        logging.error(f"JSON log dosyasına yazılırken hata oluştu: {e}")
    if status == "SUCCESS":
        logging.info(f"{event_type} - File: {os.path.basename(file_name) if file_name else 'N/A'} - {details}")
    elif status == "ERROR":
        logging.error(f"{event_type} - File: {os.path.basename(file_name) if file_name else 'N/A'} - Error: {error}")


# 1. Dosyadan Veri Okuma
def read_file(file_path):
    try:
        with open(file_path, "rb") as file:
            data = file.read()
        log_event("FILE_READ", file_name=file_path, status="SUCCESS", details="Dosya başarıyla okundu.")
        return data
    except FileNotFoundError as e:
         log_event("FILE_READ", file_name=file_path, status="ERROR", error=e)
         raise FileNotFoundError(f"Dosya bulunamadı: {file_path}") from e
    except Exception as e:
        log_event("FILE_READ", file_name=file_path, status="ERROR", error=e)
        raise Exception(f"Dosya okunurken hata oluştu: {e}") from e

# 2. DSA Anahtar Çifti Oluşturma
def generate_keys():
    private_key = dsa.generate_private_key(key_size=2048)
    public_key = private_key.public_key()
    log_event("KEY_GENERATION", status="SUCCESS", details="DSA anahtar çifti oluşturuldu.")
    return private_key, public_key


# 3. Sertifika Oluşturma
def generate_certificate(private_key, public_key):
    certificate = (
        CertificateBuilder()
        .subject_name(CERTIFICATE_SUBJECT)
        .issuer_name(CERTIFICATE_SUBJECT)
        .public_key(public_key)
        .serial_number(random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=CERTIFICATE_VALIDITY_DAYS))
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    log_event("CERTIFICATE_CREATION", status="SUCCESS", details="X.509 sertifikası oluşturuldu.")
    return certificate


# 4. Private Key Şifreleme ve Kaydetme
def save_encrypted_private_key(private_key, file_path, password):
     try:
        salt = secrets.token_bytes(16)
        key = _derive_key(password, salt)
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_key = encryptor.update(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )) + encryptor.finalize()
        with open(file_path, "wb") as file:
            file.write(salt)
            file.write(iv)
            file.write(encrypted_key)
        log_event("KEY_SAVE", file_name=file_path, status="SUCCESS", details="Şifreli private key başarıyla kaydedildi.")
     except Exception as e:
         log_event("KEY_SAVE", file_name=file_path, status="ERROR", error=e)
         raise Exception(f"Şifreli private key kaydedilirken hata oluştu: {e}") from e

# 5. Şifreli Private Key'i Çözme
def load_encrypted_private_key(file_path, password):
    try:
        with open(file_path, "rb") as file:
            salt = file.read(16)
            iv = file.read(16)
            encrypted_key = file.read()
        key = _derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_key = decryptor.update(encrypted_key) + decryptor.finalize()
        private_key = serialization.load_pem_private_key(decrypted_key, password=None, backend=default_backend())
        log_event("KEY_LOAD", file_name=file_path, status="SUCCESS", details="Şifreli private key başarıyla yüklendi.")
        return private_key
    except Exception as e:
        log_event("KEY_LOAD", file_name=file_path, status="ERROR", error=e)
        raise Exception(f"Şifreli private key yüklenirken hata oluştu: {e}") from e


# 6. Şifreleme Anahtarı Türetme (KDF)
def _derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key


# 7. Dosya İmzalama (Zaman Damgası Eklendi)
def sign_file(private_key, data, file_name):
      try:
         ts_content = f"timestamp:{datetime.now(UTC).isoformat()}".encode()
         signature = private_key.sign(ts_content + data, hashes.SHA256())
         log_event("FILE_SIGNING", file_name=file_name, status="SUCCESS", details="Dosya başarıyla imzalandı.")
         return signature, ts_content
      except Exception as e:
          log_event("FILE_SIGNING", file_name=file_name, status="ERROR", error=e)
          raise Exception(f"Dosya imzalama hatası: {e}") from e


# 8. İmza Doğrulama (Zaman Damgası Kontrolü)
def verify_signature_with_cert(file_data, signature, certificate_pem, file_name, ts_content):
    try:
        certificate = load_pem_x509_certificate(certificate_pem.encode(), default_backend())
        public_key = certificate.public_key()
        public_key.verify(signature,ts_content + file_data, hashes.SHA256())
        log_event("SIGNATURE_VERIFICATION", file_name=file_name, status="SUCCESS", details="İmza doğrulandı.")
        print("İmza doğrulandı: Dosya geçerli!")
        return True
    except Exception as e:
        log_event("SIGNATURE_VERIFICATION", file_name=file_name, status="ERROR", error=e)
        print(f"İmza doğrulama başarısız: {e}")
        return False


# Ana Program (Test Amaçlı)
if __name__ == "__main__":
    file_path = "empty_file.pdf"
    password = "my_secret_password" # test password
    try:
        file_data = read_file(file_path)
        private_key, public_key = generate_keys()
        certificate = generate_certificate(private_key, public_key)
        save_encrypted_private_key(private_key,"encrypted_key.pem", password)
        loaded_private_key = load_encrypted_private_key("encrypted_key.pem", password)
        signature, ts_content = sign_file(loaded_private_key, file_data, file_path)
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
        print("\nSertifika PEM Formatı:\n", certificate_pem)
        print("\nDoğrulama işlemi başlatılıyor...")
        verify_signature_with_cert(file_data, signature, certificate_pem, file_path, ts_content)

    except Exception as e:
        log_event("PROGRAM_ERROR", file_name=file_path, status="ERROR", error=e)
        print("Bir hata oluştu, logları kontrol edin.")