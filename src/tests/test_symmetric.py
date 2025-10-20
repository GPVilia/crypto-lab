"""
Testes de criptografia simétrica (KDF, AES-GCM, 3DES-CBC)
"""

import os
from pathlib import Path

# Importa as funções do módulo crypto.symmetric
from src.crypto.symmetric import (
    derive_key,
    encrypt_file_aes,
    decrypt_file_aes,
    encrypt_file_3des,
    decrypt_file_3des
)

# === Diretório temporário para testes ===
BASE_DIR = Path(__file__).resolve().parent
TMP_DIR = BASE_DIR / "tmp"
TMP_DIR.mkdir(exist_ok=True)

# === Funções auxiliares ===
def write_temp_file(filename: str, content: str) -> Path:
    """Cria um ficheiro temporário com texto simples."""
    path = TMP_DIR / filename
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path

def read_file(path: Path) -> str:
    """Lê o conteúdo de um ficheiro de texto."""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

# === 1️⃣ Teste: Derivação de chave (Scrypt) ===
print("\n=== Teste: Derivação de chave (Scrypt) ===")
key, salt = derive_key("minha_password")
key2, salt2 = derive_key(b"minha_password")
key3, _ = derive_key("minha_password", salt)

print("Key:", key.hex())
print("Salt:", salt.hex())
print("Key2:", key2.hex())
print("Salt2:", salt2.hex())
print("Key3:", key3.hex())
print("✅ Iguais?", key == key3)

# === 2️⃣ Teste: AES-GCM ===
print("\n=== Teste: AES-GCM ===")

plain_path = write_temp_file("aes_plain.txt", "Mensagem secreta AES-GCM 🚀")
enc_path = TMP_DIR / "aes_encrypted.bin"
dec_path = TMP_DIR / "aes_decrypted.txt"

encrypt_file_aes(str(plain_path), str(enc_path), "password123")
decrypt_file_aes(str(enc_path), str(dec_path), "password123")

print("Conteúdo decifrado (AES):", read_file(dec_path))

# === 3️⃣ Teste: 3DES-CBC ===
print("\n=== Teste: 3DES-CBC ===")

plain_path_3des = write_temp_file("des_plain.txt", "Mensagem secreta 3DES 🔒")
enc_path_3des = TMP_DIR / "des_encrypted.bin"
dec_path_3des = TMP_DIR / "des_decrypted.txt"

encrypt_file_3des(str(plain_path_3des), str(enc_path_3des), "password123")
decrypt_file_3des(str(enc_path_3des), str(dec_path_3des), "password123")

print("Conteúdo decifrado (3DES):", read_file(dec_path_3des))

# === Limpeza opcional ===
# Apaga os ficheiros após os testes
import shutil
shutil.rmtree(TMP_DIR)