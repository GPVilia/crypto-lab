"""
Testes de hashing (hashes e HMAC)
"""
from src.crypto.hashing import hash_data, hash_file, hmac_data
import os
import shutil


# === TESTE: HASH DE TEXTO ===
print("🧠 Teste de hash de texto")
mensagem = "Criptografia e segurança!!".encode("utf-8")

hash_md5 = hash_data(mensagem, "md5")
hash_sha256 = hash_data(mensagem, "sha256")
hash_sha3_512 = hash_data(mensagem, "sha3_512")

print(f"MD5:       {hash_md5.hex()}")
print(f"SHA-256:   {hash_sha256.hex()}")
print(f"SHA3-512:  {hash_sha3_512.hex()}")


# === TESTE: HASH DE FICHEIRO ===
print("\n📄 Teste de hash de ficheiro")
# cria um ficheiro temporário
TMP_DIR = os.path.join("src", "tests", "tmp")
file_path = os.path.join(TMP_DIR, "teste_hash.txt")

os.makedirs(TMP_DIR, exist_ok=True)

try:
    with open(file_path, "w", encoding="utf-8") as f:
        f.write("dados de teste para hash de ficheiro")

    file_hash = hash_file(file_path, "sha256")
    print(f"SHA-256 (ficheiro): {file_hash}")

    # === TESTE: HMAC ===
    print("\n🔑 Teste de HMAC")
    key = os.urandom(32)
    mensagem_hmac = b"Mensagem autenticada com chave secreta"
    hmac_code = hmac_data(key, mensagem_hmac, "sha256")

    print(f"HMAC (SHA-256): {hmac_code.hex()}")

    # === VERIFICAÇÃO ===
    print("\n✅ Verificação de consistência")

    # Recalcula o mesmo HMAC para confirmar que é igual
    hmac_code_2 = hmac_data(key, mensagem_hmac, "sha256") # Recalcula o HMAC com a mesma chave e mensagem
    print("HMACs iguais?", hmac_code == hmac_code_2)

finally:
    # Limpa o temp dir
    try:
        if os.path.isdir(TMP_DIR):
            shutil.rmtree(TMP_DIR)
    except Exception as e:
        print(f"Falha ao remover diretório temporário {TMP_DIR}: {e}")
