"""
Testes para o módulo de criptografia assimétrica.
"""

from src.crypto.asymmetric import (
    generate_rsa_keypair,
    encrypt_rsa,
    decrypt_rsa,
    generate_ecdh_keypair
)
from cryptography.hazmat.primitives.asymmetric import ec

# === Teste: RSA ===
print("🔐 Teste RSA")
private_key, public_key = generate_rsa_keypair()

mensagem = "Mensagem secreta RSA !!".encode("utf-8")
cipher = encrypt_rsa(public_key, mensagem)
plain = decrypt_rsa(private_key, cipher)

print("Mensagem original:", mensagem)
print("Mensagem decifrada:", plain)
print("✅ Iguais?", mensagem == plain)

# === Teste: ECDH ===
print("\n🔑 Teste ECDH")
privA, pubA = generate_ecdh_keypair()
privB, pubB = generate_ecdh_keypair()

# Cada lado gera o mesmo segredo partilhado
shared1 = privA.exchange(ec.ECDH(), pubB)
shared2 = privB.exchange(ec.ECDH(), pubA)

print("Chave partilhada A:", shared1.hex()[:32], "...")
print("Chave partilhada B:", shared2.hex()[:32], "...")
print("✅ Iguais?", shared1 == shared2)
