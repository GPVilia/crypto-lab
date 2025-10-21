from src.crypto.signatures import (
    sign_message_rsa, verify_signature_rsa,
    sign_message_dsa, verify_signature_dsa,
    sign_message_ecdsa, verify_signature_ecdsa
)
from src.crypto.asymmetric import generate_rsa_keypair, generate_ecdh_keypair
from cryptography.hazmat.primitives.asymmetric import dsa


# === TESTE: RSA-PSS ===
print("🔏 Teste de Assinatura RSA-PSS")
priv_rsa, pub_rsa = generate_rsa_keypair()
mensagem_rsa = b"Mensagem assinada com RSA-PSS"
assinatura_rsa = sign_message_rsa(priv_rsa, mensagem_rsa)

print("Assinatura RSA:", assinatura_rsa[:24].hex(), "...")
print("✅ Válida?", verify_signature_rsa(pub_rsa, mensagem_rsa, assinatura_rsa))
print("❌ Alterada?", verify_signature_rsa(pub_rsa, b"Mensagem alterada", assinatura_rsa))


# === TESTE: DSA ===
print("\n🖊️ Teste de Assinatura DSA")
priv_dsa = dsa.generate_private_key(key_size=2048)
pub_dsa = priv_dsa.public_key()
mensagem_dsa = b"Mensagem assinada com DSA"
assinatura_dsa = sign_message_dsa(priv_dsa, mensagem_dsa)

print("Assinatura DSA:", assinatura_dsa[:24].hex(), "...")
print("✅ Válida?", verify_signature_dsa(pub_dsa, mensagem_dsa, assinatura_dsa))
print("❌ Alterada?", verify_signature_dsa(pub_dsa, b"Mensagem alterada", assinatura_dsa))


# === TESTE: ECDSA ===
print("\n⚡ Teste de Assinatura ECDSA")
priv_ecdsa, pub_ecdsa = generate_ecdh_keypair()  # função do módulo asymmetric
mensagem_ecdsa = b"Mensagem assinada com ECDSA"
assinatura_ecdsa = sign_message_ecdsa(priv_ecdsa, mensagem_ecdsa)

print("Assinatura ECDSA:", assinatura_ecdsa[:24].hex(), "...")
print("✅ Válida?", verify_signature_ecdsa(pub_ecdsa, mensagem_ecdsa, assinatura_ecdsa))
print("❌ Alterada?", verify_signature_ecdsa(pub_ecdsa, b"Mensagem alterada", assinatura_ecdsa))
