# Assinaturas digitais (RSA-PSS, DSA, ECDSA)

# RSA-PSS é um esquema de assinatura digital baseado em RSA que utiliza o padrão PSS (Probabilistic Signature Scheme) para fornecer segurança adicional contra certos tipos de ataques. Ele é amplamente utilizado devido à sua robustez e segurança.
# DSA (Digital Signature Algorithm) é um padrão de assinatura digital que utiliza a criptografia de chave pública para garantir a autenticidade e integridade dos dados. É frequentemente usado em aplicações governamentais e comerciais.
# ECDSA (Elliptic Curve Digital Signature Algorithm) é um esquema de assinatura digital baseado em curvas elípticas, oferecendo níveis equivalentes de segurança com chaves menores em comparação com RSA e DSA, o que resulta em melhor desempenho.

from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


# === 1️⃣ RSA-PSS ===
def sign_message_rsa(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Assina dados usando RSA-PSS (SHA-256).
    Args:
        private_key (rsa.RSAPrivateKey): Chave privada RSA usada para assinar.
        data (bytes): Dados a assinar.
    Returns:
        bytes: Assinatura gerada.
    """
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_signature_rsa(public_key: rsa.RSAPublicKey, data: bytes, signature: bytes) -> bool:
    """
    Verifica uma assinatura RSA-PSS (SHA-256).
    Args:
        public_key (rsa.RSAPublicKey): Chave pública RSA usada para verificar.
        data (bytes): Dados originais.
        signature (bytes): Assinatura a verificar.
    Returns:
        bool: True se for válida, False caso contrário.
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


# === 2️⃣ DSA ===
def sign_message_dsa(private_key: dsa.DSAPrivateKey, data: bytes) -> bytes:
    """
    Assina dados usando DSA (SHA-256).
    Args:
        private_key (dsa.DSAPrivateKey): Chave privada DSA usada para assinar.
        data (bytes): Dados a assinar.
    Returns:
        bytes: Assinatura gerada.
    """
    return private_key.sign(data, hashes.SHA256())


def verify_signature_dsa(public_key: dsa.DSAPublicKey, data: bytes, signature: bytes) -> bool:
    """
    Verifica uma assinatura DSA (SHA-256).
    Args:
        public_key (dsa.DSAPublicKey): Chave pública DSA usada para verificar.
        data (bytes): Dados originais.
        signature (bytes): Assinatura a verificar.
    Returns:
        bool: True se for válida, False caso contrário.
    """
    try:
        public_key.verify(signature, data, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


# === 3️⃣ ECDSA ===
def sign_message_ecdsa(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """
    Assina dados usando ECDSA (SHA-256).
    Args:
        private_key (ec.EllipticCurvePrivateKey): Chave privada ECDSA usada para assinar.
        data (bytes): Dados a assinar.
    Returns:
        bytes: Assinatura gerada.
    """
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify_signature_ecdsa(public_key: ec.EllipticCurvePublicKey, data: bytes, signature: bytes) -> bool:
    """
    Verifica uma assinatura ECDSA (SHA-256).
    Args:
        public_key (ec.EllipticCurvePublicKey): Chave pública ECDSA usada para verificar.
        data (bytes): Dados originais.
        signature (bytes): Assinatura a verificar.
    Returns:
        bool: True se for válida, False caso contrário.
    """
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
