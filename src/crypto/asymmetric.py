# RSA, ECDH, etc...

# RSA é um sistema de cifragem assimétrica que funciona com um par de chaves: uma chave pública para cifragem e uma chave privada para decifragem. 

# ECDH (Elliptic Curve Diffie-Hellman) é um método/protocolo de troca de chaves que permite a duas partes gerar uma chave secreta partilhada utilizando as chaves privadas e as chaves públicas uma da outra.

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes

# RSA Key Generation
def generate_rsa_keypair(key_size: int = 2048) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Gera um par de chaves RSA.
    Args:
        key_size (int): O tamanho da chave em bits. Padrão é 2048 bits.
    Returns:
        tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]: O par de chaves gerado.
    """
    
    # Gera uma chave privada RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537, # Valor padrão recomendado
        key_size=key_size, # Tamanho da chave em bits
    )
    # Gera a chave pública correspondente
    public_key = private_key.public_key()
    return private_key, public_key

# ECDH Key Generation
def generate_ecdh_keypair(curve: ec.EllipticCurve = ec.SECP256R1()) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """
    Gera um par de chaves ECDH usando a curva elíptica especificada.
    Args:
        curve (ec.EllipticCurve): A curva elíptica a ser usada. Padrão é SECP256R1.
    Returns:
        tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]: O par de chaves gerado.
    """

    # Gera uma chave privada ECDH e a chave pública correspondente
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    return private_key, public_key

# RSA Encryption
def encrypt_rsa(public_key : rsa.RSAPublicKey, plaintext : bytes) -> bytes:
    """
    Cifra dados usando RSA com a chave pública fornecida.
    Args:
        public_key (rsa.RSAPublicKey): A chave pública RSA usada para a cifragem.
        plaintext (bytes): Os dados em texto simples a serem cifrados.
    Returns:
        bytes: Os dados cifrados.
    """
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# RSA Decryption
def decrypt_rsa(private_key : rsa.RSAPrivateKey, ciphertext : bytes) -> bytes:
    """
    Descriptografa dados cifrados com RSA usando a chave privada fornecida.
    Args:
        private_key (rsa.RSAPrivateKey): A chave privada RSA usada para a descriptografia.
        ciphertext (bytes): Os dados cifrados a serem descriptografados.
    Returns:
        bytes: Os dados em texto simples descriptografados.
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext