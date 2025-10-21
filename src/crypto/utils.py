# Funções utilitárias para criptografia


# === Leitura e escrita de ficheiros binários ===
def read_file_bytes(file_path: str) -> bytes:
    """
    Lê um ficheiro e retorna o seu conteúdo em bytes.
    Args:
        file_path (str): Caminho do ficheiro a ser lido.
    Returns:
        bytes: O conteúdo do ficheiro em bytes.
    """
    with open(file_path, 'rb') as f:
        return f.read()

def write_file_bytes(file_path: str, data: bytes):
    """
    Escreve dados em um ficheiro binário.
    Args:
        file_path (str): Caminho do ficheiro onde os dados serão escritos.
        data (bytes): Os dados em bytes a serem escritos no ficheiro.
    Returns:
        None
    """
    with open(file_path, 'wb') as f:
        f.write(data)

# === Conversões ===
import base64

def bytes_to_hex(data: bytes) -> str:
    """
    Converte bytes para uma string hexadecimal.
    Args:
        data (bytes): Os dados em bytes a serem convertidos.
    Returns:
        str: A string hexadecimal resultante.
    """
    return data.hex()

def hex_to_bytes(hex_str: str) -> bytes:
    """
    Converte uma string hexadecimal de volta para bytes.
    Args:
        hex_str (str): A string hexadecimal a ser convertida.
    Returns:
        bytes: Os dados decodificados em bytes.
    """
    return bytes.fromhex(hex_str)

def bytes_to_base64(data: bytes) -> str:
    """
    Converte bytes para uma string em base64.
    Args:
        data (bytes): Os dados em bytes a serem convertidos.
    Returns:
        str: A string em base64 resultante.
    """
    return base64.b64encode(data).decode('utf-8')

def base64_to_bytes(base64_str: str) -> bytes:
    """
    Converte uma string em base64 de volta para bytes.
    Args:
        base64_str (str): A string em base64 a ser convertida.
    Returns:
        bytes: Os dados decodificados em bytes.
    """
    return base64.b64decode(base64_str)

# === Gerar aleatoriedade ===
import os

def generate_salt(length: int = 16) -> bytes:
    """
    Gera um salt aleatório de tamanho especificado (padrão 16 bytes).
    Args:
        length (int): O comprimento do salt em bytes. Padrão é 16 bytes.
    Returns:
        bytes: O salt gerado.
    """
    return os.urandom(length)

def generate_nonce(length: int = 12) -> bytes:
    """
    Gera um nonce aleatório de tamanho especificado (padrão 12 bytes, comum para AES-GCM).
    Args:
        length (int): O comprimento do nonce em bytes. Padrão é 12 bytes.
    Returns:
        bytes: O nonce gerado.
    """
    return os.urandom(length)

# === Serialização de chaves ===
from cryptography.hazmat.primitives import serialization
from typing import Optional

def serialize_public_key(public_key) -> bytes:
    """
    Serializa uma chave pública para o formato PEM.
    Args:
        public_key: A chave pública a ser serializada.
    Returns:
        bytes: A chave pública serializada em formato PEM.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def serialize_private_key(private_key, password: Optional[bytes] = None) -> bytes:
    """
    Serializa uma chave privada para o formato PEM, opcionalmente protegida por password.
    Args:
        private_key: A chave privada a ser serializada.
        password (bytes | None): Password para proteger a chave, se desejado.
    Returns:
        bytes: A chave privada serializada em formato PEM.
    """
    encryption_algorithm = (serialization.BestAvailableEncryption(password)
                            if password else serialization.NoEncryption())
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption_algorithm
    )

def deserialize_public_key(pem_data: bytes):
    """
    Desserializa uma chave pública a partir do formato PEM.
    Args:
        pem_data (bytes): Dados PEM da chave pública.
    Returns:
        public_key: A chave pública desserializada.
    """
    return serialization.load_pem_public_key(pem_data)

def deserialize_private_key(pem_data: bytes, password: Optional[bytes] = None):
    """Desserializa uma chave privada a partir do formato PEM, opcionalmente protegida por password.
    Args:
        pem_data (bytes): Dados PEM da chave privada.
        password (bytes | None): Password para descriptografar a chave, se estiver protegida.
    Returns:
        private_key: A chave privada desserializada.
    """
    return serialization.load_pem_private_key(pem_data, password=password)