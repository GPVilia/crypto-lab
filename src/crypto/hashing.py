# Hashes (MD5, SHA-256, SHA-512, HMAC SHA-256)

# MD5 é coniderado um algoritmo fraco para segurança, mas ainda é usado para checksums e integridade de dados.
# SHA-256 e SHA-512 são parte da família SHA-2 e são amplamente usados para segurança.
# HMAC (Hash-based Message Authentication Code) é usado para autenticação de mensagens com uma chave secreta.

import hashlib
import hmac

def hash_data(data: bytes, algorithm: str = 'sha256') -> bytes:
    """
    Calcula o hash de dados usando o algoritmo especificado.
    Args:
        data (bytes): Dados de entrada.
        algorithm (str): Algoritmo ('md5', 'sha1', 'sha256', 'sha512', 'sha3_256', 'sha3_512', etc.)
    Returns:
        bytes: Hash resultante.
    """
    try:
        hasher = hashlib.new(algorithm) # Cria o objeto hash dinamicamente
        hasher.update(data) # Atualiza o objeto hash com os dados
        return hasher.digest() # Retorna o hash em bytes
    except ValueError:
        raise ValueError(f"Algoritmo '{algorithm}' não é suportado.")


def hash_file(path: str, algorithm: str = 'sha256') -> str:
    """
    Calcula o hash de um ficheiro (modo leitura binária).
    Args:
        path (str): Caminho para o ficheiro.
        algorithm (str): Algoritmo ('sha256', 'sha3_512', etc.)
    Returns:
        str: Hash hexadecimal.
    """
    hasher = hashlib.new(algorithm)
    with open(path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()


def hmac_data(key: bytes, data: bytes, algorithm: str = 'sha256') -> bytes:
    """
    Calcula o HMAC de dados usando a chave e o algoritmo especificado.
    Args:
        key (bytes): Chave secreta.
        data (bytes): Dados de entrada.
        algorithm (str): Algoritmo ('sha256', 'sha512', etc.)
    Returns:
        bytes: HMAC resultante.
    """
    try:
        digest_mod = getattr(hashlib, algorithm)
    except AttributeError:
        # Fallback para compatibilidade com versões que não têm o atributo direto
        digest_mod = lambda: hashlib.new(algorithm)

    try:
        hmac_obj = hmac.new(key, data, digestmod=digest_mod)
        return hmac_obj.digest()
    except (TypeError, ValueError):
        raise ValueError(f"Algoritmo '{algorithm}' não é suportado.")
