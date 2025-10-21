# AES, 3DES, etc...

# AES (Advanced Encryption Standard) é um algoritmo de cifragem simétrica amplamente utilizado que suporta tamanhos de chave de 128, 192 e 256 bits.

# 3DES (Triple Data Encryption Standard) é uma versão mais segura do DES que aplica o algoritmo DES três vezes a cada bloco de dados, geralmente com uma chave de 168 bits.

from typing import Optional
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from .utils import read_file_bytes, write_file_bytes, generate_salt, generate_nonce

# AES
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(password: str | bytes, salt: Optional[bytes] = None, length: int = 32) -> tuple[bytes, bytes]:
    """
    Deriva uma chave simétrica a partir de uma password usando Scrypt.
    Args:
        password (str | bytes): A password a partir da qual a chave será derivada.
        salt (bytes | None): O salt a ser usado na derivação. Se None, um salt aleatório será gerado.
        length (int): O comprimento da chave derivada em bytes. Padrão é 32 bytes (256 bits).
    Returns:
        tuple[bytes, bytes]: A chave derivada e o salt usado.
    """

    if isinstance(password, str):
        # Converte a password para bytes se for uma string
        password = password.encode('utf-8')

    if salt is None:
        salt = generate_salt(16) # Gera um salt aleatório se não fornecido
    kdf = Scrypt(
        salt=salt,
        length=length, # comprimento da chave derivada
        n=2**14, # parâmetro de custo de CPU / memória
        r=8, # tamanho do bloco de memória
        p=1, # paralelismo
    )
    key = kdf.derive(password)
    return key, salt

# Encrypt AES
def encrypt_file_aes(in_path: str, out_path: str, password: str | bytes):
    """
    Cifra um ficheiro utilizando AES-256-GCM com chave derivada via Scrypt.
    O ficheiro resultante contem: salt + nonce + ciphertext.
    Args:
        in_path (str): Caminho do ficheiro de entrada a ser cifrado.
        out_path (str): Caminho do ficheiro de saída cifrado.
        password (str | bytes): A password para derivar a chave de cifragem.

    Returns:
        None
    """

    #Lê o ficheiro original
    data = read_file_bytes(in_path)
    #Deriva a chave e obtém o salt
    key, salt = derive_key(password)
    nonce = generate_nonce(12) # Gera um nonce aleatório para AES-GCM (96 bits é o padrão GCM)

    # Cria o objeto AESGCM e cifra
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    # Guarda o salt + nonce + ciphertext num ficheiro binário
    write_file_bytes(out_path, salt + nonce + ciphertext)

# Decrypt AES
def decrypt_file_aes(in_path: str, out_path: str, password: str | bytes):
    """
    Decifra um ficheiro cifrado utilizando AES-256-GCM com chave derivada via Scrypt.
    O ficheiro de entrada deve conter: salt + nonce + ciphertext.
    Args:
        in_path (str): Caminho do ficheiro cifrado a ser decifrado.
        out_path (str): Caminho do ficheiro de saída decifrado.
        password (str | bytes): A password para derivar a chave de decifragem.

    Returns:
        None
    """

    #Lê o ficheiro cifrado
    file_data = read_file_bytes(in_path)

    # Extrai o salt, nonce e ciphertext
    salt = file_data[:16] # Primeiro 16 bytes são o salt
    nonce = file_data[16:28] # Próximos 12 bytes são o nonce
    ciphertext = file_data[28:] # Resto é o ciphertext

    # Deriva a chave com o salt extraído
    key, _ = derive_key(password, salt)

    # Cria o objeto AESGCM e decifra
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    # Guarda o texto decifrado num ficheiro
    write_file_bytes(out_path, plaintext)


# 3DES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def encrypt_file_3des(in_path: str, out_path: str, password: str | bytes):
    """
    Cifra um ficheiro utilizando 3DES (modo CBC com PKCS7 padding).
    Guarda: salt + iv + ciphertext no ficheiro de saída.

    Args:
        in_path (str): Caminho do ficheiro de entrada a ser cifrado.
        out_path (str): Caminho do ficheiro de saída cifrado.
        password (str | bytes): A password para derivar a chave de cifragem.
    Returns:
        None
    """

    # Lê o ficheiro original
    data = read_file_bytes(in_path)

    # Deriva a chave e obtém o salt
    key, salt = derive_key(password, length=24) # 3DES usa chave de 24 bytes
    iv = generate_nonce(8) # Gera um IV aleatório para 3DES (64 bits)

    # Cria um objeto de cifra (CBC)
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Aplica padding PKCS7
    padder = padding.PKCS7(algorithms.TripleDES.block_size).padder() #type: ignore
    padded_data = padder.update(data) + padder.finalize()

    # Cifra os dados
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Guarda o salt + iv + ciphertext num ficheiro binário
    write_file_bytes(out_path, salt + iv + ciphertext)


def decrypt_file_3des(in_path: str, out_path: str, password: str | bytes):
    """
    Decifra um ficheiro cifrado utilizando 3DES (modo CBC com PKCS7 padding).
    O ficheiro de entrada deve conter: salt + iv + ciphertext.

    Args:
        in_path (str): Caminho do ficheiro cifrado a ser decifrado.
        out_path (str): Caminho do ficheiro de saída decifrado.
        password (str | bytes): A password para derivar a chave de decifragem.
    Returns:
        None
    """

    # Lê o ficheiro cifrado
    file_data = read_file_bytes(in_path)

    # Extrai o salt, iv e ciphertext
    salt = file_data[:16] # Primeiro 16 bytes são o salt
    iv = file_data[16:24] # Próximos 8 bytes são o iv
    ciphertext = file_data[24:] # Resto é o ciphertext

    # Deriva a chave com o salt extraído
    key, _ = derive_key(password, salt, length=24)

    # Cria um objeto de cifra (CBC)
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decifra os dados
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove o padding PKCS7
    unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder() #type: ignore
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Guarda o texto decifrado num ficheiro
    write_file_bytes(out_path, plaintext)