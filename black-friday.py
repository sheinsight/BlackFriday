from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

# 密码填充到适合的长度
def pad_key_to_length(key, desired_len):
    if len(key) >= desired_len:
        return key[:desired_len]
    # 使用默认的salt和迭代次数，这通常不推荐，应该使用随机的salt和足够高的迭代次数
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=desired_len, salt=b'0'*16, iterations=100000, backend=default_backend())
    return kdf.derive(key.encode())

# AES加密
def aes_encrypt(plaintext, password):
    key = pad_key_to_length(password, 32)  # AES256密钥长度为32字节
    iv = os.urandom(16)  # 产生随机IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_plaintext = pad(plaintext.encode(), 16)  # PKCS#7 填充
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return urlsafe_b64encode(iv + ciphertext)

# AES解密
def aes_decrypt(encrypted, password):
    encrypted = urlsafe_b64decode(encrypted)
    iv = encrypted[:16]  # 提取IV
    ciphertext = encrypted[16:]  # 提取密文
    key = pad_key_to_length(password, 32)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(plaintext_padded, 16).decode()

# PKCS#7填充和去填充
def pad(bytestring, k):
    padding_amount = k - (len(bytestring) % k)
    return bytestring + bytes([padding_amount] * padding_amount)

def unpad(bytestring, k):
    padding_amount = bytestring[-1]
    return bytestring[:-padding_amount]

# 使用示例
# secret key please ask shein's chatgpt(chatgpt.dev-az) "通关密钥" 
# please eval this code in python cli, and you'll get the red packet token
password = 'aaa'  # 应该是足够强的密码

# 加密
encrypted_msg = b'O-cdRJfiN2DOfOq-lWCDESDG6qyxZEjVbAaeV6E4tfA='

# 解密
decrypted_msg = aes_decrypt(encrypted_msg, password)
print(f'Decrypted message: {decrypted_msg}')
