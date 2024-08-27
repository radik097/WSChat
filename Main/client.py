import requests
import asyncio
import websockets
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# URL сервера
base_url = "http://127.0.0.1:8000"

# Генерация пары ключей RSA
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Шифрование данных с использованием RSA
def rsa_encrypt(public_key, data: bytes) -> bytes:
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Дешифрование данных с использованием RSA
def rsa_decrypt(private_key, encrypted_data: bytes) -> bytes:
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Генерация симметричного ключа AES
def generate_aes_key() -> bytes:
    return os.urandom(32)

# Шифрование данных с использованием AES
def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

# Дешифрование данных с использованием AES
def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext[16:]) + decryptor.finalize()

# Регистрация пользователя
def register_user(username: str, full_name: str, password: str):
    private_key, public_key = generate_rsa_key_pair()

    # Сохранение приватного ключа
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f"{username}_private_key.pem", "wb") as key_file:
        key_file.write(private_key_pem)

    # Сохранение публичного ключа
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"{username}_public_key.pem", "wb") as key_file:
        key_file.write(public_key_pem)

    response = requests.post(
        f"{base_url}/users/register",
        data={"username": username, "full_name": full_name, "password": password}
    )
    if response.status_code == 200:
        print("User registered successfully")
    else:
        print("Error:", response.json())

# Вход пользователя
def login_user(username: str, password: str):
    response = requests.post(
        f"{base_url}/users/login",
        data={"username": username, "password": password}
    )
    if response.status_code == 200:
        print("Login successful")
        return True
    else:
        print("Error:", response.json())
        return False

# Клиент WebSocket
async def chat_client(username: str, private_key, public_key):
    uri = f"ws://192.168.178.10:8000/ws/chat/{username}"
    async with websockets.connect(uri) as websocket:
        while True:
            message = input("Enter message: ")
            encrypted_message = rsa_encrypt(public_key, message.encode())
            await websocket.send(encrypted_message.hex())
            response = await websocket.recv()
            decrypted_response = rsa_decrypt(private_key, bytes.fromhex(response))
            print(f"Received: {decrypted_response.decode()}")

if __name__ == "__main__":
    choice = input("Do you want to (1) Register or (2) Login? ")

    username = input("Enter your username: ")
    password = input("Enter your password: ")

    if choice == "1":
        full_name = input("Enter your full name: ")
        register_user(username, full_name, password)
    elif choice == "2":
        if not login_user(username, password):
            exit()

    # Загрузка ключей из файлов
    public_key_pem = open(f"{username}_public_key.pem", "rb").read()
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )
    private_key_pem = open(f"{username}_private_key.pem", "rb").read()
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )

    asyncio.get_event_loop().run_until_complete(chat_client(username=username, private_key=private_key, public_key=public_key))
