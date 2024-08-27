from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request, Response, Form, Header
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from typing import Dict, Optional
from pydantic import BaseModel
import sqlite3
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import rich.console
import rich.traceback
import rich.logging
import json
import logging

# Настройка логирования
logging.basicConfig(level="INFO", format="%(message)s", handlers=[rich.logging.RichHandler()])
logger = logging.getLogger("server")

console = rich.console.Console()
rich.traceback.install(console=console)

app = FastAPI()

# Настройка шаблонов
templates = Jinja2Templates(directory="Main/templates")

# Модель данных для пользователей
class User(BaseModel):
    username: str
    full_name: str

# Подключение к базе данных
def get_db_connection():
    try:
        conn = sqlite3.connect("Database.db")
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        console.print(f"[bold red]Error connecting to database:[/bold red] {str(e)}")
        console.print_exception()
        raise HTTPException(status_code=500, detail="Database connection failed")

# Генерация пары ключей RSA
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Функция для шифрования данных с использованием RSA
def rsa_encrypt(public_key, data: bytes) -> bytes:
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Функция для расшифровки данных с использованием RSA
def rsa_decrypt(private_key, encrypted_data: bytes) -> bytes:
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Функция для шифрования данных с использованием AES
def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

# Функция для расшифровки данных с использованием AES
def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext[16:]) + decryptor.finalize()

# Функция для генерации симметричного ключа AES
def generate_aes_key() -> bytes:
    return os.urandom(32)

# Функция для генерации уникального токена сессии
def generate_session_token():
    return str(uuid.uuid4())

# Управление подключениями WebSocket
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, username: str):
        await websocket.accept()
        self.active_connections[username] = websocket

    def disconnect(self, username: str):
        if username in self.active_connections:
            del self.active_connections[username]

    async def send_private_message(self, message: str, receiver_username: str):
        connection = self.active_connections.get(receiver_username)
        if connection:
            await connection.send_text(message)

manager = ConnectionManager()

@app.get("/friends", response_class=HTMLResponse)
async def secure_chat(request: Request):
    try:
        conn = get_db_connection()
        curs = conn.cursor()
        friends = curs.execute("SELECT friends FROM users WHERE username = ?", (request.cookies.get("username"),)).fetchall()
        return templates.TemplateResponse("secure_chat.html", {"request": request, "friends": friends})
    except HTTPException as e:
        console.print(f"[bold red]Error loading friends page:[/bold red] {str(e)}")
        console.print_exception()
        return templates.TemplateResponse("error.html", {"request": request, "title": "500", "message": f"HTTPException {e}"})
    except sqlite3.OperationalError as e:
        console.print(f"[bold red]Error loading friends page:[/bold red] {str(e)}")
        console.print_exception()
        return templates.TemplateResponse("error.html", {"request": request, "title": "500", "message": "SQLite3 error OperationalError"})
    except sqlite3.Error as e:
        console.print(f"[bold red]Error loading friends page:[/bold red] {str(e)}")
        console.print_exception()
        return templates.TemplateResponse("error.html", {"request": request, "title": "500", "message": "SQLite3 error Error"})
    except Exception as e:
        console.print(f"[bold red]Error loading friends page:[/bold red] {str(e)}")
        console.print_exception()
        return templates.TemplateResponse("error.html", {"request": request, "title": "500", "message": "Internal Server Error"})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    try:
        return templates.TemplateResponse("login.html", {"request": request})
    except HTTPException as e:
        console.print(f"[bold red]Error loading login page:[/bold red] {str(e)}")
        console.print_exception()
        return templates.TemplateResponse("error.html", {"request": request, "title": "500", "message": "Internal Server Error"})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    try:
        return templates.TemplateResponse("register.html", {"request": request})
    except HTTPException as e:
        console.print(f"[bold red]Error loading register page:[/bold red] {str(e)}")
        console.print_exception()
        return templates.TemplateResponse("error.html", {"request": request, "title": "500", "message": "Internal Server Error"})
    

@app.websocket("/ws/chat/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str, token: str = Header(None)):
    try:
        if not validate_token(token, username):
            await websocket.close(code=1008)
            return

        await manager.connect(websocket, username)
        while True:
            data = await websocket.receive_text()
            if not data.strip():
                console.print(f"[bold yellow]Warning: Received empty message from {username}[/bold yellow]")
                continue
            try:
                message_data = json.loads(data)
            except json.JSONDecodeError as e:
                console.print(f"[bold red]Error decoding JSON:[/bold red] {str(e)} - Received data: {data}")
                continue

            receiver = message_data.get("to")
            content = message_data.get("content")
            
            conn = get_db_connection()
            cursor = conn.cursor()
            friend = cursor.execute("SELECT * FROM users WHERE username = ?", (receiver,)).fetchone()

            if not friend:
                await websocket.send_text(f"Error: User {receiver} not found.")
                continue
            
            friend_public_key = serialization.load_pem_public_key(friend["public_key"].encode(), backend=default_backend())
            encrypted_message = rsa_encrypt(friend_public_key, content.encode())

            chat_name = f"{min(username, receiver)}/{max(username, receiver)}"
            cursor.execute(
                "INSERT INTO messages (chat_name, sender, receiver, message) VALUES (?, ?, ?, ?)",
                (chat_name, username, receiver, encrypted_message.hex())
            )
            conn.commit()
            conn.close()

            await manager.send_private_message(data, receiver)

    except WebSocketDisconnect:
        manager.disconnect(username)
    except Exception as e:
        console.print(f"[bold red]Error in WebSocket connection:[/bold red] {str(e)}")
        console.print_exception()

def validate_token(token: str, username: str) -> bool:
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        user = cursor.execute("SELECT * FROM users WHERE username = ? AND session_token = ?", (username, token)).fetchone()
        return user is not None
    except Exception as e:
        console.print(f"[bold red]Error validating token:[/bold red] {str(e)}")
        console.print_exception()
        return False
    finally:
        conn.close()

@app.post("/users/register", response_class=HTMLResponse)
def register_user(response: Response, request: Request, username: str = Form(...), full_name: str = Form(...), password: str = Form(...)):
    try:
        conn = get_db_connection()
        if conn is None:
            raise HTTPException(status_code=500, detail="Database connection failed")

        cursor = conn.cursor()

        existing_user = cursor.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if existing_user:
            raise HTTPException(status_code=400, detail="Username already exists")

        private_key, public_key = generate_rsa_key_pair()

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        aes_key = generate_aes_key()
        encrypted_password = aes_encrypt(aes_key, password.encode())

        aes_key_hex = aes_key.hex()

        session_token = generate_session_token()
        cursor.execute(
            "INSERT INTO users (username, full_name, password, session_token, public_key, aes_key) VALUES (?, ?, ?, ?, ?, ?)",
            (username, full_name, encrypted_password.hex(), session_token, public_key_pem.decode(), aes_key_hex)
        )
        conn.commit()

        return templates.TemplateResponse("chat.html", {"request": request, "user_info": {"username": username, "full_name": full_name}, "session_token": session_token})
    except sqlite3.IntegrityError as e:
        console.print(f"[bold red]Database IntegrityError:[/bold red] {str(e)}")
        console.print_exception()
        return templates.TemplateResponse("error.html", {"request": request, "title": "400", "message": "Username already exists"})
    except Exception as e:
        console.print(f"[bold red]Error during user registration:[/bold red] {str(e)}")
        console.print_exception()
        return templates.TemplateResponse("error.html", {"request": request, "title": "500", "message": "Internal Server Error"})
    finally:
        if conn:
            conn.close()

@app.post("/users/login", response_class=JSONResponse)
def login_user(response: Response, request: Request, username: str = Form(...), password: str = Form(...)):
    try:
        conn = get_db_connection()
        if conn is None:
            raise HTTPException(status_code=500, detail="Database connection failed")

        cursor = conn.cursor()
        
        user = cursor.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        
        if user is None:
            return JSONResponse(content={"error": "User not found"}, status_code=404)

        aes_key = bytes.fromhex(user["aes_key"])

        encrypted_password = bytes.fromhex(user["password"])
        decrypted_password = aes_decrypt(aes_key, encrypted_password).decode()

        if decrypted_password != password:
            return templates.TemplateResponse("error.html", {"request": request, "title": "401", "message": "Invalid password"})
        
        session_token = generate_session_token()
        cursor.execute(
            "UPDATE users SET session_token = ? WHERE username = ?",
            (session_token, username)
        )
        conn.commit()

        return templates.TemplateResponse("chat.html", {"request": request, "user_info": {"username": username, "full_name": user["full_name"]}, "session_token": session_token})
    except Exception as e:
        console.print(f"[bold red]Error during user login:[/bold red] {str(e)}")
        console.print_exception()
        return templates.TemplateResponse("error.html", {"request": request, "title": "500", "message": "Internal Server Error"})
    finally:
        if conn:
            conn.close()

@app.get("/logout")
async def logout(request: Request, response: Response, token: str = Header(None)):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET session_token = NULL WHERE session_token = ?", (token,))
        conn.commit()
        return templates.TemplateResponse("logout.html", {"request": request})
    except Exception as e:
        console.print(f"[bold red]Error during logout:[/bold red] {str(e)}")
        console.print_exception()
        return templates.TemplateResponse("error.html", {"request": request, "title": "500", "message": "Internal Server Error"})
    finally:
        conn.close()

@app.get("/", response_class=HTMLResponse)
async def get(request: Request, token: str = Header(None)):
    logger.info(f"Session token: {token}")
    
    try:
        user_info = None
        if token:
            conn = get_db_connection()
            if conn is None:
                raise HTTPException(status_code=500, detail="Database connection failed")

            cursor = conn.cursor()
            user = cursor.execute(
                "SELECT * FROM users WHERE session_token = ?", (token,)
            ).fetchone()

            if user:
                user_info = {"username": user["username"], "full_name": user["full_name"]}
            conn.close()

        return templates.TemplateResponse("chat.html", {"request": request, "user_info": user_info})
    except Exception as e:
        console.print(f"[bold red]Error loading chat page:[/bold red] {str(e)}")
        console.print_exception()
        return templates.TemplateResponse("error.html", {"request": request, "title": "500", "message": "Internal Server Error"})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)