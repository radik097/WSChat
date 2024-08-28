from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request, Response, Form, Header
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from typing import Dict
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

console = rich.console.Console(color_system="windows")
rich.traceback.install(console=console, show_locals=True)

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

    async def send_group_message(self, message: str):
        for connection in self.active_connections.values():
            await connection.send_text(message)

manager = ConnectionManager()

@app.get("/friends", response_class=HTMLResponse)
async def secure_chat(request: Request):
    try:
        conn = get_db_connection()
        curs = conn.cursor()
        logger.info(f"User {request.cookies.get('username')} loaded friends page")
        user_info = request.cookies.get("username")
        friends = curs.execute("SELECT friends FROM users WHERE username = ?", (request.cookies.get("username"),)).fetchone()[0].split(",")
        logger.info(f"{friends},{request.cookies.get('username')}, {user_info}")
        return templates.TemplateResponse("secure_chat.html", {"request": request, "friends": friends, "user_info": user_info})
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

@app.post("/add_friend", response_class=HTMLResponse)
async def add_friend(request: Request):
    try:
        form_data = await request.form()
        friend_username = form_data.get("friend_username")
        conn = get_db_connection()
        curs = conn.cursor()
        current_user = request.cookies.get("username")

        logger.info(f"User {current_user} is trying to add friend {friend_username}")

        if friend_username == current_user:
            raise HTTPException(status_code=400, detail="You cannot add yourself as a friend")

        # Проверяем, существует ли пользователь с таким именем
        friend = curs.execute("SELECT * FROM users WHERE username = ?", (friend_username,)).fetchone()
        if not friend:
            raise HTTPException(status_code=404, detail="Friend not found")

        # Получаем текущий список друзей
        user = curs.execute("SELECT friends FROM users WHERE username = ?", (current_user,)).fetchone()
        current_friends = user["friends"].split(",") if user["friends"] else []

        if friend_username in current_friends:
            raise HTTPException(status_code=400, detail="You are already friends with this user")

        # Обновляем список друзей
        new_friends_list = ",".join(current_friends + [friend_username])
        curs.execute("UPDATE users SET friends = ? WHERE username = ?", (new_friends_list, current_user))
        conn.commit()

        return HTMLResponse(f"Friend {friend_username} added successfully!")
        
    except HTTPException as e:
        console.print(f"[bold red]Error adding friend:[/bold red] {str(e)}")
        console.print_exception()
        return HTMLResponse(f"Error: {e.detail}")
    except Exception as e:
        console.print(f"[bold red]Error adding friend:[/bold red] {str(e)}")
        console.print_exception()
        return HTMLResponse("An error occurred while adding the friend.")
    finally:
        if conn:
            conn.close()

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

@app.websocket("/ws/group_chat/{username}")
async def websocket_group_chat(websocket: WebSocket, username: str):
    try:
        await manager.connect(websocket, username)

        # Загрузка истории сообщений при подключении пользователя
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT sender, message FROM messages WHERE chat_name = ?", ("group_chat",))
        messages = cursor.fetchall()
        conn.close()

        # Отправляем историю сообщений новому подключенному пользователю
        for sender, message in messages:
            await websocket.send_text(json.dumps({"sender": sender, "content": message}))

        # Основной цикл для обработки новых сообщений
        while True:
            data = await websocket.receive_text()
            if not data.strip():
                console.print("[bold yellow]Warning: Received empty message[/bold yellow]")
                continue

            # Сохраняем сообщение в базе данных
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO messages (chat_name, sender, message) VALUES (?, ?, ?)",
                ("group_chat", username, data)
            )
            conn.commit()
            conn.close()

            # Отправляем сообщение всем подключенным пользователям
            await manager.send_group_message(json.dumps({"sender": username, "content": data}))

    except WebSocketDisconnect:
        manager.disconnect(username)
    except Exception as e:
        console.print(f"[bold red]Error in WebSocket group chat connection:[/bold red] {str(e)}")
        console.print_exception()

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

def send_token_and_username_to_cookie(response: Response, token: str, username: str):
    response.set_cookie(key="username", value=username, httponly=True)  # Set the username cookie
    response.set_cookie(key="token", value=token, httponly=True)  # Set the token cookie with httponly=True
    return response

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

        # Записываем токен и имя пользователя в куки
        send_token_and_username_to_cookie(response, session_token, username)

        # Перенаправляем пользователя на страницу чата
        return RedirectResponse(url="/chat", status_code=302)
        
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

        # Set cookies for session token and username
        response = send_token_and_username_to_cookie(response, session_token, username)
        
        # Redirecting to the chat page after setting the cookies
        response = RedirectResponse(url="/chat", headers=response.headers, status_code=302)
        
        return response
        
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
        if conn:
            conn.close()

@app.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request):
    try:
        token = request.cookies.get("token")
        conn = get_db_connection()
        if conn is None:
            raise HTTPException(status_code=500, detail="Database connection failed")

        cursor = conn.cursor()
        user = cursor.execute(
            "SELECT * FROM users WHERE session_token = ?", (token,)
        ).fetchone()

        if user is None:
            raise HTTPException(status_code=401, detail="Invalid session token")

        return templates.TemplateResponse("chat.html", {"request": request, "user_info": {"username": user["username"], "full_name": user["full_name"]}})
    except Exception as e:
        console.print(f"[bold red]Error loading chat page:[/bold red] {str(e)}")
        console.print_exception()
        return templates.TemplateResponse("error.html", {"request": request, "title": "500", "message": "Internal Server Error"})

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
