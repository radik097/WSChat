from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request, Response, Cookie, Form
from fastapi.responses import HTMLResponse, JSONResponse
# from fastapi.staticfiles import StaticFiles
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

@app.post("/report-cookie-status")
async def report_cookie_status(request: Request):
    data = await request.json()
    logger.info(f"Received data: {data}")
    cookie_exists = data.get("cookieExists")
    
    if cookie_exists:
        logger.info("Cookie is set in the browser.")
        return {"status": "success", "cookieExists": cookie_exists}
    else:
        logger.warning("Cookie is NOT set in the browser.")
        return {"status": "error", "cookieExists": cookie_exists}
    
    
@app.post("/generate-new-session-token")
async def generate_new_session_token(response: Response, request: Request):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Получение информации о пользователе из куки
        session_token = request.cookies.get("session_token")
        user = cursor.execute(
            "SELECT * FROM users WHERE session_token = ?", (session_token,)
        ).fetchone()

        if user is None:
            return JSONResponse(content={"error": "Invalid session"}, status_code=403)

        # Генерация нового сессионного токена
        new_session_token = generate_session_token()
        cursor.execute(
            "UPDATE users SET session_token = ? WHERE username = ?",
            (new_session_token, user["username"])
        )
        conn.commit()

        # Установка нового сессионного токена в куки
        set_session_token(response, new_session_token)
        
        return JSONResponse(content={"session_token": new_session_token}, status_code=200)
    except Exception as e:
        console.print(f"[bold red]Error generating new session token:[/bold red] {str(e)}")
        console.print_exception()
        return JSONResponse(content={"error": "Internal server error"}, status_code=500)
    finally:
        if conn:
            conn.close()

# Функция для установки сессионного токена в куки
def set_session_token(response: Response, token: str):
    response.set_cookie(
        key="session_token", 
        value=token, 
        httponly=True, 
        max_age=1800,  # Время жизни куки в секундах
        path="/", 
        samesite="lax"  # или "Strict", в зависимости от вашего использования
    )
    logger.info(f"Set session token: {token}")

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

@app.websocket("/ws/chat/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    try:
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
            
            # Получаем ключи пользователя и друга из БД
            conn = get_db_connection()
            cursor = conn.cursor()
            friend = cursor.execute("SELECT * FROM users WHERE username = ?", (receiver,)).fetchone()

            if not friend:
                await websocket.send_text(f"Error: User {receiver} not found.")
                continue
            
            # Шифрование сообщения
            friend_public_key = serialization.load_pem_public_key(friend["public_key"].encode(), backend=default_backend())
            encrypted_message = rsa_encrypt(friend_public_key, content.encode())

            # Сохранение сообщения в БД
            chat_name = f"{min(username, receiver)}/{max(username, receiver)}"
            cursor.execute(
                "INSERT INTO messages (chat_name, sender, receiver, message) VALUES (?, ?, ?, ?)",
                (chat_name, username, receiver, encrypted_message.hex())
            )
            conn.commit()
            conn.close()

            # Отправка сообщения получателю
            await manager.send_private_message(data, receiver)

    except WebSocketDisconnect:
        manager.disconnect(username)
    except Exception as e:
        console.print(f"[bold red]Error in WebSocket connection:[/bold red] {str(e)}")
        console.print_exception()



@app.get("/register", response_class=HTMLResponse)
async def show_register_page(request: Request):
    try:
        return templates.TemplateResponse("register.html", {"request": request})
    except Exception as e:
        console.print(f"[bold red]Error loading register page:[/bold red] {str(e)}")
        console.print_exception()
        return templates.TemplateResponse("error.html", {"request": request, "title": "500", "message": "Internal Server Error"})

@app.get("/login", response_class=HTMLResponse)
async def show_login_page(request: Request):
    try:
        return templates.TemplateResponse("login.html", {"request": request})
    except Exception as e:
        console.print(f"[bold red]Error loading login page:[/bold red] {str(e)}")
        console.print_exception()
        return templates.TemplateResponse("error.html", {"request": request, "title": "500", "message": "Internal Server Error"})
# Функция для отображения страницы чата с друзьями
@app.get("/friends", response_class=HTMLResponse)
async def show_friends_page(request: Request, session_token: Optional[str] = Cookie(None)):
    try:
        if session_token:
            conn = get_db_connection()
            cursor = conn.cursor()
            user = cursor.execute("SELECT * FROM users WHERE session_token = ?", (session_token,)).fetchone()

            if user:
                friends = json.loads(user["friends"])
                return templates.TemplateResponse("secure_chat.html", {"request": request, "user_info": {"username": user["username"], "full_name": user["full_name"]}, "friends": friends})
            conn.close()
        return templates.TemplateResponse("error.html", {"request": request, "title": "403", "message": "Unauthorized"})
    except Exception as e:
        console.print(f"[bold red]Error loading friends page:[/bold red] {str(e)}")
        console.print_exception()
        return templates.TemplateResponse("error.html", {"request": request, "title": "500", "message": "Internal Server Error"})


# Функция для регистрации пользователя
@app.post("/users/register", response_class=HTMLResponse)
def register_user(response: Response, request: Request, username: str = Form(...), full_name: str = Form(...), password: str = Form(...)):
    try:
        conn = get_db_connection()
        if conn is None:
            raise HTTPException(status_code=500, detail="Database connection failed")

        cursor = conn.cursor()

        # Проверка на существование пользователя с таким же именем
        existing_user = cursor.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if existing_user:
            raise HTTPException(status_code=400, detail="Username already exists")

        # Генерация ключей RSA
        private_key, public_key = generate_rsa_key_pair()

        # Сохранение ключей
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Генерация и шифрование пароля
        aes_key = generate_aes_key()
        encrypted_password = aes_encrypt(aes_key, password.encode())

        # Сохранение симметричного ключа в базе данных (лучше его зашифровать перед этим)
        aes_key_hex = aes_key.hex()

        session_token = generate_session_token()
        cursor.execute(
            "INSERT INTO users (username, full_name, password, session_token, public_key, aes_key) VALUES (?, ?, ?, ?, ?, ?)",
            (username, full_name, encrypted_password.hex(), session_token, public_key_pem.decode(), aes_key_hex)
        )
        conn.commit()

        # Установка сессионного токена в куки
        set_session_token(response, session_token)
        return templates.TemplateResponse("chat.html", {"request": request, "user_info": {"username": username, "full_name": full_name}})
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
@app.post("/friends/add", response_class=HTMLResponse)
def add_friend(request: Request, response: Response, username: str = Form(...), friend_username: str = Form(...)):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Проверка существования пользователей
        user = cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        friend = cursor.execute("SELECT * FROM users WHERE username = ?", (friend_username,)).fetchone()

        if not user or not friend:
            raise HTTPException(status_code=404, detail="User or friend not found")

        # Обновление списка друзей
        friends = json.loads(user["friends"])
        if friend_username not in friends:
            friends[friend_username] = {"id": friend["id"], "public_key": friend["public_key"]}
            cursor.execute("UPDATE users SET friends = ? WHERE username = ?", (json.dumps(friends), username))
            conn.commit()
            return HTMLResponse(f"Friend {friend_username} added successfully!")
        else:
            return HTMLResponse(f"{friend_username} is already your friend.")
    except Exception as e:
        console.print(f"[bold red]Error adding friend:[/bold red] {str(e)}")
        console.print_exception()
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        conn.close()

# Функция для удаления друга
@app.post("/friends/remove", response_class=HTMLResponse)
def remove_friend(request: Request, response: Response, username: str = Form(...), friend_username: str = Form(...)):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Проверка существования пользователя
        user = cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Обновление списка друзей
        friends = json.loads(user["friends"])
        if friend_username in friends:
            del friends[friend_username]
            cursor.execute("UPDATE users SET friends = ? WHERE username = ?", (json.dumps(friends), username))
            conn.commit()
            return HTMLResponse(f"Friend {friend_username} removed successfully!")
        else:
            return HTMLResponse(f"{friend_username} is not your friend.")
    except Exception as e:
        console.print(f"[bold red]Error removing friend:[/bold red] {str(e)}")
        console.print_exception()
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        conn.close()

@app.websocket("/ws/group_chat")
async def websocket_group_chat(websocket: WebSocket):
    try:
        await manager.connect(websocket, "group_chat")
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)
            
            sender = message_data.get("sender")
            content = message_data.get("content")
            
            # Сохранение сообщения в БД (если нужно сохранить историю)
            conn = get_db_connection()
            cursor = conn.cursor()
            chat_name = "group_chat"
            cursor.execute(
                "INSERT INTO messages (chat_name, sender, message) VALUES (?, ?, ?)",
                (chat_name, sender, content)
            )
            conn.commit()
            conn.close()

            # Отправка сообщения всем участникам
            await manager.send_private_message(data, "group_chat")
    except WebSocketDisconnect:
        manager.disconnect("group_chat")
    except Exception as e:
        console.print(f"[bold red]Error in group chat WebSocket connection:[/bold red] {str(e)}")
        console.print_exception()


# Функция для отправки сообщений в групповой чат
@app.post("/group/send", response_class=HTMLResponse)
def send_group_message(request: Request, response: Response, sender: str = Form(...), chat_name: str = Form(...), message: str = Form(...)):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Получение информации о чате и участниках
        user = cursor.execute("SELECT * FROM users WHERE username = ?", (sender,)).fetchone()

        if not user:
            raise HTTPException(status_code=404, detail="Sender not found")

        # Шифрование сообщения с использованием AES
        aes_key = generate_aes_key()  # Можно использовать ключ, сохраненный для этого чата
        encrypted_message = aes_encrypt(aes_key, message.encode())

        # Сохранение сообщения в таблицу
        cursor.execute(
            "INSERT INTO messages (chat_name, sender, message) VALUES (?, ?, ?)",
            (chat_name, sender, encrypted_message.hex())
        )
        conn.commit()

        return HTMLResponse("Group message sent successfully!")
    except Exception as e:
        console.print(f"[bold red]Error sending group message:[/bold red] {str(e)}")
        console.print_exception()
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        conn.close()

# Функция для отправки личных сообщений
@app.post("/messages/send", response_class=HTMLResponse)
def send_message(request: Request, response: Response, sender: str = Form(...), receiver: str = Form(...), message: str = Form(...)):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Проверка существования пользователей
        user = cursor.execute("SELECT * FROM users WHERE username = ?", (sender,)).fetchone()
        friend = cursor.execute("SELECT * FROM users WHERE username = ?", (receiver,)).fetchone()

        if not user or not friend:
            raise HTTPException(status_code=404, detail="Sender or receiver not found")

        # Шифрование сообщения с использованием RSA
        friend_public_key = serialization.load_pem_public_key(friend["public_key"].encode(), backend=default_backend())
        encrypted_message = rsa_encrypt(friend_public_key, message.encode())

        # Сохранение сообщения в таблицу
        chat_name = f"{min(sender, receiver)}/{max(sender, receiver)}"
        cursor.execute(
            "INSERT INTO messages (chat_name, sender, receiver, message) VALUES (?, ?, ?, ?)",
            (chat_name, sender, receiver, encrypted_message.hex())
        )
        conn.commit()

        return HTMLResponse("Message sent successfully!")
    except Exception as e:
        console.print(f"[bold red]Error sending message:[/bold red] {str(e)}")
        console.print_exception()
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        conn.close()
        
@app.get("/messages", response_class=HTMLResponse)
async def get_messages(request: Request, session_token: Optional[str] = Cookie(None), friend = None):
    try:
        if session_token and friend:
            conn = get_db_connection()
            cursor = conn.cursor()
            user = cursor.execute("SELECT * FROM users WHERE session_token = ?", (session_token,)).fetchone()

            if user:
                chat_name = f"{min(user['username'], friend)}/{max(user['username'], friend)}"
                messages = cursor.execute("SELECT * FROM messages WHERE chat_name = ?", (chat_name,)).fetchall()

                message_list = []
                for message in messages:
                    decrypted_message = rsa_decrypt(
                        serialization.load_pem_private_key(user["private_key"].encode(), password=None, backend=default_backend()),
                        bytes.fromhex(message["message"])
                    ).decode()
                    message_list.append({"sender": message["sender"], "content": decrypted_message})

                return {"messages": message_list}

        return {"messages": []}
    except Exception as e:
        console.print(f"[bold red]Error loading messages:[/bold red] {str(e)}")
        console.print_exception()
        raise HTTPException(status_code=500, detail="Internal Server Error")

# Функция для входа пользователя
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

        # Извлечение симметричного ключа из базы данных
        aes_key = bytes.fromhex(user["aes_key"])

        # Расшифровка пароля пользователя
        encrypted_password = bytes.fromhex(user["password"])
        decrypted_password = aes_decrypt(aes_key, encrypted_password).decode()

        if decrypted_password != password:
            return JSONResponse(content={"error": "Incorrect password"}, status_code=403)
        
        # Если пароль правильный, генерируем сессионный токен
        session_token = generate_session_token()
        cursor.execute(
            "UPDATE users SET session_token = ? WHERE username = ?",
            (session_token, username)
        )
        conn.commit()

        return JSONResponse(content={"session_token": session_token, "username": username, "full_name": user["full_name"]}, status_code=200)
    except Exception as e:
        console.print(f"[bold red]Error during user login:[/bold red] {str(e)}")
        console.print_exception()
        return JSONResponse(content={"error": "Internal Server Error"}, status_code=500)
    finally:
        if conn:
            conn.close()


@app.get("/logout")
async def logout(request: Request, response: Response):
    response.delete_cookie("session_token")
    return templates.TemplateResponse("logout.html", {"request": request})

def get_cookie_from_request(request: Request) -> Optional[str]:
    cookies = request.cookies
    session_token = cookies.get("session_token")
    return session_token

@app.get("/", response_class=HTMLResponse)
async def get(request: Request, session_token: Optional[str] = Cookie(None)):
    # Попытка получить session_token из куки
    if not session_token:
        session_token = get_cookie_from_request(request)

    logger.info(f"Session token: {session_token}")
    
    try:
        user_info = None
        if session_token:
            conn = get_db_connection()
            if conn is None:
                raise HTTPException(status_code=500, detail="Database connection failed")

            cursor = conn.cursor()
            user = cursor.execute(
                "SELECT * FROM users WHERE session_token = ?", (session_token,)
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
