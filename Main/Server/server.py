from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
import logging
from passlib.hash import pbkdf2_sha256
import sqlite3
import uuid
from functools import wraps
import re

app = Flask(__name__)
logger_level =app.logger.setLevel(logging.INFO)
logger=app.logger

# Initialize the database
def init_db():
    with sqlite3.connect('secure_chat.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            authToken TEXT,
            ProfilePhoto TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_username TEXT,
            receiver_username TEXT,
            encrypted_data TEXT,
            iv TEXT,
            FOREIGN KEY (sender_username) REFERENCES users(username),
            FOREIGN KEY (receiver_username) REFERENCES users(username)
        )''')
        conn.commit()

init_db()

def check_auth():
    token = request.cookies.get('authToken')
    if not token:
        return None

    try:
        with sqlite3.connect('secure_chat.db') as conn:
            c = conn.cursor()
            c.execute("SELECT username FROM users WHERE authToken=?", (token,))
            row = c.fetchone()

        if row:
            return row[0]
        else:
            # Можно добавить логирование попыток использовать недействительные токены
            print("Invalid auth token.")
            return None

    except sqlite3.DatabaseError as e:
        # Логировать ошибку базы данных
        print(f"Database error during authentication: {e}")
        return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not check_auth():
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    username = check_auth()  # Предполагаем, что check_auth() возвращает имя пользователя
    base64ProfilePhoto = None

    try:
        with sqlite3.connect('secure_chat.db') as conn:
            c = conn.cursor()
            c.execute("SELECT ProfilePhoto FROM users WHERE username=?", (username,))
            row = c.fetchone()

            if row:
                base64ProfilePhoto = row[0]  # Предположим, что это правильно отформатированный base64

    except sqlite3.DatabaseError as e:
        # Логирование ошибки базы данных
        print(f"Database error: {e}")
        # Вы, возможно, захотите показать пользователю ошибку, или просто продолжить без аватара

    # Подача изображения в виде base64 строки в шаблон
    return render_template("index.html", base64_ico=base64ProfilePhoto)
@app.route('/api/user/avatar', methods=['GET'])
def get_avatar():
    username = request.args.get('username')
    if not username:
        return jsonify({"error": "Username not provided"}), 400

    # Ensure that proper authentication is performed
    if not check_auth():
        return jsonify({"error": "Unauthorized access"}), 401

    try:
        with sqlite3.connect('secure_chat.db') as conn:
            c = conn.cursor()
            c.execute("SELECT ProfilePhoto FROM users WHERE username=?", (username,))
            row = c.fetchone()
            if row and row[0]:
                # If the image is correctly stored as a base64 string
                base64ProfilePhoto = row[0]
                return jsonify({"ProfilePhoto": base64ProfilePhoto})
            else:
                # Return URL of default image if user is not found or no photo
                default_photo_url = 'https://randomuser.me/api/portraits/men/67.jpg'
                return jsonify({"ProfilePhoto": default_photo_url}), 404
    except sqlite3.DatabaseError as e:
        # Log the database error
        print(f"Database error: {e}")
        return jsonify({"error": "An error occurred while retrieving the avatar"}), 500

@app.route('/login', methods=['GET'])
def login_page():
    return render_template("login.html")

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    try:
        with sqlite3.connect('secure_chat.db') as conn:
            c = conn.cursor()
            c.execute("SELECT id, password FROM users WHERE username=?", (username,))
            row = c.fetchone()
            
            if row and pbkdf2_sha256.verify(password, row[1]):
                token = str(uuid.uuid4())
                c.execute("UPDATE users SET authToken=? WHERE id=?", (token, row[0]))
                conn.commit()

                response = make_response(redirect(url_for('index')))
                response.set_cookie('authToken', token, httponly=True, secure=True, samesite='Strict')
                return response
            else:
                return jsonify({"error": "Invalid username or password"}), 401

    except sqlite3.DatabaseError as e:
        # Log database errors here and return a generic error message
        print(f"Database error: {e}")
        return jsonify({"error": "An error occurred during login"}), 500

@app.route('/register', methods=['GET'])
def register_page():
    return render_template("register.html")

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400

    username = data.get('username')
    password = data.get('password')
    profile_photo = data.get('ProfilePhoto', '')  # Default to empty string if not provided

    # Basic validation for username and password
    if not username or not password:
        return jsonify({"error": "Invalid input"}), 400
    
    if not isinstance(username, str) or not re.match(r'^\w{3,20}$', username):
        return jsonify({"error": "Invalid username format"}), 400

    if not isinstance(password, str) or len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    password_hash = pbkdf2_sha256.hash(password)
    token = str(uuid.uuid4())

    try:
        with sqlite3.connect('secure_chat.db') as conn:
            c = conn.cursor()
            
            # Check if username already exists
            c.execute("SELECT 1 FROM users WHERE username=?", (username,))
            if c.fetchone():
                return jsonify({"error": "User already exists"}), 400

            c.execute("INSERT INTO users (username, password, authToken, ProfilePhoto) VALUES (?, ?, ?, ?)", 
                      (username, password_hash, token, profile_photo))
            conn.commit()
            
    except sqlite3.DatabaseError as e:
        # Capture a broader range of database-related errors for logging or debugging purposes
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    response = make_response(redirect(url_for('index')))
    response.set_cookie('authToken', token, httponly=True, secure=True, samesite='Strict')
    return response

@app.route('/api/users')
@login_required
def get_users():
    try:
        with sqlite3.connect('secure_chat.db') as conn:
            c = conn.cursor()
            c.execute("SELECT username, ProfilePhoto FROM users")
            users = [{"username": row[0], "ProfilePhoto": row[1] if row[1] else None} for row in c.fetchall()]
        return jsonify(users)
    except sqlite3.Error as e:
        # Обработка исключений может включать запись в лог
        print(f"Database error: {e}")
        return jsonify({"error": "An error occurred fetching users."}), 500
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({"error": "An unexpected error occurred."}), 500

@app.route('/api/message/send', methods=['POST'])
@login_required
def send_message():
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400

    sender_username = check_auth()
    receiver_username = data.get('ReceiverId')
    encrypted_data = data.get('EncryptedData')
    iv = data.get('Iv')

    if not receiver_username or not encrypted_data or not iv:
        return jsonify({"error": "Incomplete message data"}), 400

    with sqlite3.connect('secure_chat.db') as conn:
        c = conn.cursor()
        
        # Проверка существования получателя
        c.execute("SELECT username FROM users WHERE username=?", (receiver_username,))
        receiver_row = c.fetchone()

        if not receiver_row:
            return jsonify({"error": "Receiver not found"}), 404

        # Вставка сообщения в базу
        c.execute("""
            INSERT INTO messages (sender_username, receiver_username, encrypted_data, iv) 
            VALUES (?, ?, ?, ?)
        """, (sender_username, receiver_username, encrypted_data, iv))
        
        conn.commit()

    return jsonify({"status": "Message sent"})


@app.route('/api/message/receive')
@login_required
def receive_messages():
    user_id = check_auth()

    with sqlite3.connect('secure_chat.db') as conn:
        conn.row_factory = sqlite3.Row  # Позволяет получать результаты как словари
        c = conn.cursor()
        c.execute("""
            SELECT sender_username, receiver_username, encrypted_data, iv FROM messages 
            WHERE receiver_username=? OR sender_username=?
        """, (user_id, user_id))
        messages = [dict(row) for row in c.fetchall()]

    return jsonify(messages)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)