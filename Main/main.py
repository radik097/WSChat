# Main\main.py
import asyncio
import logging
from server import app
import rich.traceback
import rich.logging
import rich.console
from hypercorn.config import Config
from hypercorn.asyncio import serve
import sqlite3

def init_db():
    conn = sqlite3.connect("Database.db")
    cursor = conn.cursor()
    # Создание таблицы пользователей (если она не существует)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            password TEXT NOT NULL,
            session_token TEXT UNIQUE,
            public_key TEXT NOT NULL,
            aes_key TEXT,
            friends TEXT DEFAULT "{}"
        )
    ''')

    # Создание таблицы для хранения сообщений
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_name TEXT NOT NULL,
            sender TEXT NOT NULL,
            receiver TEXT,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()

console = rich.console.Console()
# Установка rich traceback для красивого вывода ошибок
rich.traceback.install(show_locals=True)

# Настройка логирования
logging.basicConfig(level="INFO", format="%(message)s", handlers=[rich.logging.RichHandler()])
logger = logging.getLogger("server")

async def start_server():
    config = Config()
    config.bind = ["127.0.0.1:8000"]
    
    logger.info(f"Starting server at http://{config.bind[0]}")
    
    try:
        # Используем Hypercorn для запуска FastAPI
        await serve(app, config) # type: ignore
    except KeyboardInterrupt:
        logger.info("Shutting down server due to KeyboardInterrupt...")
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        console.print_exception(show_locals=True)
    finally:
        logger.info("Server shut down gracefully.")

if __name__ == "__main__":
    # Запуск сервера
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        logger.info("Shutting down server due to KeyboardInterrupt...")
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        console.print_exception(show_locals=True)
    finally:
        logger.info("Server shut down gracefully.")