# __init__.py

import logging

# Настройка логирования для всего модуля
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.info("Module Main loaded")

# Загрузка конфигурации (пример)
import configparser
config = configparser.ConfigParser()
config.read('config.cfg')

# Теперь переменная `config` доступна для использования в других файлах модуля
