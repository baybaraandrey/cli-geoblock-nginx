import os
import configparser

BASE_DIR = os.path.dirname(__file__)
config = configparser.ConfigParser()
config.read(os.path.join(BASE_DIR, 'config.ini'))


DATABASE_URL = config.get('geoblock', 'sqlite')
NGINX_COUNTRY_VARIABLE = config.get('nginx', 'country_variable')
MODULE_NAME = config.get('geoblock', 'module_name')
TEMPLATES_FOLDER = config.get('geoblock', 'templates_folder')
