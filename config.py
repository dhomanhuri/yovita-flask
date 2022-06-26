import os

FLASK_ENV=os.getenv('FLASK_ENV')
DEBUG=1
SECRET_KEY=os.getenv('SECRET_KEY')
SECURITY_PASSWORD_SALT=os.getenv('SECURITY_PASSWORD_SALT')

DB_HOST= os.getenv('DB_HOST_DEV') if FLASK_ENV == 'development' else os.getenv('DB_HOST')
DB_DATABASE= os.getenv('DB_DATABASE_DEV') if FLASK_ENV == 'development' else os.getenv('DB_DATABASE')
DB_USERNAME= os.getenv('DB_USERNAME_DEV') if FLASK_ENV == 'development' else os.getenv('DB_USERNAME')
DB_PASSWORD= os.getenv('DB_PASSWORD_DEV') if FLASK_ENV == 'development' else os.getenv('DB_PASSWORD')

# mail settings
MAIL_SERVER = 'smtp.googlemail.com'
MAIL_PORT = 465
MAIL_USE_TLS = False
MAIL_USE_SSL = True

# gmail authentication
MAIL_USERNAME = os.environ['MAIL_USERNAME']
MAIL_PASSWORD = os.environ['MAIL_PASSWORD']

# mail accounts
MAIL_DEFAULT_SENDER = os.environ['MAIL_DEFAULT_SENDER']

UPLOAD_FOLDER = os.environ['UPLOAD_FOLDER']