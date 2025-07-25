import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'supersecretkey')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://hao:suisui0322@db:5432/eccmfa')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'eccmfa@gmail.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', 'wkft vexf lylm waua')
    MAIL_DEFAULT_SENDER = 'eccmfa@gmail.com'