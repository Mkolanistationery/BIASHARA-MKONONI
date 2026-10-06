import os
from datetime import timedelta

DEBUG = os.environ.get('FLASK_DEBUG') == '1'


def _db_url():
    url = os.environ.get('DATABASE_URL', 'sqlite:///mkolani.db')
    if url.startswith('postgres://'):
        url = url.replace('postgres://', 'postgresql://', 1)
    return url


PLANS = {
    'trial': {'name': 'Majaribio', 'staff': 2},
    'basic': {'name': 'Msingi', 'staff': 3},
    'pro': {'name': 'Pro', 'staff': 10},
}
TRIAL_DAYS = int(os.environ.get('TRIAL_DAYS', '14'))
STARTER_SMS_CREDITS = int(os.environ.get('STARTER_SMS_CREDITS', '0'))
PAY_METHODS = ['CASH', 'M-PESA', 'TIGO PESA', 'AIRTEL MONEY', 'HALOPESA', 'BANK', 'DENI']
ROLE_LABELS = {'master': 'Master', 'owner': 'Mmiliki', 'manager': 'Meneja', 'cashier': 'Muuzaji'}
MASTER_PATH = '/' + os.environ.get('MASTER_PATH', '_master').strip('/')
SUPPORT_PHONE = os.environ.get('SUPPORT_PHONE', '+255 625 567 603')
SUPPORT_EMAIL = os.environ.get('SUPPORT_EMAIL', '')


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or ('dev-only-key-change-me' if DEBUG else None)
    SQLALCHEMY_DATABASE_URI = _db_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {'pool_pre_ping': True, 'pool_recycle': 280}
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = not DEBUG
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024
    WTF_CSRF_TIME_LIMIT = None
