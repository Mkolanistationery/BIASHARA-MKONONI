import os
import re
import hmac
import hashlib
import base64
from datetime import datetime, timedelta
from functools import wraps

import requests
from flask import abort, request, current_app
from flask_login import current_user, login_required
from sqlalchemy import text, inspect

import config
from extensions import db
from models import utcnow, AuditLog, Business, SmsLog

EAT = timedelta(hours=3)


# ---------------------------------------------------------- muda
def to_eat(dt):
    return dt + EAT if dt else None


def fmt_dt(dt):
    return (dt + EAT).strftime('%d/%m/%Y %H:%M') if dt else ''


def fmt_date(d):
    return d.strftime('%d/%m/%Y') if d else ''


def today_eat():
    return (utcnow() + EAT).date()


def period_start(period):
    """Mwanzo wa kipindi kwa UTC (siku inaanza saa 00:00 EAT)."""
    now_eat = utcnow() + EAT
    midnight = now_eat.replace(hour=0, minute=0, second=0, microsecond=0)
    if period == 'today':
        return midnight - EAT
    if period == 'week':
        return midnight - timedelta(days=6) - EAT
    if period == 'month':
        return midnight.replace(day=1) - EAT
    return None


def parse_date(s):
    try:
        return datetime.strptime(str(s).strip(), '%Y-%m-%d').date()
    except Exception:
        return None


# ---------------------------------------------------------- data
def to_int(value, default=0):
    try:
        return int(float(str(value).replace(',', '').strip()))
    except Exception:
        return default


def normalize_phone(raw):
    d = re.sub(r'\D', '', str(raw or ''))
    if d.startswith('255') and len(d) == 12:
        return d
    if d.startswith('0') and len(d) == 10:
        return '255' + d[1:]
    if len(d) == 9 and d[0] in '67':
        return '255' + d
    return None


def valid_password(p):
    return bool(p) and len(p) >= 8 and re.search(r'[A-Za-z]', p) and re.search(r'\d', p)


def client_ip():
    return (request.remote_addr or '')[:45]


def hash_code(code):
    key = current_app.config['SECRET_KEY'].encode()
    return hmac.new(key, str(code).encode(), hashlib.sha256).hexdigest()


def audit(action, detail=''):
    try:
        uid = current_user.id if current_user.is_authenticated else None
        bid = current_user.business_id if current_user.is_authenticated else None
        db.session.add(AuditLog(business_id=bid, user_id=uid, action=action[:60],
                                detail=str(detail)[:250], ip=client_ip()))
    except Exception as e:
        print(f'audit error: {e}')


def roles_required(*roles):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapper(*a, **kw):
            if current_user.role not in roles:
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco


def own_or_404(model, obj_id):
    obj = model.query.filter_by(id=obj_id, business_id=current_user.business_id).first()
    if not obj:
        abort(404)
    return obj


# ---------------------------------------------------------- picha / QR
def logo_from_upload(f):
    data = f.read(150 * 1024 + 1)
    if not data or len(data) > 150 * 1024:
        return None, 'Picha ni kubwa mno (kiwango cha juu ni 150KB).'
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        mime = 'image/png'
    elif data.startswith(b'\xff\xd8\xff'):
        mime = 'image/jpeg'
    else:
        return None, 'Tumia picha ya PNG au JPG tu.'
    return f'data:{mime};base64,' + base64.b64encode(data).decode(), None


def qr_svg(text_in):
    try:
        import segno
        return segno.make(text_in, error='m').svg_inline(scale=3, border=1)
    except Exception as e:
        print(f'qr error: {e}')
        return None


# ---------------------------------------------------------- SMS (Beem)
BEEM_SEND_URL = 'https://apisms.beem.africa/v1/send'
BEEM_BALANCE_URL = 'https://apisms.beem.africa/public/v1/vendors/balance'
_SMS_CHAR_MAP = {'\u2018': "'", '\u2019': "'", '\u201c': '"', '\u201d': '"',
                 '\u2013': '-', '\u2014': '-', '\u2026': '...', '\u00a0': ' '}


def sms_enabled():
    return bool(os.environ.get('BEEM_API_KEY') and os.environ.get('BEEM_SECRET_KEY'))


def clean_sms_text(t):
    t = ''.join(_SMS_CHAR_MAP.get(ch, ch) for ch in (t or '')).strip()
    if not t or any(ord(ch) > 126 for ch in t):
        return None
    return t


def sms_parts(message):
    n = len(message)
    return 1 if n <= 160 else -(-n // 153)


def beem_send(numbers, message):
    """Rudisha (ok, maelezo, request_id). 'ok' inamaanisha Beem imepokea, si kwamba imefika."""
    auth = (os.environ.get('BEEM_API_KEY', ''), os.environ.get('BEEM_SECRET_KEY', ''))
    payload = {
        'source_addr': os.environ.get('BEEM_SENDER_ID', 'INFO'),
        'schedule_time': '',
        'encoding': 0,
        'message': message,
        'recipients': [{'recipient_id': i + 1, 'dest_addr': n} for i, n in enumerate(numbers)],
    }
    try:
        r = requests.post(BEEM_SEND_URL, json=payload, auth=auth, timeout=20)
    except requests.RequestException as e:
        print(f'Beem network error: {e}')
        return False, 'Imeshindikana kuwasiliana na Beem (mtandao).', None
    try:
        data = r.json()
    except ValueError:
        data = {}
    if r.status_code in (401, 403):
        return False, 'Beem imekataa funguo za jukwaa.', None
    if r.status_code == 200 and (data.get('successful') is True or data.get('code') == 100):
        return True, str(data.get('message') or 'OK')[:240], data.get('request_id')
    print(f'Beem failed: HTTP {r.status_code} {(r.text or "")[:400]}')
    reason = data.get('message') or data.get('error') or (r.text or '').strip()[:150] or 'hakuna maelezo'
    return False, f'HTTP {r.status_code}: {reason}'[:240], None


def beem_balance():
    auth = (os.environ.get('BEEM_API_KEY', ''), os.environ.get('BEEM_SECRET_KEY', ''))
    try:
        r = requests.get(BEEM_BALANCE_URL, auth=auth, timeout=8)
        if r.status_code in (401, 403):
            return None, 'Funguo zimekataliwa'
        data = r.json()
        block = data.get('data', data) if isinstance(data, dict) else {}
        for k in ('credit_balance', 'balance'):
            if k in block:
                return float(block[k]), None
    except Exception as e:
        return None, f'Imeshindikana ({type(e).__name__})'
    return None, 'Muundo wa jibu haujulikani'


def send_sms(numbers, message, business=None, user_id=None, charge=True):
    """Tuma SMS. Kama 'business' imetolewa na charge=True, credits zinakatwa kabla ya kutuma
    na kurudishwa kama Beem imekataa. Rudisha (zilizokubaliwa, zilizoshindwa, kosa la kwanza)."""
    msg = clean_sms_text(message)
    if not msg:
        return 0, len(numbers), 'Ujumbe una herufi zisizoruhusiwa (emoji au alama maalum) au ni tupu.'
    nums = []
    for n in numbers:
        n = normalize_phone(n)
        if n and n not in nums:
            nums.append(n)
    if not nums:
        return 0, 0, 'Hakuna namba sahihi.'
    if not sms_enabled():
        return 0, len(nums), 'Huduma ya SMS bado haijawashwa na msimamizi wa mfumo.'

    parts = sms_parts(msg)
    sent = failed = 0
    first_err = ''
    charged = bool(business and charge)
    bid = business.id if business else None
    label = nums[0] if len(nums) == 1 else f'Namba {len(nums)}'

    for i in range(0, len(nums), 100):
        batch = nums[i:i + 100]
        cost = parts * len(batch)
        if charged:
            rows = Business.query.filter(Business.id == bid, Business.sms_credits >= cost).update(
                {Business.sms_credits: Business.sms_credits - cost}, synchronize_session=False)
            db.session.commit()
            if not rows:
                failed += len(nums) - i
                first_err = first_err or 'SMS credits hazitoshi. Wasiliana na msimamizi kuziongeza.'
                db.session.add(SmsLog(business_id=bid, user_id=user_id, recipient=label,
                                      recipients_count=len(batch), parts=parts, message=msg,
                                      status='blocked', detail='credits hazitoshi'))
                db.session.commit()
                break
        ok, detail, req_id = beem_send(batch, msg)
        if charged and not ok:
            Business.query.filter(Business.id == bid).update(
                {Business.sms_credits: Business.sms_credits + cost}, synchronize_session=False)
        db.session.add(SmsLog(business_id=bid, user_id=user_id, recipient=label,
                              recipients_count=len(batch), parts=parts, message=msg,
                              status='accepted' if ok else 'failed', detail=detail,
                              request_id=str(req_id) if req_id else None))
        db.session.commit()
        if ok:
            sent += len(batch)
        else:
            failed += len(batch)
            first_err = first_err or detail
    if business is not None:
        try:
            db.session.refresh(business)
        except Exception:
            pass
    return sent, failed, first_err


# ---------------------------------------------------------- uhamiaji salama wa meza
def add_missing_columns():
    """Ongeza columns mpya kwenye meza zilizopo bila kufuta data (kwa masasisho ya baadaye)."""
    insp = inspect(db.engine)
    for table_name, table in db.metadata.tables.items():
        if not insp.has_table(table_name):
            continue
        existing = {c['name'] for c in insp.get_columns(table_name)}
        for col in table.columns:
            if col.name in existing:
                continue
            ctype = col.type.compile(db.engine.dialect)
            try:
                with db.engine.begin() as conn:
                    conn.execute(text(f'ALTER TABLE "{table_name}" ADD COLUMN "{col.name}" {ctype}'))
                print(f'Column mpya: {table_name}.{col.name}')
            except Exception as e:
                print(f'Migration error {table_name}.{col.name}: {e}')
