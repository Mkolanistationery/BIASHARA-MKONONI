from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from extensions import db


def utcnow():
    """Muda wa UTC (bila tzinfo). Kuonyesha tunaongeza saa 3 (EAT)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Business(db.Model):
    __tablename__ = 'businesses'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    business_type = db.Column(db.String(50), default='retail')
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))
    receipt_footer = db.Column(db.String(200))
    logo_data = db.Column(db.Text)
    plan = db.Column(db.String(20), default='trial')
    status = db.Column(db.String(20), default='active')  # active | suspended
    trial_ends = db.Column(db.DateTime)
    paid_until = db.Column(db.DateTime)  # tupu = bila kikomo (kwa mipango ya kulipia)
    sms_credits = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)

    def is_usable(self):
        if self.status != 'active':
            return False
        now = utcnow()
        if self.plan == 'trial':
            return bool(self.trial_ends and now <= self.trial_ends)
        return self.paid_until is None or now <= self.paid_until


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'), nullable=True, index=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(20), index=True)
    password_hash = db.Column(db.Text, nullable=False)
    role = db.Column(db.String(20), default='owner')  # master | owner | manager | cashier
    active = db.Column(db.Boolean, default=True)
    failed_logins = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=utcnow)
    business = db.relationship('Business', backref='users')

    @property
    def is_active(self):
        return bool(self.active)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw, method='pbkdf2:sha256')

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw or '')


class Customer(db.Model):
    __tablename__ = 'customers'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'), nullable=False, index=True)
    name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(200))
    notes = db.Column(db.Text)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=utcnow)


class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'), nullable=False, index=True)
    name = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(100))
    barcode = db.Column(db.String(50))
    buy_price = db.Column(db.Integer, default=0)
    sell_price = db.Column(db.Integer, default=0)
    stock = db.Column(db.Integer, default=0)
    min_stock = db.Column(db.Integer, default=5)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=utcnow)


class Sale(db.Model):
    __tablename__ = 'sales'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    receipt_no = db.Column(db.String(20), unique=True, index=True)
    verify_code = db.Column(db.String(12))
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'))
    customer_name = db.Column(db.String(150), default='Mteja wa Cash')
    customer_phone = db.Column(db.String(20))
    payment_method = db.Column(db.String(30), default='CASH')
    total = db.Column(db.Integer, default=0)
    paid = db.Column(db.Integer, default=0)
    status = db.Column(db.String(10), default='paid')  # paid | credit | void
    void_reason = db.Column(db.String(200))
    voided_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    items = db.relationship('SaleItem', backref='sale', cascade='all, delete-orphan')
    user = db.relationship('User')


class SaleItem(db.Model):
    __tablename__ = 'sale_items'
    id = db.Column(db.Integer, primary_key=True)
    sale_id = db.Column(db.Integer, db.ForeignKey('sales.id'), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'))
    name = db.Column(db.String(150), nullable=False)
    price = db.Column(db.Integer, default=0)
    cost = db.Column(db.Integer, default=0)
    qty = db.Column(db.Integer, default=1)
    total = db.Column(db.Integer, default=0)


class Debt(db.Model):
    __tablename__ = 'debts'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'), nullable=False, index=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'))
    sale_id = db.Column(db.Integer, db.ForeignKey('sales.id'))
    kind = db.Column(db.String(10), default='deni')  # deni | mkopo
    customer_name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20))
    principal = db.Column(db.Integer, default=0)
    interest_rate = db.Column(db.Float, default=0.0)
    amount = db.Column(db.Integer, default=0)  # jumla inayodaiwa (pamoja na riba)
    paid = db.Column(db.Integer, default=0)
    due_date = db.Column(db.Date)
    note = db.Column(db.String(250))
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    payments = db.relationship('DebtPayment', backref='debt', cascade='all, delete-orphan',
                               order_by='DebtPayment.id.desc()')

    @property
    def balance(self):
        return max((self.amount or 0) - (self.paid or 0), 0)


class DebtPayment(db.Model):
    __tablename__ = 'debt_payments'
    id = db.Column(db.Integer, primary_key=True)
    debt_id = db.Column(db.Integer, db.ForeignKey('debts.id'), nullable=False, index=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    amount = db.Column(db.Integer, nullable=False)
    method = db.Column(db.String(30), default='CASH')
    created_at = db.Column(db.DateTime, default=utcnow)


class Expense(db.Model):
    __tablename__ = 'expenses'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(100))
    amount = db.Column(db.Integer, default=0)
    note = db.Column(db.String(250))
    created_at = db.Column(db.DateTime, default=utcnow, index=True)


class SmsLog(db.Model):
    __tablename__ = 'sms_logs'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'), index=True)  # tupu = SMS ya jukwaa (OTP)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    recipient = db.Column(db.String(120))
    recipients_count = db.Column(db.Integer, default=1)
    parts = db.Column(db.Integer, default=1)
    message = db.Column(db.Text)
    status = db.Column(db.String(12), default='accepted')  # accepted | failed | blocked
    detail = db.Column(db.String(250))
    request_id = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    business = db.relationship('Business')


class OtpCode(db.Model):
    __tablename__ = 'otp_codes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    code_hash = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, default=0)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=utcnow)


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'), index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(60), nullable=False)
    detail = db.Column(db.String(250))
    ip = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    user = db.relationship('User')
    business = db.relationship('Business')


class Announcement(db.Model):
    __tablename__ = 'announcements'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    body = db.Column(db.Text)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=utcnow)
