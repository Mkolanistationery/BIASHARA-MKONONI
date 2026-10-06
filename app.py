import csv
import io
import os
import re
import secrets
from datetime import timedelta

from flask import (Flask, render_template, request, redirect, url_for, flash, jsonify, abort,
                   Response)
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf.csrf import generate_csrf
from markupsafe import Markup
from sqlalchemy import func, text
from werkzeug.middleware.proxy_fix import ProxyFix

import config
from extensions import db, login_manager, csrf
from models import (utcnow, Business, User, Customer, Product, Sale, SaleItem, Debt, DebtPayment,
                    Expense, SmsLog, OtpCode, AuditLog, Announcement)
from helpers import (EAT, fmt_dt, fmt_date, today_eat, period_start, parse_date, to_int,
                     normalize_phone, valid_password, hash_code, audit, roles_required, own_or_404,
                     logo_from_upload, qr_svg, sms_enabled, send_sms, add_missing_columns)

app = Flask(__name__)
app.config.from_object(config.Config)
if not app.config['SECRET_KEY']:
    raise RuntimeError('SECRET_KEY haijawekwa. Iweke kwenye Environment Variables za Render.')
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

db.init_app(app)
csrf.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Tafadhali ingia kwanza.'
login_manager.login_message_category = 'warning'


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None


# ============================================================ templates & usalama
@app.template_filter('money')
def money(v):
    try:
        return f'{int(v or 0):,}'
    except Exception:
        return '0'


app.add_template_filter(fmt_dt, 'dt')
app.add_template_filter(fmt_date, 'd')


def csrf_input():
    return Markup(f'<input type="hidden" name="csrf_token" value="{generate_csrf()}">')


@app.context_processor
def inject():
    return dict(csrf_input=csrf_input, PAY_METHODS=config.PAY_METHODS, ROLE_LABELS=config.ROLE_LABELS,
                PLANS=config.PLANS, sms_enabled=sms_enabled(), support_phone=config.SUPPORT_PHONE,
                support_email=config.SUPPORT_EMAIL, trial_days=config.TRIAL_DAYS,
                year=(utcnow() + EAT).year)


@app.after_request
def secure_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'same-origin'
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; script-src 'self'; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'self'")
    if current_user.is_authenticated:
        resp.headers['Cache-Control'] = 'no-store'
    return resp


OPEN_EPS = {'static', 'logout', 'health', 'verify', 'terms', 'privacy', 'landing', 'login',
            'register', 'forgot_password', 'reset_password', 'profile', 'change_password'}


@app.before_request
def gate():
    if not current_user.is_authenticated:
        return None
    if not current_user.active:
        logout_user()
        flash('Akaunti yako imezimwa. Wasiliana na mmiliki wa biashara.', 'danger')
        return redirect(url_for('login'))
    ep = request.endpoint or ''
    if current_user.role == 'master':
        if ep.startswith('master.') or ep in ('static', 'logout', 'health', 'verify', 'terms', 'privacy'):
            return None
        return redirect(url_for('master.home'))
    biz = current_user.business
    if biz is None:
        logout_user()
        return redirect(url_for('login'))
    if not biz.is_usable() and ep not in OPEN_EPS:
        return render_template('errors.html', code=402, title='Akaunti ya biashara haifanyi kazi',
                               msg='Kipindi cha majaribio kimeisha, au akaunti imesimamishwa. '
                                   'Wasiliana nasi ili kuiwasha tena.'), 402
    return None


@app.errorhandler(403)
def e403(e):
    return render_template('errors.html', code=403, title='Huna ruhusa',
                           msg='Kazi hii inaruhusiwa kwa mmiliki au meneja tu.'), 403


@app.errorhandler(404)
def e404(e):
    return render_template('errors.html', code=404, title='Ukurasa haupatikani',
                           msg='Kiungo hiki hakipo au kimehamishwa.'), 404


@app.errorhandler(500)
def e500(e):
    db.session.rollback()
    return render_template('errors.html', code=500, title='Hitilafu ya mfumo',
                           msg='Tatizo limetokea upande wetu. Jaribu tena baada ya muda.'), 500


@app.route('/health')
def health():
    try:
        db.session.execute(text('SELECT 1'))
        return jsonify(status='ok')
    except Exception:
        return jsonify(status='db_error'), 500


# ============================================================ umma: landing, auth
@app.route('/')
def landing():
    if current_user.is_authenticated:
        if current_user.role == 'master':
            return redirect(url_for('master.home'))
        return redirect(url_for('dashboard'))
    return render_template('landing.html')


@app.route('/terms')
def terms():
    return render_template('legal.html', page='terms')


@app.route('/privacy')
def privacy():
    return render_template('legal.html', page='privacy')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('landing'))
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        pw = request.form.get('password') or ''
        user = User.query.filter_by(email=email).first()
        now = utcnow()
        if user and user.locked_until and user.locked_until > now:
            flash('Akaunti imefungwa kwa muda kwa sababu ya majaribio mengi. Jaribu tena baada ya dakika 15.', 'danger')
            return redirect(url_for('login'))
        if user and user.active and user.check_password(pw):
            user.failed_logins = 0
            user.locked_until = None
            user.last_login = now
            login_user(user)
            audit('login')
            db.session.commit()
            return redirect(url_for('landing'))
        if user:
            user.failed_logins = (user.failed_logins or 0) + 1
            if user.failed_logins >= 5:
                user.locked_until = now + timedelta(minutes=15)
                user.failed_logins = 0
            db.session.commit()
        flash('Barua pepe au nywila si sahihi.', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('landing'))
    if request.method == 'POST':
        f = request.form
        bname = (f.get('business_name') or '').strip()[:150]
        oname = (f.get('owner_name') or '').strip()[:150]
        email = (f.get('email') or '').strip().lower()[:150]
        phone = normalize_phone(f.get('phone'))
        pw = f.get('password') or ''
        btype = f.get('business_type') or 'retail'
        err = None
        if not bname or not oname or not email:
            err = 'Jaza jina la biashara, jina lako na barua pepe.'
        elif not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email):
            err = 'Barua pepe si sahihi.'
        elif not phone:
            err = 'Namba ya simu iwe kama 0768XXXXXX au 255768XXXXXX.'
        elif not valid_password(pw):
            err = 'Nywila iwe na angalau herufi 8, ikiwa na herufi na namba.'
        elif pw != f.get('confirm_password'):
            err = 'Nywila mbili hazilingani.'
        elif not f.get('accept'):
            err = 'Kubali Masharti na Sera ya Faragha ili kuendelea.'
        elif User.query.filter_by(email=email).first():
            err = 'Barua pepe hii tayari imesajiliwa. Ingia badala yake.'
        elif User.query.filter_by(phone=phone).first():
            err = 'Namba hii ya simu tayari imesajiliwa.'
        if err:
            flash(err, 'danger')
            return render_template('register.html', form=f), 400
        biz = Business(name=bname, business_type=btype[:50], phone=phone, plan='trial',
                       trial_ends=utcnow() + timedelta(days=config.TRIAL_DAYS),
                       sms_credits=config.STARTER_SMS_CREDITS)
        db.session.add(biz)
        db.session.flush()
        user = User(business_id=biz.id, name=oname, email=email, phone=phone, role='owner')
        user.set_password(pw)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        audit('register', bname)
        db.session.commit()
        flash(f'Karibu {bname}! Una siku {config.TRIAL_DAYS} za majaribio.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('register.html', form={})


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    audit('logout')
    db.session.commit()
    logout_user()
    flash('Umetoka kwenye mfumo.', 'info')
    return redirect(url_for('login'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        phone = normalize_phone(request.form.get('phone'))
        user = User.query.filter_by(phone=phone, active=True).first() if phone else None
        if user and user.role != 'master':
            since = utcnow() - timedelta(hours=1)
            recent = OtpCode.query.filter(OtpCode.user_id == user.id, OtpCode.created_at >= since).count()
            if recent < 3:
                code = str(secrets.randbelow(900000) + 100000)
                db.session.add(OtpCode(user_id=user.id, code_hash=hash_code(code),
                                       expires_at=utcnow() + timedelta(minutes=10)))
                db.session.commit()
                if config.DEBUG:
                    print(f'[DEV] OTP ya {phone}: {code}')
                send_sms([phone], f'Mkolani POS: kodi yako ya kubadilisha nywila ni {code}. Inaisha baada ya dakika 10.',
                         business=None, user_id=user.id, charge=False)
        flash('Kama namba hii imesajiliwa, kodi imetumwa kwa SMS. Weka kodi na nywila mpya hapa chini.', 'info')
        return redirect(url_for('reset_password'))
    return render_template('forgot.html')


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        phone = normalize_phone(request.form.get('phone'))
        code = (request.form.get('code') or '').strip()
        pw = request.form.get('password') or ''
        generic = 'Kodi si sahihi au imeisha muda. Omba kodi mpya.'
        if not valid_password(pw):
            flash('Nywila iwe na angalau herufi 8, ikiwa na herufi na namba.', 'danger')
            return render_template('reset.html'), 400
        user = User.query.filter_by(phone=phone, active=True).first() if phone else None
        otp = None
        if user:
            otp = (OtpCode.query.filter(OtpCode.user_id == user.id, OtpCode.used.is_(False),
                                        OtpCode.expires_at > utcnow(), OtpCode.attempts < 5)
                   .order_by(OtpCode.id.desc()).first())
        if not otp:
            flash(generic, 'danger')
            return render_template('reset.html'), 400
        import hmac as _hmac
        if not _hmac.compare_digest(otp.code_hash, hash_code(code)):
            otp.attempts += 1
            db.session.commit()
            flash(generic, 'danger')
            return render_template('reset.html'), 400
        otp.used = True
        user.set_password(pw)
        user.failed_logins = 0
        user.locked_until = None
        db.session.add(AuditLog(business_id=user.business_id, user_id=user.id,
                                action='password_reset', detail='kupitia SMS OTP'))
        db.session.commit()
        flash('Nywila imebadilishwa. Ingia sasa.', 'success')
        return redirect(url_for('login'))
    return render_template('reset.html')


@app.route('/verify')
def verify():
    r = (request.args.get('r') or '').strip().upper()
    c = (request.args.get('c') or '').strip().upper()
    result = None
    if r and c:
        sale = Sale.query.filter_by(receipt_no=r).first()
        if sale and sale.verify_code and secrets.compare_digest(sale.verify_code.upper().encode(), c.encode()):
            biz = db.session.get(Business, sale.business_id)
            result = dict(ok=True, business=biz.name, date=fmt_dt(sale.created_at), total=sale.total,
                          status=sale.status, receipt_no=sale.receipt_no)
        else:
            result = dict(ok=False)
    return render_template('verify.html', result=result, r=r, c=c)


# ============================================================ dashibodi
@app.route('/dashboard')
@login_required
def dashboard():
    bid = current_user.business_id
    S = db.session
    today, month = period_start('today'), period_start('month')
    valid = (Sale.business_id == bid, Sale.status != 'void')

    today_sales = S.query(func.coalesce(func.sum(Sale.total), 0)).filter(*valid, Sale.created_at >= today).scalar()
    today_count = S.query(Sale).filter(*valid, Sale.created_at >= today).count()
    today_profit = S.query(func.coalesce(func.sum((SaleItem.price - SaleItem.cost) * SaleItem.qty), 0)) \
        .join(Sale, Sale.id == SaleItem.sale_id).filter(*valid, Sale.created_at >= today).scalar()
    month_exp = S.query(func.coalesce(func.sum(Expense.amount), 0)).filter(
        Expense.business_id == bid, Expense.created_at >= month).scalar()
    owed = S.query(func.coalesce(func.sum(Debt.amount - Debt.paid), 0)).filter(Debt.business_id == bid).scalar()

    low_stock = Product.query.filter(Product.business_id == bid, Product.active.is_(True),
                                     Product.stock <= Product.min_stock).order_by(Product.stock).limit(8).all()
    open_debts = Debt.query.filter(Debt.business_id == bid, Debt.amount > Debt.paid).all()
    td = today_eat()
    overdue = sorted([d for d in open_debts if d.due_date and d.due_date < td], key=lambda d: d.due_date)[:6]

    top = S.query(SaleItem.name, func.sum(SaleItem.qty), func.sum(SaleItem.total)) \
        .join(Sale, Sale.id == SaleItem.sale_id).filter(*valid, Sale.created_at >= month) \
        .group_by(SaleItem.name).order_by(func.sum(SaleItem.total).desc()).limit(5).all()

    rows = S.query(Sale.created_at, Sale.total).filter(*valid, Sale.created_at >= today - timedelta(days=6)).all()
    buckets = {}
    for dt, tot in rows:
        d = (dt + EAT).date()
        buckets[d] = buckets.get(d, 0) + (tot or 0)
    dows = ['Jtt', 'Jnn', 'Jtn', 'Alh', 'Iju', 'Jms', 'Jpl']
    series = []
    for i in range(6, -1, -1):
        d = td - timedelta(days=i)
        series.append({'label': dows[d.weekday()], 'date': d.strftime('%d/%m'), 'value': buckets.get(d, 0)})
    mx = max([s['value'] for s in series] + [1])
    for s in series:
        s['pct'] = max(int(s['value'] * 100 / mx), 2 if s['value'] else 0)

    biz = current_user.business
    trial_left = None
    if biz.plan == 'trial' and biz.trial_ends:
        trial_left = max((biz.trial_ends - utcnow()).days, 0)
    ann = Announcement.query.filter_by(active=True).order_by(Announcement.id.desc()).limit(3).all()
    return render_template('dashboard.html', today_sales=today_sales, today_count=today_count,
                           today_profit=today_profit, month_exp=month_exp, owed=owed, low_stock=low_stock,
                           overdue=overdue, top=top, series=series, trial_left=trial_left, ann=ann)


# ============================================================ mauzo & risiti
@app.route('/sales')
@login_required
def sales():
    bid = current_user.business_id
    products = Product.query.filter_by(business_id=bid, active=True).order_by(Product.name).all()
    customers = Customer.query.filter_by(business_id=bid, active=True).order_by(Customer.name).all()
    recent = Sale.query.filter_by(business_id=bid).order_by(Sale.id.desc()).limit(10).all()
    pdata = [dict(id=p.id, name=p.name, price=p.sell_price, stock=p.stock, barcode=p.barcode or '')
             for p in products]
    return render_template('sales.html', products=pdata, customers=customers, recent=recent,
                           can_price=current_user.role in ('owner', 'manager'))


@app.route('/sales/save', methods=['POST'])
@login_required
def sales_save():
    data = request.get_json(silent=True) or {}
    items = data.get('items')
    if not isinstance(items, list) or not items or len(items) > 100:
        return jsonify(ok=False, error='Kikapu kiko wazi.'), 400
    bid = current_user.business_id
    can_price = current_user.role in ('owner', 'manager')
    payment = data.get('payment_method')
    payment = payment if payment in config.PAY_METHODS else 'CASH'
    is_credit = payment == 'DENI'
    try:
        customer = None
        cid = to_int(data.get('customer_id'))
        if cid:
            customer = Customer.query.filter_by(id=cid, business_id=bid, active=True).first()
        cust_name = customer.name if customer else (str(data.get('customer_name') or '').strip()[:150] or 'Mteja wa Cash')
        cust_phone = customer.phone if customer else (normalize_phone(data.get('customer_phone')) or '')

        pids = {to_int(i.get('product_id')) for i in items if isinstance(i, dict) and to_int(i.get('product_id'))}
        prods = {}
        if pids:
            q = Product.query.filter(Product.business_id == bid, Product.id.in_(pids),
                                     Product.active.is_(True)).with_for_update()
            prods = {p.id: p for p in q.all()}

        need, lines, total = {}, [], 0
        for it in items:
            if not isinstance(it, dict):
                raise ValueError('Kikapu kina taarifa zisizo sahihi.')
            qty = to_int(it.get('qty'))
            if qty <= 0 or qty > 100000:
                raise ValueError('Idadi ya bidhaa si sahihi.')
            pid = to_int(it.get('product_id'))
            if pid:
                p = prods.get(pid)
                if not p:
                    raise ValueError('Bidhaa moja haipo tena kwenye stoko.')
                price = to_int(it.get('price')) if can_price else p.sell_price
                if price <= 0:
                    price = p.sell_price
                name, cost = p.name, p.buy_price or 0
                need[pid] = need.get(pid, 0) + qty
            else:
                name = str(it.get('name') or '').strip()[:150]
                price, cost = to_int(it.get('price')), 0
                if not name or price <= 0:
                    raise ValueError('Jina na bei vinahitajika kwa kila bidhaa.')
            if price > 2_000_000_000:
                raise ValueError('Bei ni kubwa mno.')
            lines.append((pid or None, name, price, cost, qty))
            total += price * qty
        for pid, q in need.items():
            if (prods[pid].stock or 0) < q:
                raise ValueError(f'Stoko ya "{prods[pid].name}" haitoshi. Iliyobaki: {prods[pid].stock}.')

        paid_now, due = total, None
        if is_credit:
            paid_now = max(0, min(to_int(data.get('paid')), total))
            if paid_now >= total:
                is_credit, payment = False, 'CASH'
            else:
                if not customer:
                    if cust_name == 'Mteja wa Cash' or not cust_phone:
                        raise ValueError('Kwa DENI, chagua mteja aliyesajiliwa au andika jina na namba yake ya simu.')
                    customer = Customer(business_id=bid, name=cust_name, phone=cust_phone)
                    db.session.add(customer)
                    db.session.flush()
                due = parse_date(data.get('due_date'))

        sale = Sale(business_id=bid, user_id=current_user.id, customer_id=customer.id if customer else None,
                    customer_name=cust_name, customer_phone=cust_phone, payment_method=payment,
                    total=total, paid=paid_now, status='credit' if is_credit else 'paid',
                    verify_code=secrets.token_hex(4).upper())
        for pid, name, price, cost, qty in lines:
            sale.items.append(SaleItem(product_id=pid, name=name, price=price, cost=cost, qty=qty, total=price * qty))
        db.session.add(sale)
        db.session.flush()
        sale.receipt_no = f'MK{sale.id:07d}'
        for pid, q in need.items():
            prods[pid].stock = (prods[pid].stock or 0) - q
        if is_credit:
            db.session.add(Debt(business_id=bid, customer_id=customer.id, sale_id=sale.id, kind='deni',
                                customer_name=cust_name, phone=cust_phone, principal=total - paid_now,
                                amount=total - paid_now, paid=0, due_date=due,
                                note=f'Deni la risiti {sale.receipt_no}'))
        audit('sale', f'{sale.receipt_no} TZS {total:,} {payment}')
        db.session.commit()
    except ValueError as e:
        db.session.rollback()
        return jsonify(ok=False, error=str(e)), 400
    except Exception as e:
        db.session.rollback()
        print(f'sale error: {e}')
        return jsonify(ok=False, error='Kuna tatizo la seva. Jaribu tena.'), 500

    if data.get('send_sms') and cust_phone and sms_enabled():
        try:
            send_sms([cust_phone], f'{current_user.business.name[:30]}: Risiti {sale.receipt_no}, TZS {total:,}. Asante!',
                     business=current_user.business, user_id=current_user.id)
        except Exception as e:
            print(f'receipt sms error: {e}')
    return jsonify(ok=True, url=url_for('receipt', sale_id=sale.id))


@app.route('/receipt/<int:sale_id>')
@login_required
def receipt(sale_id):
    sale = own_or_404(Sale, sale_id)
    url = url_for('verify', r=sale.receipt_no, c=sale.verify_code, _external=True)
    return render_template('receipt.html', sale=sale, biz=current_user.business, qr=qr_svg(url), verify_url=url)


@app.route('/sales/<int:sale_id>/void', methods=['POST'])
@roles_required('owner', 'manager')
def sale_void(sale_id):
    sale = own_or_404(Sale, sale_id)
    reason = (request.form.get('reason') or '').strip()[:200]
    if sale.status == 'void':
        flash('Risiti hii tayari imebatilishwa.', 'warning')
    elif not reason:
        flash('Andika sababu ya kubatilisha risiti.', 'warning')
    else:
        debt = Debt.query.filter_by(business_id=current_user.business_id, sale_id=sale.id).first()
        if debt and debt.paid > 0:
            flash('Risiti hii ina deni lenye malipo tayari. Haiwezi kubatilishwa hapa.', 'danger')
            return redirect(request.referrer or url_for('reports'))
        for it in sale.items:
            if it.product_id:
                p = Product.query.filter_by(id=it.product_id, business_id=current_user.business_id).first()
                if p:
                    p.stock = (p.stock or 0) + it.qty
        if debt:
            db.session.delete(debt)
        sale.status, sale.void_reason, sale.voided_at = 'void', reason, utcnow()
        audit('sale_void', f'{sale.receipt_no}: {reason}')
        db.session.commit()
        flash('Risiti imebatilishwa na stoko imerudishwa.', 'success')
    return redirect(url_for('reports'))


# ============================================================ bidhaa & stoko
@app.route('/products', methods=['GET', 'POST'])
@login_required
def products():
    bid = current_user.business_id
    if request.method == 'POST':
        if current_user.role not in ('owner', 'manager'):
            abort(403)
        f = request.form
        name = (f.get('name') or '').strip()[:150]
        if not name:
            flash('Jina la bidhaa linahitajika.', 'warning')
            return redirect(url_for('products'))
        db.session.add(Product(business_id=bid, name=name, category=(f.get('category') or '').strip()[:100],
                               barcode=(f.get('barcode') or '').strip()[:50],
                               buy_price=max(to_int(f.get('buy_price')), 0),
                               sell_price=max(to_int(f.get('sell_price')), 0),
                               stock=max(to_int(f.get('stock')), 0),
                               min_stock=max(to_int(f.get('min_stock'), 5), 0)))
        audit('product_add', name)
        db.session.commit()
        flash('Bidhaa imeongezwa.', 'success')
        return redirect(url_for('products'))
    q = (request.args.get('q') or '').strip()
    query = Product.query.filter_by(business_id=bid, active=True)
    if q:
        like = f'%{q}%'
        query = query.filter(Product.name.ilike(like) | Product.barcode.ilike(like) | Product.category.ilike(like))
    plist = query.order_by(Product.name).all()
    stock_value = sum((p.stock or 0) * (p.buy_price or 0) for p in plist)
    low = sum(1 for p in plist if (p.stock or 0) <= (p.min_stock or 0))
    return render_template('products.html', plist=plist, q=q, stock_value=stock_value, low=low)


@app.route('/products/<int:pid>/edit', methods=['POST'])
@roles_required('owner', 'manager')
def product_edit(pid):
    p = own_or_404(Product, pid)
    f = request.form
    name = (f.get('name') or '').strip()[:150]
    if not name:
        flash('Jina la bidhaa linahitajika.', 'warning')
        return redirect(url_for('products'))
    p.name, p.category = name, (f.get('category') or '').strip()[:100]
    p.barcode = (f.get('barcode') or '').strip()[:50]
    p.buy_price, p.sell_price = max(to_int(f.get('buy_price')), 0), max(to_int(f.get('sell_price')), 0)
    p.stock, p.min_stock = max(to_int(f.get('stock')), 0), max(to_int(f.get('min_stock'), 5), 0)
    audit('product_edit', name)
    db.session.commit()
    flash('Bidhaa imebadilishwa.', 'success')
    return redirect(url_for('products'))


@app.route('/products/<int:pid>/restock', methods=['POST'])
@roles_required('owner', 'manager')
def product_restock(pid):
    p = own_or_404(Product, pid)
    qty = to_int(request.form.get('qty'))
    if qty <= 0:
        flash('Weka idadi sahihi ya kuongeza.', 'warning')
    else:
        p.stock = (p.stock or 0) + qty
        audit('restock', f'{p.name} +{qty}')
        db.session.commit()
        flash(f'Stoko ya {p.name} imeongezeka kwa {qty}.', 'success')
    return redirect(url_for('products'))


@app.route('/products/<int:pid>/delete', methods=['POST'])
@roles_required('owner', 'manager')
def product_delete(pid):
    p = own_or_404(Product, pid)
    p.active = False
    audit('product_delete', p.name)
    db.session.commit()
    flash('Bidhaa imeondolewa kwenye orodha (historia ya mauzo imebaki).', 'success')
    return redirect(url_for('products'))


# ============================================================ wateja
@app.route('/customers', methods=['GET', 'POST'])
@login_required
def customers():
    bid = current_user.business_id
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()[:150]
        phone = normalize_phone(request.form.get('phone'))
        if not name or not phone:
            flash('Jina na namba sahihi ya simu vinahitajika.', 'warning')
        elif Customer.query.filter_by(business_id=bid, phone=phone, active=True).first():
            flash('Mteja mwenye namba hii tayari yupo.', 'warning')
        else:
            db.session.add(Customer(business_id=bid, name=name, phone=phone,
                                    address=(request.form.get('address') or '').strip()[:200],
                                    notes=(request.form.get('notes') or '').strip()[:500]))
            audit('customer_add', name)
            db.session.commit()
            flash('Mteja amesajiliwa.', 'success')
        return redirect(url_for('customers'))
    q = (request.args.get('q') or '').strip()
    query = Customer.query.filter_by(business_id=bid, active=True)
    if q:
        query = query.filter(Customer.name.ilike(f'%{q}%') | Customer.phone.ilike(f'%{q}%'))
    clist = query.order_by(Customer.name).all()
    spent = dict(db.session.query(Sale.customer_id, func.sum(Sale.total)).filter(
        Sale.business_id == bid, Sale.status != 'void', Sale.customer_id.isnot(None)).group_by(Sale.customer_id).all())
    owed = dict(db.session.query(Debt.customer_id, func.sum(Debt.amount - Debt.paid)).filter(
        Debt.business_id == bid, Debt.customer_id.isnot(None)).group_by(Debt.customer_id).all())
    return render_template('customers.html', clist=clist, spent=spent, owed=owed, q=q)


@app.route('/customers/<int:cid>/edit', methods=['POST'])
@roles_required('owner', 'manager')
def customer_edit(cid):
    c = own_or_404(Customer, cid)
    name = (request.form.get('name') or '').strip()[:150]
    phone = normalize_phone(request.form.get('phone'))
    if not name or not phone:
        flash('Jina na namba sahihi ya simu vinahitajika.', 'warning')
    else:
        c.name, c.phone = name, phone
        c.address = (request.form.get('address') or '').strip()[:200]
        c.notes = (request.form.get('notes') or '').strip()[:500]
        audit('customer_edit', name)
        db.session.commit()
        flash('Taarifa za mteja zimebadilishwa.', 'success')
    return redirect(url_for('customers'))


@app.route('/customers/<int:cid>/delete', methods=['POST'])
@roles_required('owner', 'manager')
def customer_delete(cid):
    c = own_or_404(Customer, cid)
    c.active = False
    audit('customer_delete', c.name)
    db.session.commit()
    flash('Mteja ameondolewa kwenye orodha.', 'success')
    return redirect(url_for('customers'))


# ============================================================ madeni & mikopo
@app.route('/debts', methods=['GET', 'POST'])
@login_required
def debts():
    bid = current_user.business_id
    if request.method == 'POST':
        if current_user.role not in ('owner', 'manager'):
            abort(403)
        f = request.form
        cust = None
        cid = to_int(f.get('customer_id'))
        if cid:
            cust = Customer.query.filter_by(id=cid, business_id=bid, active=True).first()
        name = cust.name if cust else (f.get('customer_name') or '').strip()[:150]
        phone = cust.phone if cust else (normalize_phone(f.get('phone')) or '')
        principal = to_int(f.get('amount'))
        rate = 0.0
        try:
            rate = min(max(float(f.get('interest_rate') or 0), 0.0), 1000.0)
        except ValueError:
            pass
        if not name or principal <= 0:
            flash('Jina la mdaiwa na kiasi sahihi vinahitajika.', 'warning')
            return redirect(url_for('debts'))
        kind = 'mkopo' if f.get('kind') == 'mkopo' else 'deni'
        total = int(round(principal + principal * rate / 100.0))
        db.session.add(Debt(business_id=bid, customer_id=cust.id if cust else None, kind=kind,
                            customer_name=name, phone=phone, principal=principal, interest_rate=rate,
                            amount=total, paid=0, due_date=parse_date(f.get('due_date')),
                            note=(f.get('note') or '').strip()[:250]))
        audit('debt_add', f'{name} TZS {total:,}')
        db.session.commit()
        flash('Deni/mkopo limerekodiwa.', 'success')
        return redirect(url_for('debts'))
    show = request.args.get('show', 'open')
    query = Debt.query.filter_by(business_id=bid)
    if show != 'all':
        query = query.filter(Debt.amount > Debt.paid)
    dlist = query.order_by(Debt.id.desc()).limit(300).all()
    customers_ = Customer.query.filter_by(business_id=bid, active=True).order_by(Customer.name).all()
    total_owed = db.session.query(func.coalesce(func.sum(Debt.amount - Debt.paid), 0)).filter(
        Debt.business_id == bid).scalar()
    return render_template('debts.html', dlist=dlist, customers=customers_, show=show,
                           total_owed=total_owed, today=today_eat())


@app.route('/debts/<int:did>/pay', methods=['POST'])
@login_required
def debt_pay(did):
    d = own_or_404(Debt, did)
    amount = to_int(request.form.get('amount'))
    method = request.form.get('method') if request.form.get('method') in config.PAY_METHODS else 'CASH'
    if method == 'DENI':
        method = 'CASH'
    if amount <= 0:
        flash('Weka kiasi sahihi cha malipo.', 'warning')
    elif amount > d.balance:
        flash(f'Kiasi kinazidi deni lililobaki (TZS {d.balance:,}).', 'warning')
    else:
        d.paid = (d.paid or 0) + amount
        db.session.add(DebtPayment(debt_id=d.id, business_id=d.business_id, user_id=current_user.id,
                                   amount=amount, method=method))
        audit('debt_pay', f'{d.customer_name} TZS {amount:,}')
        db.session.commit()
        flash(f'Malipo ya TZS {amount:,} yamepokelewa.', 'success')
    return redirect(url_for('debts'))


@app.route('/debts/<int:did>/delete', methods=['POST'])
@roles_required('owner')
def debt_delete(did):
    d = own_or_404(Debt, did)
    if d.paid > 0 or d.sale_id:
        flash('Deni lenye malipo au lililotokana na risiti haliwezi kufutwa. Batilisha risiti badala yake.', 'danger')
    else:
        audit('debt_delete', f'{d.customer_name} TZS {d.amount:,}')
        db.session.delete(d)
        db.session.commit()
        flash('Rekodi imefutwa.', 'success')
    return redirect(url_for('debts'))


# ============================================================ matumizi
@app.route('/expenses', methods=['GET', 'POST'])
@roles_required('owner', 'manager')
def expenses():
    bid = current_user.business_id
    if request.method == 'POST':
        title = (request.form.get('title') or '').strip()[:150]
        amount = to_int(request.form.get('amount'))
        if not title or amount <= 0:
            flash('Maelezo na kiasi sahihi vinahitajika.', 'warning')
        else:
            db.session.add(Expense(business_id=bid, user_id=current_user.id, title=title,
                                   category=(request.form.get('category') or '').strip()[:100],
                                   amount=amount, note=(request.form.get('note') or '').strip()[:250]))
            audit('expense_add', f'{title} TZS {amount:,}')
            db.session.commit()
            flash('Matumizi yamerekodiwa.', 'success')
        return redirect(url_for('expenses'))
    elist = Expense.query.filter_by(business_id=bid).order_by(Expense.id.desc()).limit(200).all()
    month_total = db.session.query(func.coalesce(func.sum(Expense.amount), 0)).filter(
        Expense.business_id == bid, Expense.created_at >= period_start('month')).scalar()
    return render_template('expenses.html', elist=elist, month_total=month_total)


@app.route('/expenses/<int:eid>/delete', methods=['POST'])
@roles_required('owner')
def expense_delete(eid):
    e = own_or_404(Expense, eid)
    audit('expense_delete', f'{e.title} TZS {e.amount:,}')
    db.session.delete(e)
    db.session.commit()
    flash('Matumizi yamefutwa.', 'success')
    return redirect(url_for('expenses'))


# ============================================================ ripoti
def _report_data(period):
    bid = current_user.business_id
    start = period_start(period)
    sq = Sale.query.filter(Sale.business_id == bid)
    if start:
        sq = sq.filter(Sale.created_at >= start)
    all_sales = sq.order_by(Sale.id.desc()).all()
    valid = [s for s in all_sales if s.status != 'void']
    total_sales = sum(s.total or 0 for s in valid)
    profit = sum(sum((i.price - (i.cost or 0)) * i.qty for i in s.items) for s in valid)
    eq = db.session.query(func.coalesce(func.sum(Expense.amount), 0)).filter(Expense.business_id == bid)
    if start:
        eq = eq.filter(Expense.created_at >= start)
    pay, top = {}, {}
    for s in valid:
        pay[s.payment_method] = pay.get(s.payment_method, 0) + (s.total or 0)
        for i in s.items:
            row = top.setdefault(i.name, [0, 0])
            row[0] += i.qty
            row[1] += i.total or 0
    return dict(all_sales=all_sales, valid=valid, total_sales=total_sales, profit=profit,
                expenses=eq.scalar(), pay=pay,
                top=sorted(top.items(), key=lambda kv: kv[1][1], reverse=True)[:8])


@app.route('/reports')
@roles_required('owner', 'manager')
def reports():
    period = request.args.get('period', 'month')
    period = period if period in ('today', 'week', 'month', 'all') else 'month'
    d = _report_data(period)
    return render_template('reports.html', period=period, sales_list=d['all_sales'][:100],
                           count=len(d['valid']), total_sales=d['total_sales'], profit=d['profit'],
                           expenses=d['expenses'], net=d['profit'] - d['expenses'], pay=d['pay'], top=d['top'])


@app.route('/reports/export.csv')
@roles_required('owner', 'manager')
def reports_csv():
    period = request.args.get('period', 'month')
    period = period if period in ('today', 'week', 'month', 'all') else 'month'
    d = _report_data(period)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(['Risiti', 'Tarehe', 'Mteja', 'Malipo', 'Jumla', 'Kilicholipwa', 'Hali'])
    for s in d['all_sales']:
        safe = [s.receipt_no, fmt_dt(s.created_at), s.customer_name, s.payment_method, s.total, s.paid, s.status]
        w.writerow([("'" + str(v)) if isinstance(v, str) and v[:1] in '=+-@' else v for v in safe])
    audit('export_csv', period)
    db.session.commit()
    return Response('\ufeff' + buf.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename=mauzo-{period}.csv'})


# ============================================================ SMS
@app.route('/sms')
@roles_required('owner', 'manager')
def sms():
    bid = current_user.business_id
    logs = SmsLog.query.filter_by(business_id=bid).order_by(SmsLog.id.desc()).limit(30).all()
    customers_ = Customer.query.filter_by(business_id=bid, active=True).order_by(Customer.name).all()
    return render_template('sms.html', logs=logs, customers=customers_, biz=current_user.business)


@app.route('/sms/send', methods=['POST'])
@roles_required('owner', 'manager')
def sms_send():
    bid = current_user.business_id
    rtype = request.form.get('recipient_type', 'all')
    if rtype == 'all':
        raw = [c.phone for c in Customer.query.filter_by(business_id=bid, active=True).all()]
    elif rtype == 'debtors':
        raw = [d.phone for d in Debt.query.filter(Debt.business_id == bid, Debt.amount > Debt.paid).all() if d.phone]
    elif rtype == 'single':
        raw = [request.form.get('single_phone')]
    else:
        raw = re.split(r'[,\n;\s]+', request.form.get('custom_phones') or '')
    raw = [r for r in raw if r]
    if len(raw) > 500:
        flash('Unaweza kutuma kwa watu 500 kwa wakati mmoja. Gawanya orodha.', 'warning')
        return redirect(url_for('sms'))
    sent, failed, err = send_sms(raw, request.form.get('message') or '', business=current_user.business,
                                 user_id=current_user.id)
    audit('sms_send', f'zimekubaliwa {sent}, zimeshindwa {failed}')
    db.session.commit()
    if sent and not failed:
        flash(f'SMS zimekabidhiwa kwa Beem kwa watu {sent}. Hali ya kufika simuni angalia kwenye dashibodi ya Beem.', 'success')
    elif sent:
        flash(f'Zimekubaliwa {sent}, zimeshindwa {failed}. Sababu: {err}', 'warning')
    else:
        flash(f'SMS hazikutumwa. {err}', 'danger')
    return redirect(url_for('sms'))


@app.route('/sms/remind-debts', methods=['POST'])
@roles_required('owner', 'manager')
def sms_remind():
    bid = current_user.business_id
    td = today_eat()
    due = [d for d in Debt.query.filter(Debt.business_id == bid, Debt.amount > Debt.paid).all()
           if d.phone and d.due_date and d.due_date <= td][:50]
    if not due:
        flash('Hakuna madeni yaliyofika au kupita tarehe ya malipo yenye namba ya simu.', 'info')
        return redirect(url_for('sms'))
    sent = failed = 0
    last_err = ''
    for d in due:
        first = (d.customer_name or '').split(' ')[0][:20]
        msg = (f'{current_user.business.name[:30]}: Habari {first}, una deni la TZS {d.balance:,} '
               f'lililofika tarehe {d.due_date.strftime("%d/%m/%Y")}. Tafadhali lipa. Asante.')
        s, f_, e = send_sms([d.phone], msg, business=current_user.business, user_id=current_user.id)
        sent += s
        failed += f_
        last_err = e or last_err
        if 'credits' in (e or ''):
            break
    audit('sms_remind', f'zimekubaliwa {sent}, zimeshindwa {failed}')
    db.session.commit()
    flash(f'Vikumbusho: {sent} vimekubaliwa, {failed} vimeshindwa.' + (f' {last_err}' if failed else ''),
          'success' if not failed else 'warning')
    return redirect(url_for('sms'))


# ============================================================ wafanyakazi
@app.route('/staff', methods=['GET', 'POST'])
@roles_required('owner')
def staff():
    biz = current_user.business
    bid = biz.id
    if request.method == 'POST':
        f = request.form
        name = (f.get('name') or '').strip()[:150]
        email = (f.get('email') or '').strip().lower()[:150]
        phone = normalize_phone(f.get('phone'))
        role = f.get('role') if f.get('role') in ('manager', 'cashier') else 'cashier'
        pw = f.get('password') or ''
        cap = config.PLANS.get(biz.plan, config.PLANS['trial'])['staff']
        active_n = User.query.filter_by(business_id=bid, active=True).count()
        err = None
        if active_n >= cap + 1:
            err = f'Mpango wako unaruhusu wafanyakazi {cap} tu. Wasiliana nasi kuongeza.'
        elif not name or not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email) or not phone:
            err = 'Jaza jina, barua pepe sahihi na namba ya simu.'
        elif not valid_password(pw):
            err = 'Nywila iwe na angalau herufi 8, ikiwa na herufi na namba.'
        elif User.query.filter_by(email=email).first() or User.query.filter_by(phone=phone).first():
            err = 'Barua pepe au namba hii tayari inatumika.'
        if err:
            flash(err, 'danger')
        else:
            u = User(business_id=bid, name=name, email=email, phone=phone, role=role)
            u.set_password(pw)
            db.session.add(u)
            audit('staff_add', f'{name} ({role})')
            db.session.commit()
            flash('Mfanyakazi ameongezwa. Mpe nywila yake kwa usalama.', 'success')
        return redirect(url_for('staff'))
    users = User.query.filter_by(business_id=bid).order_by(User.id).all()
    cap = config.PLANS.get(biz.plan, config.PLANS['trial'])['staff']
    return render_template('staff.html', users=users, cap=cap)


@app.route('/staff/<int:uid>/toggle', methods=['POST'])
@roles_required('owner')
def staff_toggle(uid):
    u = User.query.filter_by(id=uid, business_id=current_user.business_id).first_or_404()
    if u.id == current_user.id:
        flash('Huwezi kuzima akaunti yako mwenyewe.', 'warning')
    else:
        u.active = not u.active
        audit('staff_toggle', f'{u.name} -> {"hai" if u.active else "imezimwa"}')
        db.session.commit()
        flash('Imebadilishwa.', 'success')
    return redirect(url_for('staff'))


@app.route('/staff/<int:uid>/password', methods=['POST'])
@roles_required('owner')
def staff_password(uid):
    u = User.query.filter_by(id=uid, business_id=current_user.business_id).first_or_404()
    pw = request.form.get('password') or ''
    if u.id == current_user.id:
        flash('Tumia ukurasa wa Mipangilio kubadilisha nywila yako.', 'warning')
    elif not valid_password(pw):
        flash('Nywila iwe na angalau herufi 8, ikiwa na herufi na namba.', 'danger')
    else:
        u.set_password(pw)
        u.failed_logins, u.locked_until = 0, None
        audit('staff_password', u.name)
        db.session.commit()
        flash('Nywila mpya imewekwa.', 'success')
    return redirect(url_for('staff'))


@app.route('/activity')
@roles_required('owner')
def activity():
    logs = AuditLog.query.filter_by(business_id=current_user.business_id).order_by(AuditLog.id.desc()).limit(150).all()
    return render_template('activity.html', logs=logs)


# ============================================================ mipangilio
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        if current_user.role != 'owner':
            abort(403)
        biz = current_user.business
        action = request.form.get('action')
        if action == 'info':
            name = (request.form.get('name') or '').strip()[:150]
            if not name:
                flash('Jina la biashara linahitajika.', 'warning')
            else:
                biz.name = name
                biz.business_type = (request.form.get('business_type') or 'retail')[:50]
                biz.phone = normalize_phone(request.form.get('phone')) or biz.phone
                biz.address = (request.form.get('address') or '').strip()[:200]
                biz.receipt_footer = (request.form.get('receipt_footer') or '').strip()[:200]
                audit('profile_update')
                db.session.commit()
                flash('Taarifa za biashara zimehifadhiwa.', 'success')
        elif action == 'logo':
            f = request.files.get('logo')
            if not f or not f.filename:
                flash('Chagua picha kwanza.', 'warning')
            else:
                data, err = logo_from_upload(f)
                if err:
                    flash(err, 'danger')
                else:
                    biz.logo_data = data
                    audit('logo_update')
                    db.session.commit()
                    flash('Nembo imehifadhiwa.', 'success')
        elif action == 'logo_remove':
            biz.logo_data = None
            db.session.commit()
            flash('Nembo imeondolewa.', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', biz=current_user.business)


@app.route('/profile/password', methods=['POST'])
@login_required
def change_password():
    old, new = request.form.get('old_password'), request.form.get('new_password') or ''
    if not current_user.check_password(old):
        flash('Nywila ya sasa si sahihi.', 'danger')
    elif not valid_password(new):
        flash('Nywila mpya iwe na angalau herufi 8, ikiwa na herufi na namba.', 'danger')
    else:
        current_user.set_password(new)
        audit('password_change')
        db.session.commit()
        flash('Nywila imebadilishwa.', 'success')
    return redirect(url_for('profile'))


# ============================================================ kuanzisha
from master import bp as master_bp  # noqa: E402

app.register_blueprint(master_bp, url_prefix=config.MASTER_PATH)


def bootstrap_master():
    email = os.environ.get('MASTER_EMAIL', '').strip().lower()
    pw = os.environ.get('MASTER_PASSWORD', '')
    if not email or not pw or User.query.filter_by(role='master').first():
        return
    if not valid_password(pw):
        print('MASTER_PASSWORD ni dhaifu (angalau herufi 8 zenye herufi na namba). Master haikuundwa.')
        return
    if User.query.filter_by(email=email).first():
        print('MASTER_EMAIL tayari inatumika na akaunti nyingine. Master haikuundwa.')
        return
    u = User(name='Master', email=email, role='master', business_id=None)
    u.set_password(pw)
    db.session.add(u)
    db.session.commit()
    print('Akaunti ya Master imeundwa. Ondoa MASTER_PASSWORD kwenye Environment sasa.')


with app.app_context():
    try:
        db.create_all()
        add_missing_columns()
        bootstrap_master()
    except Exception as exc:
        print(f'Startup DB error: {exc}')

if __name__ == '__main__':
    app.run(debug=config.DEBUG)
