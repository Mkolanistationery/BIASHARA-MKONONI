"""Master Dashboard (ya ndani). Mtu yeyote asiye Master anapata 404, kana kwamba ukurasa haupo.
Master anahitaji kuthibitisha nywila yake tena (dakika 30) kabla ya kuingia."""
import time
from datetime import timedelta
from functools import wraps

from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort
from flask_login import current_user
from sqlalchemy import func

import config
from extensions import db
from models import (utcnow, Business, User, Sale, SmsLog, AuditLog, Announcement)
from helpers import period_start, to_int, parse_date, audit, beem_balance, sms_enabled

bp = Blueprint('master', __name__)
UNLOCK_SECONDS = 30 * 60


def master_only(fn):
    @wraps(fn)
    def w(*a, **k):
        if not current_user.is_authenticated or current_user.role != 'master':
            abort(404)
        return fn(*a, **k)
    return w


def master_required(fn):
    @wraps(fn)
    @master_only
    def w(*a, **k):
        if session.get('master_until', 0) < time.time():
            return redirect(url_for('master.unlock'))
        return fn(*a, **k)
    return w


@bp.route('/unlock', methods=['GET', 'POST'])
@master_only
def unlock():
    if request.method == 'POST':
        now = utcnow()
        if current_user.locked_until and current_user.locked_until > now:
            flash('Imefungwa kwa muda kwa majaribio mengi. Subiri dakika 15.', 'danger')
            return render_template('master/unlock.html'), 429
        if current_user.check_password(request.form.get('password')):
            current_user.failed_logins = 0
            session['master_until'] = time.time() + UNLOCK_SECONDS
            audit('master_unlock')
            db.session.commit()
            return redirect(url_for('master.home'))
        current_user.failed_logins = (current_user.failed_logins or 0) + 1
        if current_user.failed_logins >= 5:
            current_user.locked_until = now + timedelta(minutes=15)
            current_user.failed_logins = 0
        audit('master_unlock_failed')
        db.session.commit()
        flash('Nywila si sahihi.', 'danger')
    return render_template('master/unlock.html')


@bp.route('/')
@master_required
def home():
    now, today = utcnow(), period_start('today')
    S = db.session
    stats = dict(
        biz_total=Business.query.count(),
        trial_active=Business.query.filter(Business.plan == 'trial', Business.status == 'active',
                                           Business.trial_ends >= now).count(),
        trial_expired=Business.query.filter(Business.plan == 'trial', Business.trial_ends < now).count(),
        paid=Business.query.filter(Business.plan != 'trial', Business.status == 'active').count(),
        suspended=Business.query.filter_by(status='suspended').count(),
        users=User.query.filter(User.role != 'master').count(),
        signups7=Business.query.filter(Business.created_at >= now - timedelta(days=7)).count(),
        signups30=Business.query.filter(Business.created_at >= now - timedelta(days=30)).count(),
        sales_today=S.query(func.coalesce(func.sum(Sale.total), 0)).filter(
            Sale.status != 'void', Sale.created_at >= today).scalar(),
        sales_today_n=Sale.query.filter(Sale.status != 'void', Sale.created_at >= today).count(),
        sms_today=S.query(func.coalesce(func.sum(SmsLog.recipients_count * SmsLog.parts), 0)).filter(
            SmsLog.status == 'accepted', SmsLog.created_at >= today).scalar(),
        credits=S.query(func.coalesce(func.sum(Business.sms_credits), 0)).scalar(),
    )
    recent_biz = Business.query.order_by(Business.id.desc()).limit(8).all()
    owners = {u.business_id: u for u in User.query.filter(User.role == 'owner').all()}
    logs = AuditLog.query.order_by(AuditLog.id.desc()).limit(10).all()
    return render_template('master/home.html', stats=stats, recent_biz=recent_biz, owners=owners, logs=logs)


@bp.route('/businesses')
@master_required
def businesses():
    q = (request.args.get('q') or '').strip()
    flt = request.args.get('f', '')
    query = Business.query
    now = utcnow()
    if q:
        query = query.filter(Business.name.ilike(f'%{q}%') | Business.phone.ilike(f'%{q}%'))
    if flt == 'trial':
        query = query.filter(Business.plan == 'trial', Business.trial_ends >= now)
    elif flt == 'expired':
        query = query.filter(Business.plan == 'trial', Business.trial_ends < now)
    elif flt == 'paid':
        query = query.filter(Business.plan != 'trial')
    elif flt == 'suspended':
        query = query.filter(Business.status == 'suspended')
    blist = query.order_by(Business.id.desc()).limit(200).all()
    counts = dict(db.session.query(User.business_id, func.count(User.id)).group_by(User.business_id).all())
    owners = {u.business_id: u for u in User.query.filter(User.role == 'owner').all()}
    return render_template('master/businesses.html', blist=blist, counts=counts, owners=owners, q=q, flt=flt, now=now)


@bp.route('/businesses/<int:bid>')
@master_required
def business(bid):
    b = db.session.get(Business, bid) or abort(404)
    users = User.query.filter_by(business_id=bid).order_by(User.id).all()
    n_sales = Sale.query.filter_by(business_id=bid).filter(Sale.status != 'void').count()
    total = db.session.query(func.coalesce(func.sum(Sale.total), 0)).filter(
        Sale.business_id == bid, Sale.status != 'void').scalar()
    logs = AuditLog.query.filter_by(business_id=bid).order_by(AuditLog.id.desc()).limit(15).all()
    return render_template('master/business.html', b=b, users=users, n_sales=n_sales, total=total, logs=logs)


@bp.route('/businesses/<int:bid>/plan', methods=['POST'])
@master_required
def business_plan(bid):
    b = db.session.get(Business, bid) or abort(404)
    plan = request.form.get('plan')
    if plan not in config.PLANS:
        abort(400)
    b.plan = plan
    now = utcnow()
    if plan == 'trial':
        days = max(to_int(request.form.get('extend_days')), 0)
        if days:
            b.trial_ends = max(now, b.trial_ends or now) + timedelta(days=days)
    else:
        d = parse_date(request.form.get('paid_until'))
        b.paid_until = None if d is None else utcnow().replace(year=d.year, month=d.month, day=d.day,
                                                              hour=20, minute=59, second=0, microsecond=0)
    audit('master_plan', f'{b.name} -> {plan}')
    db.session.commit()
    flash('Mpango umebadilishwa.', 'success')
    return redirect(url_for('master.business', bid=bid))


@bp.route('/businesses/<int:bid>/status', methods=['POST'])
@master_required
def business_status(bid):
    b = db.session.get(Business, bid) or abort(404)
    b.status = 'suspended' if b.status == 'active' else 'active'
    audit('master_status', f'{b.name} -> {b.status}')
    db.session.commit()
    flash('Hali ya biashara imebadilishwa.', 'success')
    return redirect(url_for('master.business', bid=bid))


@bp.route('/businesses/<int:bid>/credits', methods=['POST'])
@master_required
def business_credits(bid):
    b = db.session.get(Business, bid) or abort(404)
    amount = to_int(request.form.get('amount'))
    reason = (request.form.get('reason') or '').strip()[:100]
    if amount == 0 or (b.sms_credits or 0) + amount < 0:
        flash('Kiasi si sahihi (salio haliwezi kuwa chini ya sifuri).', 'danger')
    else:
        b.sms_credits = (b.sms_credits or 0) + amount
        audit('master_credits', f'{b.name} {amount:+d} ({reason})')
        db.session.commit()
        flash(f'SMS credits zimebadilishwa. Salio jipya: {b.sms_credits}.', 'success')
    return redirect(url_for('master.business', bid=bid))


@bp.route('/users')
@master_required
def users():
    q = (request.args.get('q') or '').strip()
    query = User.query.filter(User.role != 'master')
    if q:
        query = query.filter(User.email.ilike(f'%{q}%') | User.name.ilike(f'%{q}%') | User.phone.ilike(f'%{q}%'))
    ulist = query.order_by(User.id.desc()).limit(200).all()
    return render_template('master/users.html', ulist=ulist, q=q, now=utcnow())


@bp.route('/users/<int:uid>/toggle', methods=['POST'])
@master_required
def user_toggle(uid):
    u = db.session.get(User, uid) or abort(404)
    if u.role == 'master':
        abort(400)
    u.active = not u.active
    audit('master_user_toggle', f'{u.email} -> {"hai" if u.active else "imezimwa"}')
    db.session.commit()
    flash('Imebadilishwa.', 'success')
    return redirect(url_for('master.users'))


@bp.route('/users/<int:uid>/unlock', methods=['POST'])
@master_required
def user_unlock(uid):
    u = db.session.get(User, uid) or abort(404)
    u.failed_logins, u.locked_until = 0, None
    audit('master_user_unlock', u.email)
    db.session.commit()
    flash('Akaunti imefunguliwa.', 'success')
    return redirect(url_for('master.users'))


@bp.route('/announcements', methods=['GET', 'POST'])
@master_required
def announcements():
    if request.method == 'POST':
        title = (request.form.get('title') or '').strip()[:150]
        if title:
            db.session.add(Announcement(title=title, body=(request.form.get('body') or '').strip()[:1000]))
            audit('master_announcement', title)
            db.session.commit()
            flash('Tangazo limechapishwa.', 'success')
        return redirect(url_for('master.announcements'))
    alist = Announcement.query.order_by(Announcement.id.desc()).limit(50).all()
    return render_template('master/announcements.html', alist=alist)


@bp.route('/announcements/<int:aid>/toggle', methods=['POST'])
@master_required
def announcement_toggle(aid):
    a = db.session.get(Announcement, aid) or abort(404)
    a.active = not a.active
    db.session.commit()
    return redirect(url_for('master.announcements'))


@bp.route('/announcements/<int:aid>/delete', methods=['POST'])
@master_required
def announcement_delete(aid):
    a = db.session.get(Announcement, aid) or abort(404)
    db.session.delete(a)
    db.session.commit()
    return redirect(url_for('master.announcements'))


@bp.route('/audit')
@master_required
def audit_view():
    bid = to_int(request.args.get('business_id'))
    query = AuditLog.query
    if bid:
        query = query.filter_by(business_id=bid)
    logs = query.order_by(AuditLog.id.desc()).limit(300).all()
    return render_template('master/audit.html', logs=logs, bid=bid or '')


@bp.route('/sms')
@master_required
def sms():
    logs = SmsLog.query.order_by(SmsLog.id.desc()).limit(100).all()
    balance, err = (None, None)
    if request.args.get('check') and sms_enabled():
        balance, err = beem_balance()
    return render_template('master/sms.html', logs=logs, balance=balance, err=err, enabled=sms_enabled(),
                           checked=bool(request.args.get('check')))
