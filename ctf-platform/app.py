import os
import secrets
import hashlib
import hmac
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import UniqueConstraint
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    solves = db.relationship('Solve', back_populates='user', cascade='all, delete-orphan')

class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(40), nullable=False)
    description = db.Column(db.Text, nullable=False)
    points = db.Column(db.Integer, nullable=False)
    flag_hash = db.Column(db.String(64), nullable=False)
    solves = db.relationship('Solve', back_populates='challenge', cascade='all, delete-orphan')

class Solve(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=False)
    solved_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    user = db.relationship('User', back_populates='solves')
    challenge = db.relationship('Challenge', back_populates='solves')
    __table_args__ = (UniqueConstraint('user_id', 'challenge_id', name='unique_solve'),)

def flag_digest(flag):
    return hashlib.sha256(flag.encode('utf-8')).hexdigest()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))
        if db.session.get(User, session['user_id']) is None:
            session.clear()
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if not db.session.get(User, session['user_id']).is_admin:
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

def seed_challenges():
    examples = [
        ('Welcome Flag', 'Basics', 'Submit the example flag: CTF{welcome_to_hackstreetboys}', 50, 'CTF{welcome_to_hackstreetboys}'),
        ('Base64 Basics', 'Encoding', 'Decode this Base64 text and submit the result as the flag: Q1RGe2Jhc2U2NF9pc19lbmNvZGluZ30=', 100, 'CTF{base64_is_encoding}'),
        ('Caesar Cipher', 'Cryptography', 'Decode this Caesar cipher (shift 3 backwards): FWI{fdhvdu_flskhu}. Submit the decoded text.', 150, 'CTF{caesar_cipher}'),
    ]
    if db.session.query(Challenge.id).first() is None:
        for title, category, description, points, flag in examples:
            db.session.add(Challenge(title=title, category=category, description=description, points=points, flag_hash=flag_digest(flag)))
        db.session.commit()

def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get('SECRET_KEY') or secrets.token_hex(32),
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///ctf.db'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    db.init_app(app)

    @app.before_request
    def csrf_protect():
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            supplied = request.form.get('csrf_token', '') or request.headers.get('X-CSRF-Token', '')
            expected = session.get('csrf_token', '')
            if not expected or not hmac.compare_digest(supplied, expected):
                abort(400, description='Invalid CSRF token')

    @app.context_processor
    def inject_csrf():
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_urlsafe(32)
        return {'csrf_token': session['csrf_token'], 'current_user': db.session.get(User, session['user_id']) if 'user_id' in session else None}

    @app.after_request
    def secure_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        return response

    @app.route('/')
    def home():
        return redirect(url_for('dashboard') if 'user_id' in session else url_for('login'))

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            if not (3 <= len(username) <= 40) or not all(c.isalnum() or c == '_' for c in username) or not username.isascii():
                flash('Username must be 3–40 ASCII letters, numbers, or underscores.', 'error')
            elif len(password) < 12:
                flash('Password must be at least 12 characters.', 'error')
            elif User.query.filter_by(username=username).first():
                flash('Username already exists.', 'error')
            else:
                db.session.add(User(username=username, password_hash=generate_password_hash(password)))
                db.session.commit()
                flash('Account created. Please log in.', 'success')
                return redirect(url_for('login'))
        return render_template('register.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            user = User.query.filter_by(username=request.form.get('username', '').strip()).first()
            if user and check_password_hash(user.password_hash, request.form.get('password', '')):
                session.clear()
                session['user_id'] = user.id
                session['csrf_token'] = secrets.token_urlsafe(32)
                return redirect(url_for('dashboard'))
            flash('Invalid username or password.', 'error')
        return render_template('login.html')

    @app.post('/logout')
    @login_required
    def logout():
        session.clear()
        return redirect(url_for('login'))

    @app.get('/dashboard')
    @login_required
    def dashboard():
        user = db.session.get(User, session['user_id'])
        solved_ids = {solve.challenge_id for solve in user.solves}
        challenges = Challenge.query.order_by(Challenge.points).all()
        points = sum(s.challenge.points for s in user.solves)
        return render_template('dashboard.html', user=user, challenges=challenges, solved_ids=solved_ids, points=points)

    @app.post('/challenge/<int:challenge_id>/submit')
    @login_required
    def submit_flag(challenge_id):
        challenge = db.get_or_404(Challenge, challenge_id)
        user_id = session['user_id']
        if Solve.query.filter_by(user_id=user_id, challenge_id=challenge.id).first():
            flash('You already solved this challenge.', 'info')
        elif hmac.compare_digest(flag_digest(request.form.get('flag', '').strip()), challenge.flag_hash):
            db.session.add(Solve(user_id=user_id, challenge_id=challenge.id))
            db.session.commit()
            flash(f'Correct! +{challenge.points} points.', 'success')
        else:
            flash('Incorrect flag. Try again!', 'error')
        return redirect(url_for('dashboard'))

    @app.get('/leaderboard')
    @login_required
    def leaderboard():
        users = User.query.all()
        scores = sorted(((u.username, sum(s.challenge.points for s in u.solves), len(u.solves)) for u in users), key=lambda row: (-row[1], row[0]))
        return render_template('leaderboard.html', scores=scores)

    @app.route('/admin/challenges', methods=['GET', 'POST'])
    @admin_required
    def admin_challenges():
        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            category = request.form.get('category', '').strip()
            description = request.form.get('description', '').strip()
            flag = request.form.get('flag', '').strip()
            try:
                points = int(request.form.get('points', '0'))
            except ValueError:
                points = 0
            if not (1 <= len(title) <= 100 and 1 <= len(category) <= 40 and 1 <= len(description) <= 3000 and 1 <= points <= 10000 and flag.startswith('CTF{') and flag.endswith('}') and len(flag) <= 200):
                flash('Check title, category, description, points (1–10000), and CTF{...} flag.', 'error')
            else:
                db.session.add(Challenge(title=title, category=category, description=description, points=points, flag_hash=flag_digest(flag)))
                db.session.commit()
                flash('Challenge created!', 'success')
                return redirect(url_for('admin_challenges'))
        return render_template('admin.html', challenges=Challenge.query.all())

    with app.app_context():
        db.create_all()
        seed_challenges()
    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=False)
