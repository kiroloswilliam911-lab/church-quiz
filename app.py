from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text
import os
import hmac
import hashlib
import re
import secrets
import smtplib
import uuid
from datetime import date, datetime, timedelta
from email.message import EmailMessage
from functools import wraps
from zoneinfo import ZoneInfo
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
database_url = os.environ.get('DATABASE_URL', 'sqlite:///church_quiz.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql+psycopg://', 1)
elif database_url.startswith('postgresql://'):
    database_url = database_url.replace('postgresql://', 'postgresql+psycopg://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.environ.get(
    'UPLOAD_FOLDER',
    os.path.join(app.root_path, 'uploads'),
)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', '').lower() == 'true'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

ROLE_LABELS = {
    'super_admin': 'مضيف',
    'co_host': 'مضيف مساعد',
    'moderator': 'مشرف',
    'participant': 'مشارك',
}


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(254), nullable=True)
    password = db.Column(db.String(255), nullable=False)
    score = db.Column(db.Integer, default=0)
    role = db.Column(db.String(20), default='participant')
    is_active = db.Column(db.Boolean, default=True)
    streak_days = db.Column(db.Integer, default=0, nullable=False)
    last_answer_day = db.Column(db.Date, nullable=True)


class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_text = db.Column(db.String(200), nullable=False)
    correct_answer = db.Column(db.String(100), nullable=False)
    points = db.Column(db.Integer, default=10)
    is_open = db.Column(db.Boolean, default=False)


class QuestionAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    accessed_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('user_id', 'question_id'),)

    user = db.relationship('User', backref='question_accesses')
    question = db.relationship('Question', backref='accesses')


class AudioAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    audio_file = db.Column(db.String(255), nullable=True)
    answer_text = db.Column(db.String(500), nullable=True)
    awarded_points = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='answers')
    question = db.relationship('Question', backref='answers')


class AttendanceSession(db.Model):
    """A meeting/class the host opens so participants can check in."""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    is_open = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('attendance_session.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    checked_in_at = db.Column(db.DateTime, default=datetime.utcnow)
    marked_by_host = db.Column(db.Boolean, default=False)

    __table_args__ = (db.UniqueConstraint('session_id', 'user_id'),)

    session = db.relationship('AttendanceSession', backref='records')
    user = db.relationship('User', backref='attendance_records')


def ensure_column(table, name, ddl):
    column_names = {column['name'] for column in inspect(db.engine).get_columns(table)}
    if name not in column_names:
        db.session.execute(text(f'ALTER TABLE {table} ADD COLUMN {ddl}'))


with app.app_context():
    db.create_all()
    ensure_column('user', 'role', "role VARCHAR(20) DEFAULT 'participant'")
    ensure_column('user', 'email', 'email VARCHAR(254)')
    ensure_column('user', 'is_active', 'is_active BOOLEAN DEFAULT TRUE')
    ensure_column('user', 'streak_days', 'streak_days INTEGER NOT NULL DEFAULT 0')
    ensure_column('user', 'last_answer_day', 'last_answer_day DATE')
    ensure_column('question', 'points', 'points INTEGER DEFAULT 10')
    ensure_column('question', 'is_open', 'is_open BOOLEAN DEFAULT FALSE')
    ensure_column('audio_answer', 'answer_text', 'answer_text VARCHAR(500)')
    ensure_column('audio_answer', 'awarded_points', 'awarded_points INTEGER DEFAULT 0')
    ensure_column('audio_answer', 'created_at', 'created_at TIMESTAMP')
    db.session.execute(text(
        'CREATE UNIQUE INDEX IF NOT EXISTS uq_user_email ON user (email)'
    ))
    db.session.commit()


def current_user():
    if 'username' not in session:
        return None
    user = User.query.filter_by(username=session['username']).first()
    if user and not user.is_active:
        session.clear()
        return None
    return user


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for('login'))
        return view(user, *args, **kwargs)
    return wrapped


def staff_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for('login'))
        if not is_primary_host(user) and user.role not in ('co_host', 'moderator'):
            flash('هذه الصفحة مخصصة للمضيفين فقط.')
            return redirect(url_for('dashboard'))
        return view(user, *args, **kwargs)
    return wrapped


def can_manage_questions(user):
    return is_primary_host(user) or user.role in ('co_host', 'moderator')


def can_appoint(user):
    return is_primary_host(user)


def is_primary_host(user):
    return bool(
        user
        and user.is_active
        and user.username.casefold() == 'churchhost'
        and user.role == 'super_admin')


def normalize_email(email):
    return (email or '').strip().lower()


def is_valid_email(email):
    return (
        len(email) <= 254
        and re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email) is not None
    )


def send_password_reset_email(recipient, reset_url):
    mail_username = os.environ.get('MAIL_USERNAME')
    mail_password = (os.environ.get('MAIL_PASSWORD') or '').replace(' ', '')
    if not mail_username or not mail_password:
        raise RuntimeError('MAIL_USERNAME and MAIL_PASSWORD must be configured.')

    message = EmailMessage()
    message['Subject'] = 'إعادة تعيين كلمة مرور مسابقات الكنيسة'
    message['From'] = mail_username
    message['To'] = recipient
    message.set_content(
        'وصلنا طلب لتغيير كلمة مرور حسابك في مسابقات الكنيسة.\n\n'
        f'افتح الرابط التالي لتعيين كلمة مرور جديدة خلال 15 دقيقة:\n{reset_url}\n\n'
        'إذا لم تطلب تغيير كلمة المرور، تجاهل هذه الرسالة.'
    )

    with smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=15) as smtp:
        smtp.login(mail_username, mail_password)
        smtp.send_message(message)


def password_reset_link(token):
    public_base_url = (os.environ.get('PUBLIC_BASE_URL') or '').strip().rstrip('/')
    if not public_base_url.startswith('https://'):
        raise RuntimeError('PUBLIC_BASE_URL must be configured with the HTTPS site URL.')
    return f'{public_base_url}{url_for("reset_password", token=token)}'


def cairo_today():
    return datetime.now(ZoneInfo('Africa/Cairo')).date()


def current_streak(user, today=None):
    today = today or cairo_today()
    if not user.last_answer_day:
        return 0
    days_since_answer = (today - user.last_answer_day).days
    if days_since_answer < 0 or days_since_answer > 1:
        return 0
    return user.streak_days or 0


def record_answer_streak(user, today=None):
    today = today or cairo_today()
    if user.last_answer_day == today:
        return
    if user.last_answer_day == today - timedelta(days=1):
        user.streak_days = (user.streak_days or 0) + 1
    else:
        user.streak_days = 1
    user.last_answer_day = today


@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/host')
def host_portal():
    user = current_user()
    if not user:
        return redirect(url_for('login', next='host'))
    if not is_primary_host(user):
        flash('رابط المضيف مخصص لحساب المضيف الرئيسي.')
        return redirect(url_for('dashboard'))
    return redirect(url_for('admin'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ""
    if request.args.get('restart') == '1':
        session.pop('pending_registration_email', None)
        session.pop('pending_registration_password_hash', None)

    pending_email = session.get('pending_registration_email')
    pending_password_hash = session.get('pending_registration_password_hash')
    if not pending_email or not pending_password_hash:
        pending_email = None
        pending_password_hash = None
        session.pop('pending_registration_email', None)
        session.pop('pending_registration_password_hash', None)

    bootstrap_code = os.environ.get('INITIAL_ADMIN_CODE')
    bootstrap_available = bool(
        bootstrap_code and User.query.filter_by(role='super_admin').count() == 0
    )
    if request.method == 'POST':
        if request.form.get('step') == 'name' and pending_email:
            uname = (request.form.get('username') or '').strip()
            submitted_bootstrap_code = request.form.get('admin_code') or ''
            existing_user = User.query.filter_by(username=uname).first()
            existing_email = User.query.filter(
                db.func.lower(User.email) == pending_email
            ).first()
            if not uname:
                message = "اكتب الاسم الذي تريد استخدامه في الموقع."
            elif existing_user:
                message = "اسم المستخدم موجود مسبقاً!"
            elif existing_email:
                message = "البريد الإلكتروني مستخدم في حساب آخر. ابدأ التسجيل ببريد آخر."
                session.pop('pending_registration_email', None)
                session.pop('pending_registration_password_hash', None)
                pending_email = None
                pending_password_hash = None
            elif (
                bootstrap_available
                and submitted_bootstrap_code
                and not hmac.compare_digest(submitted_bootstrap_code, bootstrap_code)
            ):
                message = "رمز إنشاء المضيف غير صحيح."
            else:
                is_first_user = User.query.count() == 0
                has_admin_code = (
                    bootstrap_available
                    and submitted_bootstrap_code
                    and hmac.compare_digest(submitted_bootstrap_code, bootstrap_code)
                )
                role = 'super_admin' if uname.strip().casefold() == 'churchhost' else 'participant'
                new_user = User(
                    username=uname,
                    email=pending_email,
                    password=pending_password_hash,
                    role=role,
                )
                db.session.add(new_user)
                db.session.commit()
                session.pop('pending_registration_email', None)
                session.pop('pending_registration_password_hash', None)
                session['username'] = new_user.username
                return redirect(url_for('dashboard'))
        else:
            session.pop('pending_registration_email', None)
            session.pop('pending_registration_password_hash', None)
            pending_email = None
            pending_password_hash = None
            email = normalize_email(request.form.get('email'))
            password = request.form.get('password') or ''
            existing_email = User.query.filter(
                db.func.lower(User.email) == email
            ).first()
            if not is_valid_email(email):
                message = "أدخل بريدًا إلكترونيًا صحيحًا."
            elif existing_email:
                message = "البريد الإلكتروني مستخدم في حساب آخر."
            elif not password:
                message = "أدخل كلمة المرور."
            else:
                session['pending_registration_email'] = email
                session['pending_registration_password_hash'] = generate_password_hash(
                    password
                )
                return redirect(url_for('register'))

    return render_template(
        'register.html',
        message=message,
        bootstrap_available=bootstrap_available,
        step='name' if pending_email else 'credentials',
        email=pending_email,
    )


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    message = ''
    if request.method == 'POST':
        email = normalize_email(request.form.get('email'))
        user = None
        if is_valid_email(email):
            user = User.query.filter(
                db.func.lower(User.email) == email,
                User.is_active.is_(True),
            ).first()

            primary_host_email = normalize_email(
                os.environ.get('PRIMARY_HOST_EMAIL')
            )
            if not user and email == primary_host_email and primary_host_email:
                primary_host = (
                    User.query
                    .filter_by(role='super_admin', is_active=True)
                    .order_by(User.id)
                    .first()
                )
                if primary_host and not primary_host.email:
                    primary_host.email = primary_host_email
                    db.session.commit()
                    user = primary_host

        if user:
            now = datetime.utcnow()
            recent_reset = PasswordResetToken.query.filter(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.created_at >= now - timedelta(minutes=1),
            ).first()
            if not recent_reset:
                PasswordResetToken.query.filter_by(
                    user_id=user.id,
                    used_at=None,
                ).update({'used_at': now}, synchronize_session=False)

                token = secrets.token_urlsafe(32)
                reset = PasswordResetToken(
                    user_id=user.id,
                    token_hash=hashlib.sha256(token.encode('utf-8')).hexdigest(),
                    created_at=now,
                    expires_at=now + timedelta(minutes=15),
                )
                db.session.add(reset)
                db.session.commit()

                try:
                    send_password_reset_email(email, password_reset_link(token))
                except (OSError, RuntimeError, smtplib.SMTPException):
                    app.logger.exception(
                        'Could not send password reset email for user id %s',
                        user.id,
                    )
                    reset.used_at = datetime.utcnow()
                    db.session.commit()

        message = (
            'لو البريد الإلكتروني مرتبطًا بحساب نشط، هتوصلك رسالة فيها رابط '
            'لتغيير كلمة المرور. راجع مجلد الرسائل غير المرغوب فيها أيضًا.'
        )

    return render_template('forgot_password.html', message=message)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
    reset = PasswordResetToken.query.filter_by(token_hash=token_hash).first()
    now = datetime.utcnow()
    user = db.session.get(User, reset.user_id) if reset else None
    if (
        not reset
        or reset.used_at
        or reset.expires_at <= now
        or not user
        or not user.is_active
    ):
        return render_template('reset_password.html', invalid=True), 400

    message = ''
    if request.method == 'POST':
        password = request.form.get('password') or ''
        confirm_password = request.form.get('confirm_password') or ''
        if len(password) < 8:
            message = 'كلمة المرور يجب ألا تقل عن 8 أحرف.'
        elif password != confirm_password:
            message = 'كلمتا المرور غير متطابقتين.'
        else:
            user.password = generate_password_hash(password)
            PasswordResetToken.query.filter_by(
                user_id=user.id,
                used_at=None,
            ).update({'used_at': now}, synchronize_session=False)
            db.session.commit()
            return render_template('reset_password.html', success=True)

    return render_template('reset_password.html', message=message)


@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ""
    if request.method == 'POST':
        login_identifier = (request.form.get('username') or '').strip()
        pword = request.form.get('password') or ''

        user = User.query.filter(
            db.func.lower(User.email) == normalize_email(login_identifier)
        ).first()
        if not user:
            user = User.query.filter_by(username=login_identifier).first()
        if user and (
            check_password_hash(user.password, pword)
            if user.password.startswith(('scrypt:', 'pbkdf2:'))
            else user.password == pword
        ):
            if not user.is_active:
                message = "هذا الحساب موقوف. تواصل مع المضيف."
            else:
                if not user.password.startswith(('scrypt:', 'pbkdf2:')):
                    user.password = generate_password_hash(pword)
                    db.session.commit()
                session.pop('pending_registration_email', None)
                session.pop('pending_registration_password_hash', None)
                session['username'] = user.username
                if request.form.get('next') == 'host' and is_primary_host(user):
                    return redirect(url_for('host_portal'))
                return redirect(url_for('dashboard'))
        else:
            message = "بيانات الدخول غير صحيحة!"

    return render_template(
        'login.html',
        message=message,
        next_page='host' if request.args.get('next') == 'host' else '',
    )


@app.route('/dashboard')
@login_required
def dashboard(user):
    open_sessions = AttendanceSession.query.filter_by(is_open=True).order_by(AttendanceSession.id.desc()).all()
    attended_ids = {r.session_id for r in Attendance.query.filter_by(user_id=user.id).all()}
    return render_template(
        'dashboard.html',
        username=user.username,
        score=user.score or 0,
        streak_days=current_streak(user),
        is_staff=is_primary_host(user),
        role_label=ROLE_LABELS.get(user.role, user.role),
        open_sessions=open_sessions,
        attended_ids=attended_ids,
    )


@app.route('/checkin/<int:session_id>', methods=['POST'])
@login_required
def check_in(user, session_id):
    att_session = AttendanceSession.query.get_or_404(session_id)
    if not att_session.is_open:
        flash('تسجيل الحضور مغلق لهذه الجلسة.')
    elif Attendance.query.filter_by(session_id=session_id, user_id=user.id).first():
        flash('تم تسجيل حضورك مسبقاً.')
    else:
        db.session.add(Attendance(session_id=session_id, user_id=user.id))
        db.session.commit()
        flash('تم تسجيل حضورك. أهلاً بك!')
    return redirect(url_for('dashboard'))


@app.route('/quiz')
@login_required
def quiz(user):
    questions = Question.query.filter_by(is_open=True).order_by(Question.id).all()
    if user.role == 'participant' and questions:
        question_ids = [question.id for question in questions]
        existing_ids = {
            access.question_id
            for access in QuestionAccess.query.filter(
                QuestionAccess.user_id == user.id,
                QuestionAccess.question_id.in_(question_ids),
            ).all()
        }
        db.session.add_all(
            QuestionAccess(user_id=user.id, question_id=question_id)
            for question_id in question_ids
            if question_id not in existing_ids
        )
        if len(existing_ids) != len(question_ids):
            db.session.commit()
    answered_ids = {
        answer.question_id
        for answer in AudioAnswer.query.filter_by(user_id=user.id).all()
    }
    return render_template(
        'quiz.html',
        username=user.username,
        questions=questions,
        answered_ids=answered_ids,
        is_staff=is_primary_host(user),
        streak_days=current_streak(user),
    )


@app.route('/quiz/answer', methods=['POST'])
@login_required
def submit_answer(user):
    question_id = request.form.get('question_id', type=int)
    question = Question.query.get(question_id)
    if not question or not question.is_open:
        flash('هذا السؤال غير متاح حالياً.')
        return redirect(url_for('quiz'))

    existing = AudioAnswer.query.filter_by(user_id=user.id, question_id=question.id).first()
    if existing:
        flash('لقد أجبت على هذا السؤال مسبقاً.')
        return redirect(url_for('quiz'))

    audio = request.files.get('audio')
    if not audio or not audio.filename:
        flash('سجّل إجابتك الصوتية قبل الإرسال.')
        return redirect(url_for('quiz'))
    if not audio.mimetype.startswith('audio/'):
        flash('ارفع أو سجّل ملفاً صوتياً صحيحاً.')
        return redirect(url_for('quiz'))

    allowed_extensions = {
        '.aac', '.amr', '.flac', '.m4a', '.mp3', '.mp4', '.oga',
        '.ogg', '.wav', '.webm', '.3gp',
    }
    ext = os.path.splitext(audio.filename)[1].lower()
    if ext not in allowed_extensions:
        ext = '.webm'
    audio_filename = f'{uuid.uuid4().hex}{ext}'
    audio.save(os.path.join(app.config['UPLOAD_FOLDER'], audio_filename))

    if user.role == 'participant' and not QuestionAccess.query.filter_by(
        user_id=user.id,
        question_id=question.id,
    ).first():
        db.session.add(QuestionAccess(user_id=user.id, question_id=question.id))

    db.session.add(AudioAnswer(
        user_id=user.id,
        question_id=question.id,
        audio_file=audio_filename,
    ))
    record_answer_streak(user)
    db.session.commit()
    flash('تم إرسال إجابتك.')
    return redirect(url_for('quiz'))


@app.route('/uploads/<path:filename>')
@staff_required
def uploaded_file(user, filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/admin')
@staff_required
def admin(user):
    questions = Question.query.order_by(Question.id.desc()).all()
    answers = (
        AudioAnswer.query
        .order_by(AudioAnswer.id.desc())
        .all()
    )
    users = User.query.order_by(User.username).all()
    streaks = {participant.id: current_streak(participant) for participant in users}
    att_sessions = AttendanceSession.query.order_by(AttendanceSession.id.desc()).all()
    participant_total = User.query.filter_by(role='participant').count()
    return render_template(
        'admin.html',
        att_sessions=att_sessions,
        participant_total=participant_total,
        current=user,
        questions=questions,
        answers=answers,
        users=users,
        streaks=streaks,
        role_labels=ROLE_LABELS,
        can_manage_questions=can_manage_questions(user),
        can_appoint=can_appoint(user),
    )


@app.route('/admin/questions', methods=['POST'])
@staff_required
def add_question(user):
    if not can_manage_questions(user):
        flash('لا يمكنك إضافة أسئلة.')
        return redirect(url_for('admin'))

    question_text = (request.form.get('question_text') or '').strip()
    correct_answer = (request.form.get('correct_answer') or '').strip()
    points = request.form.get('points', type=int)
    is_open = request.form.get('is_open') == 'on'

    if not question_text or not correct_answer:
        flash('أدخل نص السؤال والإجابة الصحيحة.')
        return redirect(url_for('admin'))
    if points is not None and points < 0:
        flash('يجب أن تكون الدرجة صفراً أو أكثر.')
        return redirect(url_for('admin'))

    db.session.add(Question(
        question_text=question_text,
        correct_answer=correct_answer,
        points=10 if points is None else points,
        is_open=is_open,
    ))
    db.session.commit()
    flash('تمت إضافة السؤال.')
    return redirect(url_for('admin'))


@app.route('/admin/questions/<int:question_id>/toggle', methods=['POST'])
@staff_required
def toggle_question(user, question_id):
    if not can_manage_questions(user):
        flash('لا يمكنك فتح الأسئلة أو إغلاقها.')
        return redirect(url_for('admin'))

    question = Question.query.get_or_404(question_id)
    question.is_open = not bool(question.is_open)
    db.session.commit()
    flash('تم فتح السؤال للمشاركين.' if question.is_open else 'تم إغلاق السؤال.')
    return redirect(url_for('admin'))


@app.route('/admin/questions/<int:question_id>/delete', methods=['POST'])
@staff_required
def delete_question(user, question_id):
    if not can_manage_questions(user):
        flash('لا يمكنك حذف الأسئلة.')
        return redirect(url_for('admin'))

    question = Question.query.get_or_404(question_id)
    answers = AudioAnswer.query.filter_by(question_id=question.id).all()
    uploaded_files = [answer.audio_file for answer in answers if answer.audio_file]
    users = {
        participant.id: participant
        for participant in User.query.filter(
            User.id.in_([answer.user_id for answer in answers])
        ).all()
    } if answers else {}

    for answer in answers:
        participant = users.get(answer.user_id)
        if participant:
            participant.score = (participant.score or 0) - (answer.awarded_points or 0)
        db.session.delete(answer)

    QuestionAccess.query.filter_by(question_id=question.id).delete()
    db.session.delete(question)
    db.session.commit()

    failed_files = []
    for filename in uploaded_files:
        if os.path.basename(filename) != filename:
            app.logger.error('Skipped invalid uploaded filename while deleting question: %r', filename)
            failed_files.append(filename)
            continue
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            if os.path.isfile(path):
                os.remove(path)
        except OSError:
            app.logger.exception('Could not remove uploaded answer file %s', filename)
            failed_files.append(filename)

    flash('تم حذف السؤال وإجاباته.')
    if failed_files:
        flash('تعذر حذف بعض الملفات الصوتية المرتبطة بالسؤال؛ راجع سجل التطبيق.')
    return redirect(url_for('admin'))


@app.route('/admin/answers/<int:answer_id>/score', methods=['POST'])
@staff_required
def assign_score(user, answer_id):
    answer = AudioAnswer.query.get_or_404(answer_id)
    new_points = request.form.get('awarded_points', type=int)
    if new_points is None or new_points < 0:
        flash('أدخل درجة صحيحة.')
        return redirect(url_for('admin'))

    participant = User.query.get(answer.user_id)
    old_points = answer.awarded_points or 0
    if participant:
        participant.score = (participant.score or 0) - old_points + new_points
    answer.awarded_points = new_points
    db.session.commit()
    flash(f'تم تحديث درجة {participant.username if participant else "المشارك"}.')
    return redirect(url_for('admin'))


@app.route('/admin/users/<int:user_id>/role', methods=['POST'])
@staff_required
def set_user_role(user, user_id):
    if not can_appoint(user):
        flash('تغيير أدوار الحسابات متاح للمضيف الرئيسي فقط.')
        return redirect(url_for('admin'))

    target = User.query.get_or_404(user_id)
    if target.id == user.id or target.username.casefold() == 'churchhost':
        flash('لا يمكن تغيير دور حساب المضيف الرئيسي.')
        return redirect(url_for('admin'))

    new_role = request.form.get('role')
    if new_role not in ('participant', 'co_host', 'moderator'):
        flash('الدور المحدد غير صالح.')
        return redirect(url_for('admin'))

    target.role = new_role
    db.session.commit()
    flash(f'تم تغيير دور {target.username} إلى {ROLE_LABELS[new_role]}.')
    return redirect(url_for('admin'))


@app.route('/admin/users/<int:user_id>/email', methods=['POST'])
@staff_required
def set_user_email(user, user_id):
    if not can_appoint(user):
        flash('تعديل بريد استعادة الحسابات متاح للمضيف الرئيسي فقط.')
        return redirect(url_for('admin'))

    target = User.query.get_or_404(user_id)
    email = normalize_email(request.form.get('email'))
    if not is_valid_email(email):
        flash('أدخل بريدًا إلكترونيًا صحيحًا.')
        return redirect(url_for('admin'))

    existing_email = User.query.filter(
        db.func.lower(User.email) == email,
        User.id != target.id,
    ).first()
    if existing_email:
        flash('البريد الإلكتروني مستخدم في حساب آخر.')
        return redirect(url_for('admin'))

    target.email = email
    db.session.commit()
    flash(f'تم حفظ بريد استعادة كلمة المرور لحساب {target.username}.')
    return redirect(url_for('admin'))


@app.route('/admin/users/<int:user_id>/toggle', methods=['POST'])
@staff_required
def toggle_user_active(user, user_id):
    target = User.query.get_or_404(user_id)
    if target.id == user.id or target.username.casefold() == 'churchhost':
        flash('لا يمكن إيقاف حساب المضيف الرئيسي.')
        return redirect(url_for('admin'))
    if target.role in ('co_host', 'moderator') and not can_appoint(user):
        flash('إدارة حسابات المضيفين والمشرفين متاحة للمضيف الرئيسي فقط.')
        return redirect(url_for('admin'))

    target.is_active = not bool(target.is_active)
    db.session.commit()
    flash(
        f'تم {"تفعيل" if target.is_active else "إيقاف"} حساب {target.username}.'
    )
    return redirect(url_for('admin'))


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@staff_required
def delete_user(user, user_id):
    if not can_appoint(user):
        flash('حذف الحسابات متاح للمضيف الرئيسي فقط.')
        return redirect(url_for('admin'))

    target = User.query.get_or_404(user_id)
    if target.id == user.id or target.username.casefold() == 'churchhost':
        flash('لا يمكن حذف حساب المضيف الرئيسي.')
        return redirect(url_for('admin'))

    username = target.username
    answers = AudioAnswer.query.filter_by(user_id=target.id).all()
    uploaded_files = [answer.audio_file for answer in answers if answer.audio_file]
    for answer in answers:
        db.session.delete(answer)
    QuestionAccess.query.filter_by(user_id=target.id).delete()
    Attendance.query.filter_by(user_id=target.id).delete()
    PasswordResetToken.query.filter_by(user_id=target.id).delete()
    db.session.delete(target)
    db.session.commit()

    failed_files = []
    for filename in uploaded_files:
        if os.path.basename(filename) != filename:
            app.logger.error('Skipped invalid uploaded filename while deleting user: %r', filename)
            failed_files.append(filename)
            continue
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            if os.path.isfile(path):
                os.remove(path)
        except OSError:
            app.logger.exception('Could not remove uploaded answer file %s', filename)
            failed_files.append(filename)

    flash(f'تم حذف حساب {username} وسجلاته.')
    if failed_files:
        flash('تعذر حذف بعض الملفات الصوتية المرتبطة بالحساب؛ راجع سجل التطبيق.')
    return redirect(url_for('admin'))


@app.route('/admin/sessions', methods=['POST'])
@staff_required
def add_session(user):
    title = (request.form.get('title') or '').strip()
    if not title:
        title = datetime.now().strftime('جلسة %Y-%m-%d')
    db.session.add(AttendanceSession(title=title, is_open=True))
    db.session.commit()
    flash('تم فتح تسجيل الحضور.')
    return redirect(url_for('admin'))


@app.route('/admin/sessions/<int:session_id>/toggle', methods=['POST'])
@staff_required
def toggle_session(user, session_id):
    att_session = AttendanceSession.query.get_or_404(session_id)
    att_session.is_open = not bool(att_session.is_open)
    db.session.commit()
    flash('تم فتح تسجيل الحضور.' if att_session.is_open else 'تم إغلاق تسجيل الحضور.')
    return redirect(request.referrer or url_for('admin'))


@app.route('/admin/sessions/<int:session_id>')
@staff_required
def session_attendance(user, session_id):
    att_session = AttendanceSession.query.get_or_404(session_id)
    participants = User.query.filter_by(role='participant').order_by(User.username).all()
    records = {r.user_id: r for r in att_session.records}
    present = [(u, records[u.id]) for u in participants if u.id in records]
    absent = [u for u in participants if u.id not in records]
    return render_template(
        'attendance.html',
        att_session=att_session,
        present=present,
        absent=absent,
        total=len(participants),
    )


@app.route('/admin/sessions/<int:session_id>/mark/<int:user_id>', methods=['POST'])
@staff_required
def mark_attendance(user, session_id, user_id):
    AttendanceSession.query.get_or_404(session_id)
    User.query.get_or_404(user_id)
    record = Attendance.query.filter_by(session_id=session_id, user_id=user_id).first()
    if record:
        db.session.delete(record)
    else:
        db.session.add(Attendance(session_id=session_id, user_id=user_id, marked_by_host=True))
    db.session.commit()
    return redirect(url_for('session_attendance', session_id=session_id))


@app.route('/admin/questions/<int:question_id>')
@staff_required
def question_responses(user, question_id):
    question = Question.query.get_or_404(question_id)
    answers = AudioAnswer.query.filter_by(question_id=question.id).order_by(AudioAnswer.id).all()
    answered_ids = {a.user_id for a in answers}
    participants = User.query.filter_by(role='participant').order_by(User.username).all()
    accessed_ids = {
        access.user_id
        for access in QuestionAccess.query.filter_by(question_id=question.id).all()
    } | answered_ids
    return render_template(
        'question_responses.html',
        question=question,
        answers=answers,
        not_answered=[u for u in participants if u.id not in answered_ids],
        accessed=[u for u in participants if u.id in accessed_ids],
        not_accessed=[u for u in participants if u.id not in accessed_ids],
    )


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
