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
from sqlalchemy import text
import os
import uuid
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'church_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///church_quiz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

HOST_ROLES = ('super_admin', 'co_host', 'moderator')
ROLE_LABELS = {
    'super_admin': 'مضيف',
    'co_host': 'مضيف مساعد',
    'moderator': 'مشرف',
    'participant': 'مشارك',
}


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    score = db.Column(db.Integer, default=0)
    role = db.Column(db.String(20), default='participant')
    is_active = db.Column(db.Boolean, default=True)


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
    columns = db.session.execute(text(f'PRAGMA table_info({table})')).fetchall()
    column_names = [column[1] for column in columns]
    if name not in column_names:
        db.session.execute(text(f'ALTER TABLE {table} ADD COLUMN {ddl}'))


with app.app_context():
    db.create_all()
    ensure_column('user', 'role', "role VARCHAR(20) DEFAULT 'participant'")
    ensure_column('user', 'is_active', 'is_active BOOLEAN DEFAULT 1')
    ensure_column('question', 'points', 'points INTEGER DEFAULT 10')
    ensure_column('question', 'is_open', 'is_open BOOLEAN DEFAULT 0')
    ensure_column('audio_answer', 'answer_text', 'answer_text VARCHAR(500)')
    ensure_column('audio_answer', 'awarded_points', 'awarded_points INTEGER DEFAULT 0')
    ensure_column('audio_answer', 'created_at', 'created_at DATETIME')
    db.session.commit()


def current_user():
    if 'username' not in session:
        return None
    return User.query.filter_by(username=session['username']).first()


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
        if user.role not in HOST_ROLES:
            flash('هذه الصفحة مخصصة للمضيف والمشرفين فقط.')
            return redirect(url_for('dashboard'))
        return view(user, *args, **kwargs)
    return wrapped


def can_manage_questions(user):
    return user.role in ('super_admin', 'co_host')


def can_appoint(user):
    return user.role == 'super_admin'


@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ""
    if request.method == 'POST':
        uname = request.form.get('username')
        pword = request.form.get('password')

        existing_user = User.query.filter_by(username=uname).first()
        if existing_user:
            message = "اسم المستخدم موجود مسبقاً!"
        else:
            role = 'super_admin' if User.query.count() == 0 else 'participant'
            new_user = User(username=uname, password=pword, role=role)
            db.session.add(new_user)
            db.session.commit()
            session['username'] = new_user.username
            return redirect(url_for('dashboard'))

    return render_template('register.html', message=message)


@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ""
    if request.method == 'POST':
        uname = request.form.get('username')
        pword = request.form.get('password')

        user = User.query.filter_by(username=uname, password=pword).first()
        if user:
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        else:
            message = "بيانات الدخول غير صحيحة!"

    return render_template('login.html', message=message)


@app.route('/dashboard')
@login_required
def dashboard(user):
    open_sessions = AttendanceSession.query.filter_by(is_open=True).order_by(AttendanceSession.id.desc()).all()
    attended_ids = {r.session_id for r in Attendance.query.filter_by(user_id=user.id).all()}
    return render_template(
        'dashboard.html',
        username=user.username,
        score=user.score or 0,
        is_staff=user.role in HOST_ROLES,
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
        is_staff=user.role in HOST_ROLES,
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

    answer_text = (request.form.get('answer_text') or '').strip()
    audio = request.files.get('audio')
    audio_filename = None
    if audio and audio.filename:
        ext = os.path.splitext(audio.filename)[1].lower() or '.webm'
        audio_filename = f'{uuid.uuid4().hex}{ext}'
        audio.save(os.path.join(app.config['UPLOAD_FOLDER'], audio_filename))

    if not answer_text and not audio_filename:
        flash('أدخل إجابة نصية أو سجّل صوتاً قبل الإرسال.')
        return redirect(url_for('quiz'))

    if user.role == 'participant' and not QuestionAccess.query.filter_by(
        user_id=user.id,
        question_id=question.id,
    ).first():
        db.session.add(QuestionAccess(user_id=user.id, question_id=question.id))

    db.session.add(AudioAnswer(
        user_id=user.id,
        question_id=question.id,
        answer_text=answer_text or None,
        audio_file=audio_filename or '',
    ))
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
        flash('تعيين المضيفين والمشرفين متاح للمضيف الرئيسي فقط.')
        return redirect(url_for('admin'))

    target = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    if new_role not in ROLE_LABELS:
        flash('دور غير صالح.')
        return redirect(url_for('admin'))

    if target.id == user.id and new_role != 'super_admin':
        other_hosts = User.query.filter(
            User.role == 'super_admin',
            User.id != user.id,
        ).count()
        if other_hosts == 0:
            flash('لا يمكن إزالة المضيف الوحيد.')
            return redirect(url_for('admin'))

    target.role = new_role
    db.session.commit()
    flash(f'تم تعيين {target.username} كـ{ROLE_LABELS[new_role]}.')
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
