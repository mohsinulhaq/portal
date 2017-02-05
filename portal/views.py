import os
from . import app, db, login_manager, serializer, mail
from .models import User
from flask import render_template, request, jsonify, url_for, flash, redirect, \
    send_file
from flask_mail import Message
from flask_login import login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

login_manager.login_view = 'index'
login_manager.login_message_category = 'danger'


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(uid=user_id).first()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email').strip()
    user = User(email, request.form.get('password').strip(), False)
    db.session.add(user)
    db.session.commit()
    token = serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('_activate.html', confirm_url=confirm_url)
    msg = Message(subject='Portal: Confirm your email',
                  recipients=[email], html=html)
    mail.send(msg)
    flash('You have been registered! Please check your email.', 'success')
    return redirect(url_for('index'))


@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token,
                                 salt=app.config['SECURITY_PASSWORD_SALT'])
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('index'))
    user = User.query.filter_by(email=email).first_or_404()
    if user.verified:
        flash('Account already confirmed. Please login.', 'info')
    else:
        user.verified = True
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('index'))


@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email').strip()
    password = request.form.get('password').strip()
    user = User.query.filter_by(email=email).first()
    if user is None or not check_password_hash(user.password, password):
        flash('Username or Password is invalid.', 'danger')
        return redirect(url_for('index'))

    if not user.verified:
        flash('Please confirm your email first.', 'info')
        return redirect(url_for('index'))

    remember = True if 'remember' in request.form else False
    login_user(user, remember=remember)
    return redirect(url_for('index'))


@app.route('/forgot_password/', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form.get('email').strip()
        user = User.query.filter_by(email=email).first()
        if user:
            subject = 'Portal: Password Reset'
            token = serializer.dumps(email,
                                     app.config['SECURITY_PASSWORD_SALT'])
            reset_url = url_for('reset_password', token=token,
                                _external=True)
            html = render_template('_reset.html', reset_url=reset_url)
            msg = Message(subject=subject, recipients=[email],
                          html=html)
            mail.send(msg)
            flash('Password reset email sent to ' + email +
                  '. Check your mail.', 'success')
        else:
            flash("User doesn't exist.", 'danger')
        return redirect(url_for('index'))
    return render_template('forgot-password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token,
                                 salt=app.config['SECURITY_PASSWORD_SALT'])
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        user = User.query.filter_by(email=email).first_or_404()
        if request.form.get('password').strip() == request.form.get(
                'confirm-password').strip():
            user.password = generate_password_hash(
                request.form.get('password').strip())
            db.session.commit()
            flash('Password changed successfully.', 'success')
        else:
            flash("Passwords don't match.", 'danger')
        return redirect(url_for('index'))
    return render_template('reset-password.html')


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config[
               'ALLOWED_EXTENSIONS']


@app.route('/upload/<int:semester>/<subject>', methods=['GET', 'POST'])
@login_required
def upload(semester, subject):
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if not allowed_file(file.filename):
            flash('Please upload a file in `pdf` or `docx` format.', 'danger')
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            path = os.path.join(app.config['UPLOAD_FOLDER'],
                                os.path.join(str(semester), subject))
            if not os.path.exists(path):
                os.makedirs(path)
            file.save(os.path.join(path, filename))
            flash('File upload successful.', 'success')
            return redirect(url_for('index'))
    return render_template('upload.html')


@app.route('/download/<int:semester>/<subject>')
def download(semester, subject):
    try:
        path = os.path.join(app.config['UPLOAD_FOLDER'],
                            os.path.join(str(semester), subject))
        file = os.listdir(path)
        return send_file(os.path.join(path, file[0]), as_attachment=True)
    except Exception:
        flash('No files available for this subject.', 'info')
        return redirect(url_for('index'))


@app.route('/get_reg', methods=['GET'])
def get_reg():
    user = User.query.filter_by(
        email=request.args.get('email').strip()).first()
    return jsonify(True) if user else jsonify(False)
