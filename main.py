
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\Bongeka.Mpofu\\DB Browser for SQLite\\authenticate.db'

from flask import Flask, render_template, url_for, flash, redirect, request, make_response
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.github import make_github_blueprint, github
from flask import Flask, session
from flask import session as login_session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_avatars import Avatars
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo

from datetime import datetime, timedelta
import hashlib
import secrets
import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required
from flask_bcrypt import Bcrypt
import random
import string

# Initialize app and extensions
app = Flask(__name__)

# Email Configuration
mail=Mail(app)

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'oooo@gmail.com'
app.config['MAIL_PASSWORD'] = 'abcd efgh lyeu mtxq'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_DEFAULT_SENDER'] = 'default_sender_email'
app.config['MAIL_ASCII_ATTACHMENTS'] = True
app.config['DEBUG'] = True

mail = Mail(app)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\Bongeka.Mpofu\\DB Browser for SQLite\\authenticate.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
mail = Mail(app)

# User model with email, password, and verification code
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    verification_code = db.Column(db.String(6), nullable=True)

    def __repr__(self):
        return f"<User {self.username}>"

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def generate_verification_code(self):
        """Generate and return a random 6-digit verification code"""
        self.verification_code = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        db.session.commit()

# Login manager user_loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

@app.route('/')
def index():
    return render_template('base.html')


# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if the user already exists
        user = User.query.filter_by(email=email).first()
        if user:
            flash("Email already registered.", "danger")
            return redirect(url_for('register'))

        # Create and store the new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Generate and send the verification code
        new_user.generate_verification_code()
        try:
            # Send verification email
            msg = Message('Account Registration Verification', recipients=[email])
            msg.body = f"Hello {username},\n\nYour verification code is: {new_user.verification_code}\nUse this code to log in."
            mail.send(msg)
            flash('Registration successful! Check your email for the verification code.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Error sending email: {str(e)}", 'danger')

    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        verification_code = request.form['verification_code']

        # Fetch the user from the database
        user = User.query.filter_by(email=email).first()

        if user and user.verification_code == verification_code:
            login_user(user)  # Log the user in if the code matches
            flash('Login successful!', 'success')
            return redirect(url_for('welcome'))
        else:
            flash('Invalid email or verification code.', 'danger')

    return render_template('login.html')

# Welcome route (after login)
@app.route('/welcome')
@login_required
def welcome():
    return f"Welcome {current_user.username}!"



# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Error handling for 404 and 500
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

if __name__ == "__main__":
    #app_dir = op.realpath(os.path.dirname(__file__))
    with app.app_context():
        db.create_all()
        #export_to_xml()
    app.run(debug=True)
