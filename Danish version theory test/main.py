import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import json
import random
import stripe
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
import socket
import secrets
from datetime import datetime, timedelta
from flask_session import Session

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

app.config['STRIPE_SECRET_KEY'] = os.environ.get('STRIPE_SECRET_KEY')
app.config['STRIPE_PUBLISHABLE_KEY'] = os.environ.get('STRIPE_PUBLISHABLE_KEY')
stripe.api_key = app.config['STRIPE_SECRET_KEY']

app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_FILE_DIR'] = '/tmp/flask_session'
Session(app)

# Database configuration
database_url = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

# Neon-specific configuration
if 'neon.tech' in database_url:
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
        "pool_timeout": 30,
        "max_overflow": 15,
        "pool_size": 5
    }

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy with app configuration
db = SQLAlchemy(app)

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]',
    handlers=[logging.StreamHandler(), logging.FileHandler('flask.log')]
)

app.logger.setLevel(logging.DEBUG)

# Test database connection
try:
    with app.app_context():
        db.engine.connect()
    app.logger.info("Successfully connected to the database.")
except OperationalError as e:
    app.logger.error(f"Unable to connect to the database. Error: {e}")

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    date_of_birth = db.Column(db.Date)
    paid = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    app.logger.info('Rendering index page')
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        dob = request.form.get('dob')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({"error": "Email already registered."}), 400

        # Store user data in session
        session['temp_user_data'] = {
            'email': email,
            'password': password,
            'first_name': first_name,
            'last_name': last_name,
            'dob': dob
        }
        session.modified = True
        app.logger.debug(f"User data stored in session: {session['temp_user_data']}")

        return jsonify({"success": True, "user_data": session['temp_user_data']})

    return render_template('signup.html', stripe_publishable_key=app.config['STRIPE_PUBLISHABLE_KEY'])

@app.route('/create-payment-intent', methods=['POST'])
def create_payment_intent():
    try:
        data = json.loads(request.data)
        intent = stripe.PaymentIntent.create(
            amount=9900,
            currency='dkk',
            payment_method_types=['card', 'mobilepay', 'klarna'],
            metadata={'integration_check': 'accept_a_payment'}
        )
        return jsonify({'clientSecret': intent.client_secret})
    except Exception as e:
        return jsonify(error=str(e)), 403

@app.route('/confirm-signup')
def confirm_signup():
    app.logger.debug(f"Session data at confirm-signup: {session}")
    try:
        payment_intent_id = request.args.get('payment_intent')
        payment_intent = stripe.PaymentIntent.retrieve(payment_intent_id)

        app.logger.info(f"Payment intent status: {payment_intent.status}")

        if payment_intent.status == 'succeeded':
            user_data = session.get('temp_user_data')
            app.logger.debug(f"Retrieved user data from session: {user_data}")
            if user_data:
                new_user = User(
                    email=user_data['email'],
                    first_name=user_data['first_name'],
                    last_name=user_data['last_name'],
                    date_of_birth=datetime.strptime(user_data['dob'], '%Y-%m-%d').date(),
                    paid=True
                )
                new_user.set_password(user_data['password'])
                db.session.add(new_user)
                db.session.commit()

                session.pop('temp_user_data', None)
                app.logger.info(f"New user created: {new_user.email}")

                flash('Account created successfully. Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                app.logger.error("User data not found in session. Redirecting to signup.")
                flash('Signup process interrupted. Please try again.', 'error')
                return redirect(url_for('signup'))
        elif payment_intent.status == 'requires_payment_method':
            flash('Payment was not successful. Please try again with a different payment method.', 'error')
            return redirect(url_for('signup'))
        else:
            flash(f'Unexpected payment status: {payment_intent.status}. Please contact support.', 'error')
            return redirect(url_for('signup'))

    except Exception as e:
        app.logger.error(f"Signup confirmation failed: {str(e)}")
        flash('Signup process interrupted. Please try again.', 'error')
        return redirect(url_for('signup'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/theory-test')
@login_required
def theory_test():
    with open('questions.json', 'r') as f:
        all_questions = json.load(f)
    questions = random.sample(all_questions, 25)
    return render_template('theory_test.html', questions=questions)

@app.route('/demo-test')
def demo_test():
    with open('Demoq.json', 'r') as f:
        all_questions = json.load(f)
    questions = random.sample(all_questions, 25)
    return render_template('demo_test.html', questions=questions)

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/terms-of-service')
def terms_of_service():
    return render_template('terms_of_service.html')

# Function to find an available port
def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    # Create a test user
    with app.app_context():
        test_user = User.query.filter_by(email='test@example.com').first()
        if not test_user:
            test_user = User(email='test@example.com',
                             first_name='Test',
                             last_name='User',
                             date_of_birth=datetime.now().date(),
                             paid=True)
            test_user.set_password('testpassword')
            db.session.add(test_user)
            db.session.commit()
            app.logger.info("Test user created.")
        else:
            test_user.set_password('testpassword')
            db.session.commit()
            app.logger.info("Test user password updated.")

if __name__ == "__main__":
                app.run(host="0.0.0.0", port=5000)
