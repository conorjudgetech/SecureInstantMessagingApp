from flask import Flask, render_template, request, redirect, url_for, session, flash
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

ph = PasswordHasher()

# Load and save users
def load_users():
    # Load users from users.json
    pass

def save_users(users):
    # Save users to users.json
    pass

# Team Member 1: Craig: User Authentication
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Registration logic
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        users = load_users()
        if username in users:
            flash('Username already exists.')
            return redirect(url_for('register'))

        password_hash = ph.hash(password)
        users[username] = {'password_hash': password_hash, 'failed_attempts': 0, 'locked': False}
        save_users(users)

        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Login logic
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        users = load_users()
        user = users.get(username)

        if user:
            if user.get('locked', False):
                flash('Your account is locked.')
                return redirect(url_for('login'))

            try:
                ph.verify(user['password_hash'], password)
                user['failed_attempts'] = 0
                save_users(users)
                session['username'] = username
                flash('Login successful.')
                return redirect(url_for('inbox'))
            except:
                user['failed_attempts'] += 1
                if user['failed_attempts'] >= 5:
                    user['locked'] = True
                save_users(users)
                flash('Invalid credentials.')
                return redirect(url_for('login'))
        else:
            flash('Invalid credentials.')
            return redirect(url_for('login'))

    return render_template('login.html')

# Team Member 2: Conor: Message Handling
def load_messages():
    # load messages from messages.json
    pass

def save_messages(messages):
    # save messages to messages.json
    pass

@app.route('/inbox')
def inbox():
    # inbox display
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    messages = load_messages().get(username, [])
    return render_template('inbox.html', messages=messages)

@app.route('/send', methods=['GET', 'POST'])
def send_message():
    # sending messages
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        recipient = request.form['recipient']
        plaintext = request.form['message'].encode()

        # encryption
        key = b'static_key_32_bytes_long_for_testing!'
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # storing the message
        messages = load_messages()
        recipient_messages = messages.get(recipient, [])
        recipient_messages.append({
            'sender': session['username'],
            'ciphertext': ciphertext,
            'nonce': nonce
        })
        messages[recipient] = recipient_messages
        save_messages(messages)

        flash('Message sent.')
        return redirect(url_for('inbox'))

    return render_template('send.html')