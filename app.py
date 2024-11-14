from flask import Flask, render_template, request, redirect, url_for, session, flash
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Team Member 1: Craig: User Registration and Authentication with Account Lockout
from user_authentication import (
    hash_password, verify_password, load_users, save_users,
    increment_failed_attempts, reset_failed_attempts, is_account_locked
)


# Initialize Flask application
app = Flask(__name__)
app.secret_key = os.urandom(16)  # Secret key for session management

# Configure session for security
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    # SESSION_COOKIE_SECURE=True  # Uncomment if running 
)

# File paths for data storage
USER_DATA_FILE = 'users.json'
MESSAGE_DATA_FILE = 'messages.json'

def load_messages():
    """
    Load messages from the JSON file.
    Returns a dictionary of messages.
    """
    try:
        with open(MESSAGE_DATA_FILE, 'r') as f:
            messages = json.load(f)
            # Convert hex strings back to bytes where necessary
            for user_msgs in messages.values():
                for msg in user_msgs:
                    msg['ciphertext'] = bytes.fromhex(msg['ciphertext'])
                    msg['nonce'] = bytes.fromhex(msg['nonce'])
                    msg['signature'] = bytes.fromhex(msg['signature'])
            return messages
    except (FileNotFoundError, json.JSONDecodeError):
        # Return empty dictionary if file not found or invalid JSON
        return {}

def save_messages(messages):
    """
    Save messages to the JSON file.
    """
    # Convert bytes to hex strings before saving
    messages_to_save = {}
    for user, user_msgs in messages.items():
        messages_to_save[user] = []
        for msg in user_msgs:
            msg_copy = msg.copy()
            msg_copy['ciphertext'] = msg_copy['ciphertext'].hex()
            msg_copy['nonce'] = msg_copy['nonce'].hex()
            msg_copy['signature'] = msg_copy['signature'].hex()
            messages_to_save[user].append(msg_copy)
    with open(MESSAGE_DATA_FILE, 'w') as f:
        json.dump(messages_to_save, f)

# Load users and messages from JSON files
users = load_users()
messages = load_messages()

@app.route('/')
def index():
    """
    Home route. Redirects users to inbox if logged in, else to login page.
    """
    if 'username' in session:
        return redirect(url_for('inbox'))
    else:
        return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handles user registration.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        users = load_users()

        # Check if username already exists
        if username in users:
            flash('Username already exists.')
            return redirect(url_for('register'))

        # Hash the password
        password_hash = hash_password(password)

        # Generate ECDH key pair (Team Member 3)
        ecdh_private_key, ecdh_public_key = generate_ecdh_key_pair()
        # Serialize keys to PEM format
        ecdh_private_pem = ecdh_private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode('utf-8')
        ecdh_public_pem = ecdh_public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        sig_private_key, sig_public_key = generate_signature_key_pair()
        # Serialize keys to PEM format
        sig_private_pem = sig_private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode('utf-8')
        sig_public_pem = sig_public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Store user data
        users[username] = {
            'password_hash': password_hash,
            'failed_attempts': 0,
            'locked': False,
            'ecdh_private_key': ecdh_private_pem,
            'ecdh_public_key': ecdh_public_pem,
            'sig_private_key': sig_private_pem,
            'sig_public_key': sig_public_pem
        }

        # Save updated users data
        save_users(users)

        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

# Team Member 1: User Login with Account Lockout
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login with account lockout.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        users = load_users()
        user = users.get(username)

        if user:
            # Check if the account is locked
            if is_account_locked(username):
                flash('Your account is locked due to multiple failed login attempts. Please contact support.')
                return redirect(url_for('login'))

            # Verify password
            if verify_password(user['password_hash'], password):
                # Successful login
                session['username'] = username
                reset_failed_attempts(username)  # Reset failed attempts counter
                flash('Login successful.')
                return redirect(url_for('inbox'))
            else:
                # Failed login attempt
                increment_failed_attempts(username)
                remaining_attempts = 5 - user.get('failed_attempts', 0)
                if remaining_attempts > 0:
                    flash(f'Invalid username or password. You have {remaining_attempts} more attempt(s) before your account is locked.')
                else:
                    flash('Your account has been locked due to multiple failed login attempts. Please contact support.')
                return redirect(url_for('login'))
        else:
            # Username not found
            flash('Invalid username or password.')
            return redirect(url_for('login'))

    return render_template('login.html')

# Logout Route
@app.route('/logout')
def logout():
    """
    Handles user logout.
    """
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))

# Inbox Route
@app.route('/inbox')
def inbox():
    """
    Displays the user's inbox with received messages.
    """
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    messages = load_messages()
    user_messages = messages.get(username, [])
    return render_template('inbox.html', messages=user_messages)

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