import re
from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import json
import datetime

# Craig: User Registration and Authentication with Account Lockout
from user_authentication import (
    hash_password, verify_password, load_users, save_users,
    increment_failed_attempts, reset_failed_attempts, is_account_locked
)

# Conor: Symmetric Message Encryption with Per-Message Key Derivation
from message_encryption import (
    encrypt_message, decrypt_message, derive_per_message_key
)

# Harsha: Secure Key Exchange
from key_exchange import (
    generate_ecdh_key_pair, generate_ephemeral_key_pair, derive_shared_key
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
    load_pem_public_key, load_pem_private_key
)

# Siddarth: Digital Signatures with Certificates and Audit Logging
from digital_signature import (
    generate_signature_key_pair, sign_message, verify_signature
)
from cryptography import x509

# Conor
# Initialize Flask application
app = Flask(__name__)
app.secret_key = os.urandom(16)  # Secret key for session management

# Configure session for security
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    # SESSION_COOKIE_SECURE=True  # Uncomment if running over HTTPS
)

# Conor
# File paths for data storage
USER_DATA_FILE = 'users.json'
MESSAGE_DATA_FILE = 'messages.json'

# Conor
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
                    msg['salt'] = bytes.fromhex(msg['salt'])
                    msg['info'] = bytes.fromhex(msg['info'])
                    msg['signature'] = bytes.fromhex(msg['signature'])
                    msg['timestamp'] = bytes.fromhex(msg['timestamp'])
                    # Ephemeral public key remains a PEM string
            return messages
    except (FileNotFoundError, json.JSONDecodeError):
        # Return empty dictionary if file not found or invalid JSON
        return {}

# Conor
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
            msg_copy['salt'] = msg_copy['salt'].hex()
            msg_copy['info'] = msg_copy['info'].hex()
            msg_copy['signature'] = msg_copy['signature'].hex()
            msg_copy['timestamp'] = msg_copy['timestamp'].hex()
            # Ephemeral public key remains a PEM string
            messages_to_save[user].append(msg_copy)
    with open(MESSAGE_DATA_FILE, 'w') as f:
        json.dump(messages_to_save, f, indent=4)

# Conor
# Load users and messages from JSON files
users = load_users()
messages = load_messages()

# Conor
@app.route('/')
def index():
    """
    Home route. Redirects users to inbox if logged in, else to login page.
    """
    if 'username' in session:
        return redirect(url_for('inbox'))
    else:
        return redirect(url_for('login'))

# Craig: User Registration with Account Lockout
# Strong password validation
def is_strong_password(password):
    """
    Validates the strength of the password.
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

# Craig: User Registration with Account Lockout
@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handles user registration with certificate generation and strong password enforcement.
    """
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        users = load_users()

        # Check for empty username
        if not username:
            flash('Username cannot be empty.')
            return redirect(url_for('register'))

        # Check if username already exists
        if username in users:
            flash('Username already exists.')
            return redirect(url_for('register'))

        # Enforce strong password
        if not is_strong_password(password):
            flash('Password must be at least 8 characters long and include uppercase letters, lowercase letters, digits, and special characters.')
            return redirect(url_for('register'))

        # Hash the password
        password_hash = hash_password(password)

        # Generate ECDH key pair (Harsha)
        ecdh_private_key, ecdh_public_key = generate_ecdh_key_pair()
        # Serialize keys to PEM format
        ecdh_private_pem = ecdh_private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode('utf-8')
        ecdh_public_pem = ecdh_public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Generate signature key pair and certificate (Siddarth)
        sig_private_key, sig_certificate = generate_signature_key_pair(username)
        # Serialize private key to PEM format
        sig_private_pem = sig_private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode('utf-8')
        # Serialize certificate to PEM format
        sig_certificate_pem = sig_certificate.public_bytes(Encoding.PEM).decode('utf-8')

        # Store user data
        users[username] = {
            'password_hash': password_hash,
            'failed_attempts': 0,
            'locked': False,
            'ecdh_private_key': ecdh_private_pem,
            'ecdh_public_key': ecdh_public_pem,
            'sig_private_key': sig_private_pem,
            'sig_certificate': sig_certificate_pem  # Store certificate
        }

        # Save updated users data
        save_users(users)

        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

# Craig: User Login with Account Lockout
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
                    flash(f'Invalid password. You have {remaining_attempts} more attempt(s) before your account is locked.')
                else:
                    flash('Your account has been locked due to multiple failed login attempts. Please contact support.')
                return redirect(url_for('login'))
        else:
            # Username not found
            flash('Invalid username.')
            return redirect(url_for('login'))

    return render_template('login.html')

# Conor
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

# Send Message Route (Conor, Harsha, Siddarth)
@app.route('/send', methods=['GET', 'POST'])
def send_message():
    """
    Handles sending messages with ephemeral key exchange and enhanced signatures.
    """
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        sender = session['username']
        recipient = request.form['recipient']
        plaintext = request.form['message'].encode()

        users = load_users()
        if recipient not in users:
            flash('Recipient does not exist.')
            return redirect(url_for('send_message'))

        try:
            # Load recipient's static ECDH public key
            recipient_ecdh_public_key = load_pem_public_key(
                users[recipient]['ecdh_public_key'].encode('utf-8')
            )
        except ValueError as e:
            flash('Failed to load recipient\'s public key. Cannot send message.')
            app.logger.error(f"Failed to load recipient's ECDH public key: {e}")
            return redirect(url_for('send_message'))
        except Exception as e:
            flash('An unexpected error occurred while loading recipient\'s public key.')
            app.logger.error(f"Unexpected error loading recipient's ECDH public key: {e}")
            return redirect(url_for('send_message'))

        try:
            # Generate sender's ephemeral ECDH key pair (Harsha)
            ephemeral_private_key, ephemeral_public_key = generate_ephemeral_key_pair()
            # Serialize ephemeral public key to PEM format
            ephemeral_public_pem = ephemeral_public_key.public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
        except Exception as e:
            flash('Failed to generate ephemeral key pair.')
            app.logger.error(f"Failed to generate ephemeral ECDH key pair: {e}")
            return redirect(url_for('send_message'))

        try:
            # Derive shared secret using sender's ephemeral private key and recipient's static public key
            shared_secret = derive_shared_key(ephemeral_private_key, recipient_ecdh_public_key)
        except Exception as e:
            flash('Failed to derive shared secret.')
            app.logger.error(f"Failed to derive shared secret: {e}")
            return redirect(url_for('send_message'))

        try:
            # Generate per-message salt and info
            salt = os.urandom(16)
            info = f'{sender}:{recipient}'.encode()

            # Derive per-message key using HKDF (Conor)
            per_message_key = derive_per_message_key(shared_secret, salt, info)
        except Exception as e:
            flash('Failed to derive per-message encryption key.')
            app.logger.error(f"Failed to derive per-message key: {e}")
            return redirect(url_for('send_message'))

        try:
            # Encrypt the message (Conor)
            ciphertext, nonce = encrypt_message(plaintext, per_message_key)
        except Exception as e:
            flash('Failed to encrypt the message.')
            app.logger.error(f"Encryption failed: {e}")
            return redirect(url_for('send_message'))

        try:
            # Sign the ciphertext with timestamp (Siddarth)
            sender_sig_private_key = load_pem_private_key(
                users[sender]['sig_private_key'].encode('utf-8'),
                password=None
            )
            signature, timestamp = sign_message(sender_sig_private_key, ciphertext)
        except Exception as e:
            flash('Failed to sign the message.')
            app.logger.error(f"Signing failed: {e}")
            return redirect(url_for('send_message'))

        # Load messages
        messages = load_messages()

        # Store the message
        message_entry = {
            'sender': sender,
            'ciphertext': ciphertext,
            'nonce': nonce,
            'salt': salt,
            'info': info,
            'signature': signature,
            'timestamp': timestamp,
            'ephemeral_public_key': ephemeral_public_pem  # Include ephemeral public key
        }
        messages.setdefault(recipient, []).append(message_entry)

        # Save updated messages data
        save_messages(messages)

        flash('Message sent successfully.')
        return redirect(url_for('inbox'))

    users = load_users()
    users_list = [user for user in users.keys() if user != session['username']]
    return render_template('send.html', users=users_list)

# View Message Route (Conor, Harsha, Siddarth)
@app.route('/message/<int:msg_id>', methods=['GET'])
def view_message(msg_id):
    """
    Handles viewing messages with ephemeral key exchange and enhanced signatures.
    """
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    messages = load_messages()
    user_messages = messages.get(username, [])

    if msg_id < 0 or msg_id >= len(user_messages):
        flash('Message does not exist.')
        return redirect(url_for('inbox'))

    message = user_messages[msg_id]
    sender = message['sender']
    ciphertext = message['ciphertext']
    nonce = message['nonce']
    salt = message['salt']
    info = message['info']
    signature = message['signature']
    timestamp = message['timestamp']
    ephemeral_public_pem = message['ephemeral_public_key']

    users = load_users()

    try:
        # Load recipient's static ECDH private key
        recipient_ecdh_private_key = load_pem_private_key(
            users[username]['ecdh_private_key'].encode('utf-8'),
            password=None
        )
    except Exception as e:
        flash('Failed to load your ECDH private key.')
        app.logger.error(f"Failed to load recipient's ECDH private key: {e}")
        return redirect(url_for('inbox'))

    try:
        # Load sender's ephemeral ECDH public key
        sender_ephemeral_public_key = load_pem_public_key(
            ephemeral_public_pem.encode('utf-8')
        )
    except ValueError as e:
        flash('Failed to load sender\'s public key. The message may have been tampered with.')
        app.logger.error(f"Failed to load sender's ephemeral public key: {e}")
        return redirect(url_for('inbox'))
    except Exception as e:
        flash('An unexpected error occurred while loading sender\'s public key.')
        app.logger.error(f"Unexpected error loading sender's ECDH public key: {e}")
        return redirect(url_for('inbox'))

    try:
        # Derive shared secret using recipient's private key and sender's ephemeral public key
        shared_secret = derive_shared_key(recipient_ecdh_private_key, sender_ephemeral_public_key)
    except Exception as e:
        flash('Failed to derive shared secret.')
        app.logger.error(f"Failed to derive shared secret: {e}")
        return redirect(url_for('inbox'))

    try:
        # Derive per-message key using HKDF (Conor)
        per_message_key = derive_per_message_key(shared_secret, salt, info)
    except Exception as e:
        flash('Failed to derive per-message encryption key.')
        app.logger.error(f"Failed to derive per-message key: {e}")
        return redirect(url_for('inbox'))

    try:
        # Load sender's signature certificate
        sig_certificate_pem = users[sender]['sig_certificate']
        sig_certificate = x509.load_pem_x509_certificate(sig_certificate_pem.encode('utf-8'))
        sender_sig_public_key = sig_certificate.public_key()
    except Exception as e:
        flash('Failed to load sender\'s signature certificate.')
        app.logger.error(f"Failed to load sender's signature certificate: {e}")
        return redirect(url_for('inbox'))

    try:
        # Verify the signature with timestamp (Siddarth)
        if not verify_signature(sender_sig_public_key, ciphertext, signature, timestamp):
            flash('Signature verification failed.')
            return redirect(url_for('inbox'))
    except Exception as e:
        flash('An error occurred during signature verification.')
        app.logger.error(f"Signature verification error: {e}")
        return redirect(url_for('inbox'))

    try:
        # Check if the message timestamp is within an acceptable time window
        message_time = datetime.datetime.fromisoformat(timestamp.decode())
        current_time = datetime.datetime.utcnow()
        time_difference = current_time - message_time

        if time_difference.total_seconds() > 300:  # 5 minutes
            flash('Message is outdated or replayed.')
            return redirect(url_for('inbox'))
    except ValueError as e:
        flash('Invalid message timestamp.')
        app.logger.error(f"Invalid message timestamp: {e}")
        return redirect(url_for('inbox'))
    except Exception as e:
        flash('An unexpected error occurred while processing the message timestamp.')
        app.logger.error(f"Unexpected error processing timestamp: {e}")
        return redirect(url_for('inbox'))

    try:
        # Decrypt the message (Conor)
        plaintext = decrypt_message(ciphertext, nonce, per_message_key)
    except Exception as e:
        flash('Message decryption failed.')
        app.logger.error(f"Decryption failed: {e}")
        return redirect(url_for('inbox'))

    return render_template('view_message.html', sender=sender, message=plaintext.decode())

if __name__ == '__main__':
    app.run(debug=True)
