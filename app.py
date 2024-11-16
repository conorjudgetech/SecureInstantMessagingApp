from flask import Flask, render_template, request, redirect, url_for, session, flash
import logging
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

# Initialize Flask application
app = Flask(__name__)
app.secret_key = os.urandom(16)  # Secret key for session management

# Configure session for security
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    # SESSION_COOKIE_SECURE=True  # Uncomment if running over HTTPS
)

# Set up logging for application errors
logging.basicConfig(
    filename='app.log',
    level=logging.ERROR,
    format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
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
            # Convert hex-encoded fields back to bytes where necessary
            for user, user_msgs in messages.items():
                for msg in user_msgs:
                    try:
                        msg['ciphertext'] = bytes.fromhex(msg['ciphertext'])
                        msg['nonce'] = bytes.fromhex(msg['nonce'])
                        msg['salt'] = bytes.fromhex(msg['salt'])
                        msg['info'] = bytes.fromhex(msg['info'])
                        msg['signature'] = bytes.fromhex(msg['signature'])
                        msg['timestamp'] = bytes.fromhex(msg['timestamp'])
                        # Ephemeral public key remains a PEM string
                    except Exception as e:
                        logging.error(f"Failed to deserialize message from {msg.get('sender', 'Unknown')} to {user}: {e}")
                        # Optionally, mark the message as corrupted or skip
                        msg['corrupted'] = True
            return messages
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Failed to load messages: {e}")
        # Return empty dictionary if file not found or invalid JSON
        return {}

def save_messages(messages):
    """
    Save messages to the JSON file.
    Converts bytes to hex strings before saving.
    """
    try:
        messages_to_save = {}
        for user, user_msgs in messages.items():
            messages_to_save[user] = []
            for msg in user_msgs:
                try:
                    msg_copy = msg.copy()
                    # Convert bytes to hex, leave strings as is
                    for key in ['ciphertext', 'nonce', 'salt', 'info', 'signature', 'timestamp']:
                        if isinstance(msg_copy[key], bytes):
                            msg_copy[key] = msg_copy[key].hex()
                    # Ephemeral public key remains a PEM string
                    if 'corrupted' in msg_copy:
                        del msg_copy['corrupted']  # Remove corrupted flag if present
                    messages_to_save[user].append(msg_copy)
                except AttributeError as ae:
                    logging.error(f"Failed to serialize message for {user}: {ae}")
                    continue
        with open(MESSAGE_DATA_FILE, 'w') as f:
            json.dump(messages_to_save, f, indent=4)
    except Exception as e:
        logging.error(f"Failed to save messages: {e}")

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

# Craig: User Registration with Account Lockout
@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handles user registration with certificate generation.
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

# Send Message Route (Conor, Harsha, Siddarth)
@app.route('/send', methods=['GET', 'POST'])
def send_message_route():
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
            return redirect(url_for('send_message_route'))

        try:
            # Load recipient's static ECDH public key
            recipient_ecdh_public_key = load_pem_public_key(
                users[recipient]['ecdh_public_key'].encode('utf-8')
            )
        except ValueError as e:
            flash('Failed to load recipient\'s public key. Cannot send message.')
            logging.error(f"Failed to load recipient's ECDH public key: {e}")
            return redirect(url_for('send_message_route'))
        except Exception as e:
            flash('An unexpected error occurred while loading recipient\'s public key.')
            logging.error(f"Unexpected error loading recipient's ECDH public key: {e}")
            return redirect(url_for('send_message_route'))

        try:
            # Generate sender's ephemeral ECDH key pair (Harsha)
            ephemeral_private_key, ephemeral_public_key = generate_ephemeral_key_pair()
            # Serialize ephemeral public key to PEM format
            ephemeral_public_pem = ephemeral_public_key.public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
        except Exception as e:
            flash('Failed to generate ephemeral key pair.')
            logging.error(f"Failed to generate ephemeral ECDH key pair: {e}")
            return redirect(url_for('send_message_route'))

        try:
            # Derive shared secret using sender's ephemeral private key and recipient's static public key
            shared_secret = derive_shared_key(ephemeral_private_key, recipient_ecdh_public_key)
        except Exception as e:
            flash('Failed to derive shared secret.')
            logging.error(f"Failed to derive shared secret: {e}")
            return redirect(url_for('send_message_route'))

        try:
            # Generate per-message salt and info
            salt = os.urandom(16)
            info = f'{sender}:{recipient}'.encode()

            # Derive per-message key using HKDF (Conor)
            per_message_key = derive_per_message_key(shared_secret, salt, info)
        except Exception as e:
            flash('Failed to derive per-message encryption key.')
            logging.error(f"Failed to derive per-message key: {e}")
            return redirect(url_for('send_message_route'))

        try:
            # Encrypt the message (Conor)
            ciphertext, nonce = encrypt_message(plaintext, per_message_key)
        except Exception as e:
            flash('Failed to encrypt the message.')
            logging.error(f"Encryption failed: {e}")
            return redirect(url_for('send_message_route'))

        try:
            # Sign the ciphertext with timestamp (Siddarth)
            sender_sig_private_key = load_pem_private_key(
                users[sender]['sig_private_key'].encode('utf-8'),
                password=None
            )
            signature, timestamp = sign_message(sender_sig_private_key, ciphertext)
        except Exception as e:
            flash('Failed to sign the message.')
            logging.error(f"Signing failed: {e}")
            return redirect(url_for('send_message_route'))

        # Load messages
        messages = load_messages()

        # Store the message
        message_entry = {
            'sender': sender,
            'ciphertext': ciphertext,  # Pass bytes directly
            'nonce': nonce.hex(),
            'salt': salt.hex(),
            'info': info.hex(),
            'signature': signature.hex(),
            'timestamp': timestamp.hex(),
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
    Handles viewing of a specific message by its ID.
    Verifies the signature and decrypts the message.
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

    # Check if the message is marked as corrupted
    if message.get('corrupted', False):
        flash('Corrupted message - Cannot be Displayed.')
        return redirect(url_for('inbox'))

    sender = message['sender']
    ciphertext = bytes.fromhex(message['ciphertext'])
    nonce = bytes.fromhex(message['nonce'])
    salt = bytes.fromhex(message['salt'])
    info = bytes.fromhex(message['info'])
    signature = bytes.fromhex(message['signature'])
    timestamp = bytes.fromhex(message['timestamp'])
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
        logging.error(f"Failed to load recipient's ECDH private key: {e}")
        return redirect(url_for('inbox'))

    try:
        # Load sender's ephemeral ECDH public key
        sender_ephemeral_public_key = load_pem_public_key(
            ephemeral_public_pem.encode('utf-8')
        )
    except Exception as e:
        flash('Failed to load sender\'s public key.')
        logging.error(f"Failed to load sender's ephemeral public key: {e}")
        # Since signature verification requires a public key, we cannot proceed
        # Log the failed attempt in signature_verification.log via digital_signature.py
        verify_signature(ephemeral_public_pem, b'', b'', b'')  # Dummy call to trigger logging
        return redirect(url_for('inbox'))

    try:
        # Derive shared secret using recipient's private key and sender's ephemeral public key
        shared_secret = derive_shared_key(recipient_ecdh_private_key, sender_ephemeral_public_key)
    except Exception as e:
        flash('Failed to derive shared secret.')
        logging.error(f"Failed to derive shared secret: {e}")
        # Log the failed attempt in signature_verification.log via digital_signature.py
        verify_signature(ephemeral_public_pem, b'', b'', b'')  # Dummy call to trigger logging
        return redirect(url_for('inbox'))

    try:
        # Derive per-message key using HKDF
        per_message_key = derive_per_message_key(shared_secret, salt, info)
    except Exception as e:
        flash('Failed to derive per-message encryption key.')
        logging.error(f"Failed to derive per-message key: {e}")
        return redirect(url_for('inbox'))

    try:
        # Load sender's signature certificate
        sig_certificate_pem = users[sender]['sig_certificate']
        sig_certificate = x509.load_pem_x509_certificate(sig_certificate_pem.encode('utf-8'))
        sender_sig_public_key_pem = sig_certificate.public_key().public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    except Exception as e:
        flash('Failed to load sender\'s signature certificate.')
        logging.error(f"Failed to load sender's signature certificate: {e}")
        return redirect(url_for('inbox'))

    try:
        # Verify the signature with timestamp
        if not verify_signature(sender_sig_public_key_pem, ciphertext, signature, timestamp):
            flash('Signature verification failed.')
            return redirect(url_for('inbox'))
    except Exception as e:
        flash('An error occurred during signature verification.')
        logging.error(f"Signature verification error: {e}")
        return redirect(url_for('inbox'))

    try:
        # Check if the message timestamp is within an acceptable time window (e.g., 5 minutes)
        timestamp_str = timestamp.decode('utf-8')
        message_time = datetime.datetime.fromisoformat(timestamp_str)
        current_time = datetime.datetime.utcnow()
        time_difference = current_time - message_time

        if time_difference.total_seconds() > 300:  # 5 minutes
            flash('Message is outdated or replayed.')
            return redirect(url_for('inbox'))
    except ValueError as e:
        flash('Invalid message timestamp.')
        logging.error(f"Invalid message timestamp: {e}")
        return redirect(url_for('inbox'))
    except Exception as e:
        flash('An unexpected error occurred while processing the message timestamp.')
        logging.error(f"Unexpected error processing timestamp: {e}")
        return redirect(url_for('inbox'))

    try:
        # Decrypt the message
        plaintext = decrypt_message(ciphertext, nonce, per_message_key)
    except Exception as e:
        flash('Message decryption failed.')
        logging.error(f"Decryption failed: {e}")
        return redirect(url_for('inbox'))

    return render_template('view_message.html', sender=sender, message=plaintext.decode())

if __name__ == '__main__':
    app.run(debug=True)