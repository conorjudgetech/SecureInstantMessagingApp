# Craig: User Registration and Authentication with Account Lockout

import json
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Initialize Argon2 PasswordHasher
ph = PasswordHasher()

# File to store user data
USER_DATA_FILE = 'users.json'

def load_users():
    """
    Load user data from the JSON file.
    Returns a dictionary of users.
    """
    try:
        with open(USER_DATA_FILE, 'r') as f:
            users = json.load(f)
            return users
    except (FileNotFoundError, json.JSONDecodeError):
        # Return empty dictionary if file not found or invalid JSON
        return {}

def save_users(users):
    """
    Save user data to the JSON file.
    """
    with open(USER_DATA_FILE, 'w') as f:
        json.dump(users, f)

def hash_password(password):
    """
    Hash the given password using Argon2.
    Returns the hashed password.
    """
    return ph.hash(password)

def verify_password(password_hash, password):
    """
    Verify the given password against the provided Argon2 hash.
    Returns True if valid, False otherwise.
    """
    try:
        return ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False

def increment_failed_attempts(username):
    """
    Increment the failed login attempts counter for the user.
    Lock the account if the threshold is reached.
    """
    users = load_users()
    user = users.get(username)
    if user:
        # Increment the failed attempts counter
        user['failed_attempts'] = user.get('failed_attempts', 0) + 1
        # Check if failed attempts have reached the threshold (e.g., 5)
        if user['failed_attempts'] >= 5:
            user['locked'] = True
        save_users(users)

def reset_failed_attempts(username):
    """
    Reset the failed login attempts counter for the user.
    Unlock the account if it was locked.
    """
    users = load_users()
    user = users.get(username)
    if user:
        user['failed_attempts'] = 0
        user['locked'] = False
        save_users(users)

def is_account_locked(username):
    """
    Check if the user's account is locked.
    Returns True if locked, False otherwise.
    """
    users = load_users()
    user = users.get(username)
    return user.get('locked', False) if user else False