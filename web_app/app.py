# Import Flask tools for routing, forms, sessions, and messages
from flask import Flask, render_template, request, redirect, url_for, session, flash
from cryptography.fernet import Fernet

# Import SQLite for a lightweight local database
import sqlite3

# Import secure password hashing functions
from werkzeug.security import generate_password_hash, check_password_hash

# Import wraps so our custom decorator keeps route information
from functools import wraps

# Import datetime for timestamps
from datetime import datetime, timedelta


# Create the Flask application
app = Flask(__name__)

# Secret key is used by Flask to protect sessions
# Change this later to a stronger random value for better security
app.secret_key = "change_this_to_a_long_random_secret_key"

# Automatically log out inactive users after 5 minutes
app.permanent_session_lifetime = timedelta(minutes=5)

# Name of the SQLite database file
DATABASE = "secure_chat.db"

# -------------------------------------------------------------------
# Message encryption setup
# -------------------------------------------------------------------
# This key is used to encrypt and decrypt staff messages.
# It helps protect message confidentiality in case someone accesses
# the database file directly.

ENCRYPTION_KEY = b"R38ZpzqvRxnOu0eR90j_30c_O2xL3QVfrKVcPFaaKD0="

# Create a Fernet cipher object using the fixed encryption key
cipher = Fernet(ENCRYPTION_KEY)


# Create a reusable database connection function
def get_db_connection():
    # Connect to the SQLite database file
    conn = sqlite3.connect(DATABASE)

    # This allows us to access database columns by name
    conn.row_factory = sqlite3.Row

    # Return the connection object
    return conn


# -------------------------------------------------------------------
# Message encryption functions
# -------------------------------------------------------------------
# These functions keep the logic simple:
# 1. encrypt_message() is used before storing a message in the database
# 2. decrypt_message() is used when showing a message to the receiver


def encrypt_message(plain_text):
    # Convert normal text into encrypted text before storing it
    encrypted_text = cipher.encrypt(plain_text.encode("utf-8"))
    return encrypted_text.decode("utf-8")


def decrypt_message(encrypted_text):
    # Convert encrypted database text back into readable text
    try:
        decrypted_text = cipher.decrypt(encrypted_text.encode("utf-8"))
        return decrypted_text.decode("utf-8")
    except Exception:
        # This helps avoid crashing if an old plaintext message exists
        return "[Unable to decrypt message]"


# Create the required database tables if they do not already exist
def init_db():
    # Open a database connection
    conn = get_db_connection()

    # Create a cursor to execute SQL commands
    cursor = conn.cursor()

    # Create a users table for staff account details
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            lock_until TEXT
        )
        """
    )

    # Create an audit log table to record important actions
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """
    )

    # Create a messages table to store messages between staff users
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            message_text TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (sender_id) REFERENCES users (id),
            FOREIGN KEY (receiver_id) REFERENCES users (id)
        )
    """
    )

    # Save the changes
    conn.commit()

    # Close the database connection
    conn.close()


# Record security-related events in the audit log
def log_action(user_id, action, details=""):
    # Open database connection
    conn = get_db_connection()

    # Insert the action into the audit log table
    conn.execute(
        """
        INSERT INTO audit_logs (user_id, action, details, created_at)
        VALUES (?, ?, ?, ?)
    """,
        (user_id, action, details, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )

    # Save changes
    conn.commit()

    # Close connection
    conn.close()


# Create a decorator to protect routes that require login
def login_required(route_function):
    @wraps(route_function)
    def wrapped_function(*args, **kwargs):
        # If no logged-in user exists in session, send them to login page
        if "user_id" not in session:
            flash("Please log in first.")
            return redirect(url_for("login"))

        # Otherwise allow access to the requested page
        return route_function(*args, **kwargs)

    return wrapped_function


# Automatically refresh session timeout on each request
@app.before_request
def make_session_permanent():
    if "user_id" in session:
        session.permanent = True


# Home page route
@app.route("/")
def home():
    return render_template("home.html")


# Register route for creating a new account
@app.route("/register", methods=["GET", "POST"])
def register():
    # If the user submitted the form
    if request.method == "POST":
        # Read the username from the form and remove extra spaces
        username = request.form["username"].strip()

        # Read the password fields from the form
        password = request.form["password"].strip()
        confirm_password = request.form["confirm_password"].strip()

        # Basic validation so empty values are not accepted
        if not username or not password or not confirm_password:
            flash("Username, password, and confirm password are required.")
            return redirect(url_for("register"))

        # Make sure both password fields match
        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("register"))

        # Hash the password before storing it
        password_hash = generate_password_hash(password)

        # Open database connection
        conn = get_db_connection()

        try:
            # Insert the new user into the users table
            conn.execute(
                """
                INSERT INTO users (username, password_hash, created_at)
                VALUES (?, ?, ?)
            """,
                (username, password_hash, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            )

            # Save the changes
            conn.commit()

            # Read the newly created user for logging
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

            # Log the registration action
            log_action(user["id"], "REGISTER", f"New account created for {username}")

            # Show confirmation message
            flash("Registration successful. Please log in.")

            # Send user to login page
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            # This handles duplicate usernames
            flash("That username already exists.")
            return redirect(url_for("register"))

        finally:
            # Always close the connection
            conn.close()

    # If page is opened normally, show register template
    return render_template("register.html")


# Login route for existing users
@app.route("/login", methods=["GET", "POST"])
def login():
    # If the form has been submitted
    if request.method == "POST":
        # Read username and password from the form
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        # Open database connection
        conn = get_db_connection()

        # Look up the user by username
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # If user exists, check lock status first
        if user:
            # If lock time exists, check whether it is still active
            if user["lock_until"]:
                lock_time = datetime.strptime(user["lock_until"], "%Y-%m-%d %H:%M:%S")

                # If current time is still before lock expiry, block login
                if datetime.now() < lock_time:
                    conn.close()
                    flash(
                        "Account is temporarily locked due to multiple failed login attempts. Please try again in 1 minute."
                    )
                    return redirect(url_for("login"))

                # If lock has expired, reset failed attempts and clear lock
                conn.execute(
                    """
                    UPDATE users
                    SET failed_attempts = 0, lock_until = NULL
                    WHERE id = ?
                    """,
                    (user["id"],),
                )
                conn.commit()

                # Refresh user data after reset
                user = conn.execute(
                    "SELECT * FROM users WHERE username = ?", (username,)
                ).fetchone()

            # Check whether password is correct
            if check_password_hash(user["password_hash"], password):
                # Reset failed attempts on successful login
                conn.execute(
                    """
                    UPDATE users
                    SET failed_attempts = 0, lock_until = NULL
                    WHERE id = ?
                    """,
                    (user["id"],),
                )
                conn.commit()
                conn.close()

                # Save basic user info into session
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session.permanent = True

                # Log successful login
                log_action(user["id"], "LOGIN", "User logged in successfully")

                flash("Login successful.")
                return redirect(url_for("dashboard"))

            else:
                # Increase failed attempts count
                failed_attempts = user["failed_attempts"] + 1

                # Default lock value
                lock_until = None

                # Lock account after 3 failed attempts
                if failed_attempts >= 3:
                    lock_until_time = datetime.now() + timedelta(minutes=1)
                    lock_until = lock_until_time.strftime("%Y-%m-%d %H:%M:%S")

                # Save updated failed attempts and lock time
                conn.execute(
                    """
                    UPDATE users
                    SET failed_attempts = ?, lock_until = ?
                    WHERE id = ?
                    """,
                    (failed_attempts, lock_until, user["id"]),
                )
                conn.commit()
                conn.close()

                # Log failed login
                log_action(
                    None,
                    "FAILED_LOGIN",
                    f"Failed login attempt for username: {username}",
                )

                # Show correct message
                if lock_until:
                    flash("Too many failed attempts. Account locked for 1 minute.")
                else:
                    remaining_attempts = 3 - failed_attempts
                    flash(
                        f"Invalid username or password. {remaining_attempts} attempt(s) remaining before lockout."
                    )

                return redirect(url_for("login"))

        # If username does not exist
        conn.close()
        flash("Invalid username or password.")
        return redirect(url_for("login"))

    # If page is opened normally, show login template
    return render_template("login.html")


# Logout route
@app.route("/logout")
@login_required
def logout():
    # Log the logout before clearing the session
    log_action(session["user_id"], "LOGOUT", "User logged out")

    # Remove all session data
    session.clear()

    # Show message
    flash("You have logged out.")

    # Redirect to login page
    return redirect(url_for("login"))


# Dashboard route protected by login
@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    # Open database connection
    conn = get_db_connection()

    # If the send-message form was submitted
    if request.method == "POST":
        # Read selected recipient from the form
        receiver_id = request.form["receiver_id"]

        # Read message content and remove extra spaces
        message_text = request.form["message_text"].strip()

        # Prevent empty messages
        if not message_text:
            flash("Message cannot be empty.")
            return redirect(url_for("dashboard"))

        # Encrypt the message before storing it in the database
        encrypted_message = encrypt_message(message_text)

        # Save the encrypted message into the database
        conn.execute(
            """
            INSERT INTO messages (sender_id, receiver_id, message_text, created_at)
            VALUES (?, ?, ?, ?)
        """,
            (
                session["user_id"],
                receiver_id,
                encrypted_message,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )

        # Save changes
        conn.commit()

        # Record the action in the audit log
        log_action(
            session["user_id"],
            "SEND_MESSAGE",
            f"Encrypted message sent to user ID {receiver_id}",
        )

        # Show success message
        flash("Message sent successfully.")

        # Redirect to avoid duplicate re-submission on refresh
        return redirect(url_for("dashboard"))

    # Get all users except the currently logged-in user
    users = conn.execute(
        """
        SELECT id, username
        FROM users
        WHERE id != ?
        ORDER BY username
    """,
        (session["user_id"],),
    ).fetchall()

    # Get received messages for the current user
    received_messages_raw = conn.execute(
        """
        SELECT messages.created_at, messages.message_text, users.username AS sender_name
        FROM messages
        JOIN users ON messages.sender_id = users.id
        WHERE messages.receiver_id = ?
        ORDER BY messages.created_at DESC
        """,
        (session["user_id"],),
    ).fetchall()

    # Decrypt received messages before displaying them
    received_messages = []
    for msg in received_messages_raw:
        received_messages.append(
            {
                "created_at": msg["created_at"],
                "sender_name": msg["sender_name"],
                "message_text": decrypt_message(msg["message_text"]),
            }
        )

    # Get sent messages for the current user
    sent_messages_raw = conn.execute(
        """
        SELECT messages.created_at, messages.message_text, users.username AS receiver_name
        FROM messages
        JOIN users ON messages.receiver_id = users.id
        WHERE messages.sender_id = ?
        ORDER BY messages.created_at DESC
        """,
        (session["user_id"],),
    ).fetchall()

    # Decrypt sent messages before displaying them
    sent_messages = []
    for msg in sent_messages_raw:
        sent_messages.append(
            {
                "created_at": msg["created_at"],
                "receiver_name": msg["receiver_name"],
                "message_text": decrypt_message(msg["message_text"]),
            }
        )

    # Get latest audit logs for display
    logs = conn.execute(
        """
        SELECT created_at, action, details
        FROM audit_logs
        ORDER BY created_at DESC
        LIMIT 10
        """
    ).fetchall()

    # Close connection
    conn.close()

    # Show dashboard with users, received messages, sent messages, and logs
    return render_template(
        "dashboard.html",
        users=users,
        received_messages=received_messages,
        sent_messages=sent_messages,
        logs=logs,
    )


# Start the database before the app runs
init_db()


# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)
