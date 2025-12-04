from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
import sqlite3
import jwt
import datetime
from functools import wraps
from flask_cors import CORS

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretjwtkey123'  # Change in production
bcrypt = Bcrypt(app)
CORS(app)  # Allow cross-origin requests (for frontend)

conn = sqlite3.connect('users.db', check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
""")
conn.commit()


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"message": "Token is missing"}), 401
        try:
            token = token.split()[1]  # Expect "Bearer <token>"
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            cursor.execute("SELECT * FROM users WHERE id = ?", (data['user_id'],))
            current_user = cursor.fetchone()
            if not current_user:
                raise Exception("User not found")
        except Exception as e:
            return jsonify({"message": "Token is invalid"}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400
    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
        conn.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"message": "Username already exists"}), 409

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if user and bcrypt.check_password_hash(user[2], password):
        token = jwt.encode({
            "user_id": user[0],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({"token": token})
    return jsonify({"message": "Invalid username or password"}), 401

@app.route('/protected', methods=['GET'])
@token_required
def protected_route(current_user):
    return jsonify({"message": f"Hello {current_user[1]}, you are authorized to access this!"})

if __name__ == "__main__":
    app.run(debug=True)
