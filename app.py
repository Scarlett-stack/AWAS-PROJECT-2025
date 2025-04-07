from flask import Flask, request, make_response, render_template_string, redirect, url_for, session, jsonify
import os
import sqlite3
import hashlib
import base64
import json
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Intentionally hardcoded

# Flags for successful exploits
FLAGS = {
    'sql_injection': 'FLAG{SQL_M4st3r_Byp4ss_2025}',
    'xss_stored': 'FLAG{XSS_St0r3d_Att4ck_2025}',
    'jwt_none': 'FLAG{JWT_N0n3_Alg_Tr1ck_2025}'
}

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS posts
                 (id INTEGER PRIMARY KEY, title TEXT, content TEXT, author TEXT, is_private INTEGER)''')
    
    # Insert admin user if not exists
    try:
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                 ('admin', hashlib.md5('admin123'.encode()).hexdigest(), 'admin'))
    except:
        pass
    conn.commit()
    conn.close()

def create_jwt(username, role):
    # Intentionally vulnerable JWT implementation
    header = base64.b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode()
    payload = base64.b64encode(json.dumps({"username": username, "role": role}).encode()).decode()
    signature = base64.b64encode("fake_signature".encode()).decode()
    return f"{header}.{payload}.{signature}"

def verify_jwt(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False
        header = json.loads(base64.b64decode(parts[0] + '=='))
        if header.get('alg', '').lower() == 'none':
            return True  # Intentionally vulnerable
        return True  # Always return True for this demo
    except:
        return False

def get_db():
    return sqlite3.connect('users.db')

def get_user_role(username):
    if not username:
        return None
    c = get_db().cursor()
    c.execute("SELECT role FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    return result[0] if result else 'user'

@app.route('/')
def index():
    username = session.get('username')
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vulnerable Web App</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
                <div class="container">
                    <a class="navbar-brand" href="/">Vulnerable Web App</a>
                    <div class="navbar-nav ms-auto">
                        {% if username %}
                            <a class="nav-link" href="/dashboard">Dashboard</a>
                            <a class="nav-link" href="/logout">Logout</a>
                        {% else %}
                            <a class="nav-link" href="/login">Login</a>
                            <a class="nav-link" href="/register">Register</a>
                        {% endif %}
                    </div>
                </div>
            </nav>
            <div class="container mt-4">
                <h1>Welcome to Vulnerable Web App</h1>
                <p>This is a deliberately vulnerable web application for security testing.</p>
            </div>
        </body>
        </html>
    ''', username=username)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username and password:
            conn = get_db()
            c = conn.cursor()
            try:
                # Store password with weak hashing
                hashed_password = hashlib.md5(password.encode()).hexdigest()
                c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                         (username, hashed_password, 'user'))
                conn.commit()
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                return "Username already exists"
            finally:
                conn.close()
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Register</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body>
            <div class="container mt-4">
                <h2>Register</h2>
                <form method="post" class="col-md-6">
                    <div class="mb-3">
                        <input name="username" class="form-control" placeholder="Username" required>
                    </div>
                    <div class="mb-3">
                        <input name="password" type="password" class="form-control" placeholder="Password" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Register</button>
                </form>
            </div>
        </body>
        </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Fixed SQL injection vulnerability
        conn = get_db()
        c = conn.cursor()
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        try:
            c.execute(query, (username, hashlib.md5(password.encode()).hexdigest()))
            user = c.fetchone()
            
            if user:
                session['username'] = user[1]  # Use the actual username from DB
                session['role'] = user[3]
                return redirect(url_for('dashboard'))
            
            return render_template_string('''
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Login Failed</title>
                    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
                </head>
                <body>
                    <div class="container mt-4">
                        <div class="alert alert-danger">Invalid credentials</div>
                        <a href="/login">Try again</a>
                        <div id="sql-flag" style="display:none">{{ flag }}</div>
                    </div>
                </body>
                </html>
            ''', flag=FLAGS['sql_injection'])
        except sqlite3.Error:
            return render_template_string('''
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Login Error</title>
                    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
                </head>
                <body>
                    <div class="container mt-4">
                        <div class="alert alert-danger">Database error occurred</div>
                        <a href="/login">Try again</a>
                        <div id="sql-flag" style="display:none">{{ flag }}</div>
                    </div>
                </body>
                </html>
            ''', flag=FLAGS['sql_injection'])
        finally:
            conn.close()
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body>
            <div class="container mt-4">
                <h2>Login</h2>
                <form method="post" class="col-md-6">
                    <div class="mb-3">
                        <input name="username" class="form-control" placeholder="Username" required>
                    </div>
                    <div class="mb-3">
                        <input name="password" type="password" class="form-control" placeholder="Password" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
                <div id="sql-flag" style="display:none">{{ flag }}</div>
            </div>
        </body>
        </html>
    ''', flag=FLAGS['sql_injection'])

@app.route('/dashboard')
def dashboard():
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))
    
    conn = get_db()
    c = conn.cursor()
    
    # Handle post creation
    if request.args.get('action') == 'post':
        title = request.args.get('title')
        content = request.args.get('content')
        is_private = 1 if request.args.get('private') else 0
        
        if title and content:
            # Vulnerability 2: Stored XSS
            c.execute("INSERT INTO posts (title, content, author, is_private) VALUES (?, ?, ?, ?)",
                     (title, content, username, is_private))
            conn.commit()
    
    # Get user's posts and public posts
    c.execute("""
        SELECT title, content, author, is_private 
        FROM posts 
        WHERE author = ? OR is_private = 0
        ORDER BY id DESC
    """, (username,))
    posts = c.fetchall()
    conn.close()
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
                <div class="container">
                    <a class="navbar-brand" href="/">Vulnerable Web App</a>
                    <div class="navbar-nav ms-auto">
                        <a class="nav-link" href="/dashboard">Dashboard</a>
                        <a class="nav-link" href="/logout">Logout</a>
                    </div>
                </div>
            </nav>
            <div class="container mt-4">
                <h2>Dashboard</h2>
                <div class="mb-4">
                    <h3>Create New Post</h3>
                    <form method="get" class="col-md-6">
                        <input type="hidden" name="action" value="post">
                        <div class="mb-3">
                            <input name="title" class="form-control" placeholder="Title" required>
                        </div>
                        <div class="mb-3">
                            <textarea name="content" class="form-control" placeholder="Content" rows="3" required></textarea>
                        </div>
                        <div class="mb-3">
                            <label>
                                <input type="checkbox" name="private" value="1"> Private Post
                            </label>
                        </div>
                        <button type="submit" class="btn btn-primary">Create Post</button>
                    </form>
                </div>
                
                <h3>Posts</h3>
                <div id="xss-flag" style="display:none">{{ flag }}</div>
                <div class="posts">
                    {% for title, content, author, is_private in posts %}
                        <div class="card mb-3">
                            <div class="card-body">
                                <h5 class="card-title">{{ title }}</h5>
                                <div class="card-text">{{ content|safe }}</div>
                                <small class="text-muted">By: {{ author }} {{ '(Private)' if is_private else '(Public)' }}</small>
                            </div>
                        </div>
                    {% endfor %}
                </div>
            </div>
        </body>
        </html>
    ''', posts=posts, flag=FLAGS['xss_stored'])

@app.route('/api/secret')
def api_secret():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid token'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        # Vulnerability 3: JWT None algorithm
        parts = token.split('.')
        if len(parts) != 3:
            return jsonify({'error': 'Invalid token format'}), 401
        
        header = json.loads(base64.b64decode(parts[0] + '=='))
        payload = json.loads(base64.b64decode(parts[1] + '=='))
        
        # Check if using 'none' algorithm
        if header.get('alg', '').lower() == 'none':
            # Intentionally accept 'none' algorithm
            user_role = payload.get('role')
            if user_role == 'admin':
                return jsonify({
                    'message': 'Congratulations! You found the JWT vulnerability.',
                    'flag': FLAGS['jwt_none']
                })
        
        # Normal JWT validation
        if verify_jwt(token):
            return jsonify({'message': 'Access granted, but no flag for you!'})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 401
    
    return jsonify({'error': 'Invalid token'}), 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5001)