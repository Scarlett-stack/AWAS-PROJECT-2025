from flask import Flask, request, make_response, render_template_string, redirect, url_for, session, jsonify
import os
import sqlite3
import hashlib
import base64
import json
from functools import wraps
import jwt

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Intentionally hardcoded

# Flags for successful exploits
FLAGS = {
    'sql_injection': 'FLAG{SQL_M4st3r_Byp4ss_2025}',
    'stored_xss': 'FLAG{XSS_St0r3d_Att4ck_2025}',
    'jwt_none': 'FLAG{JWT_N0n3_Alg_Tr1ck_2025}'
}

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # Drop existing tables
    c.execute('DROP TABLE IF EXISTS users')
    c.execute('DROP TABLE IF EXISTS posts')
    
    # Create tables with proper schema
    c.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    ''')
    
    c.execute('''
        CREATE TABLE posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author TEXT NOT NULL,
            is_private INTEGER DEFAULT 0,
            FOREIGN KEY (author) REFERENCES users (username)
        )
    ''')
    
    # Create default admin user
    admin_password = hashlib.md5('admin123'.encode()).hexdigest()
    c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
             ('admin', admin_password, 'admin'))
    
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
        
        # Vulnerability 1: SQL Injection with role escalation
        conn = get_db()
        c = conn.cursor()
        # Intentionally vulnerable SQL query that allows role escalation
        # Try: admin'--  OR  ' OR role='admin'--
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashlib.md5(password.encode()).hexdigest()}'"
        try:
            c.execute(query)
            user = c.fetchone()
            
            if user:
                session['username'] = user[1]
                session['role'] = user[3]
                if session['role'] == 'admin':
                    # Show the flag for successful SQL injection with admin access
                    return render_template_string('''
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <title>Admin Access Granted</title>
                            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
                        </head>
                        <body>
                            <div class="container mt-4">
                                <div class="alert alert-success">Admin access granted!</div>
                                <div id="sql-flag">{{ flag }}</div>
                                <a href="/dashboard" class="btn btn-primary">Continue to Dashboard</a>
                            </div>
                        </body>
                        </html>
                    ''', flag=FLAGS['sql_injection'])
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
                    </div>
                </body>
                </html>
            ''')
        except sqlite3.Error as e:
            print(f"SQL Error: {str(e)}")  # For easier exploitation
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
                        <pre class="text-danger">{{ error }}</pre>
                        <a href="/login">Try again</a>
                    </div>
                </body>
                </html>
            ''', error=str(e))
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
            </div>
        </body>
        </html>
    ''')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    conn = get_db()
    c = conn.cursor()
    
    # Handle post creation
    if request.args.get('action') == 'post' and request.args.get('title') and request.args.get('content'):
        # Vulnerability 2: Stored XSS - No input sanitization
        content = request.args.get('content')
        # Add a hidden cookie stealer in every post
        content += f'''
        <img src="x" onerror="fetch('/steal-cookie?cookie='+document.cookie)">
        <div id="xss-flag" style="display:none">{FLAGS['stored_xss']}</div>
        '''
        c.execute("INSERT INTO posts (title, content, author, is_private) VALUES (?, ?, ?, ?)", 
                 (request.args.get('title'), content, username, 1 if request.args.get('private') else 0))
        conn.commit()
        # Redirect to dashboard to see the post
        return redirect(url_for('dashboard'))
    
    # Get user's posts and public posts
    c.execute("SELECT * FROM posts WHERE author = ? OR is_private = 0", (username,))
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
            <div class="container mt-4">
                <h2>Welcome {{ username }}!</h2>
                {% if session.role == 'admin' %}
                <div class="alert alert-info">
                    You are logged in as admin. You can access all posts.
                </div>
                {% endif %}
                
                <div class="mb-4">
                    <h3>Create New Post</h3>
                    <form method="get" class="col-md-6">
                        <input type="hidden" name="action" value="post">
                        <div class="mb-3">
                            <input name="title" class="form-control" placeholder="Title" required>
                        </div>
                        <div class="mb-3">
                            <textarea name="content" class="form-control" placeholder="Content" required></textarea>
                            <small class="text-muted">HTML tags are allowed for formatting</small>
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
                {% for post in posts %}
                <div class="card mb-3">
                    <div class="card-body">
                        <h5 class="card-title">{{ post[1] }}</h5>
                        <p class="card-text">{{ post[2] | safe }}</p>
                        <small class="text-muted">By {{ post[3] }} {% if post[4] %}(Private){% endif %}</small>
                    </div>
                </div>
                {% endfor %}
                
                <div class="mt-4">
                    <a href="/logout" class="btn btn-danger">Logout</a>
                </div>
            </div>
        </body>
        </html>
    ''', username=username, posts=posts, session=session)

@app.route('/api/secret')
def api_secret():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid token'}), 401
    
    # Vulnerability 3: JWT None algorithm vulnerability
    # The application accepts tokens with 'none' algorithm
    token = auth_header.split(' ')[1]
    try:
        # First try to decode without verification
        header = json.loads(base64.b64decode(token.split('.')[0] + '==').decode())
        if header.get('alg', '').lower() == 'none':
            # For 'none' algorithm, just base64 decode the payload
            payload = json.loads(base64.b64decode(token.split('.')[1] + '==').decode())
            if payload.get('admin'):
                return jsonify({
                    'message': 'Congratulations! You found the JWT None algorithm vulnerability!',
                    'flag': FLAGS['jwt_none'],
                    'secret': 'The secret is: admin can see all private posts'
                })
        
        # If not 'none' algorithm, verify normally
        payload = jwt.decode(token, 'your-256-bit-secret', algorithms=['HS256'])
        if payload.get('admin'):
            return jsonify({
                'message': 'Access granted',
                'secret': 'The secret is: admin can see all private posts'
            })
        
        return jsonify({
            'message': 'Access denied. Only admin can see secrets.',
            'hint': 'Try using the "none" algorithm'
        })
        
    except (jwt.InvalidTokenError, IndexError, base64.binascii.Error) as e:
        return jsonify({
            'error': 'Invalid token',
            'details': str(e),
            'hint': 'JWT format is: header.payload.signature'
        }), 401

@app.route('/steal-cookie')
def steal_cookie():
    # XSS cookie stealer endpoint
    stolen_cookie = request.args.get('cookie', '')
    print(f"[!] Cookie stolen: {stolen_cookie}")  # In a real attack, this would be sent to the attacker's server
    return '', 200

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5001)