from flask import Flask, render_template, request, session, redirect, url_for, jsonify, send_from_directory
import sqlite3
import hashlib
import json
import jwt
import os
import base64

app = Flask(__name__, template_folder='templates', static_url_path='/static')

# Serve static files
@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

def get_random_tech_image():
    # List of tech-related placeholder images from Lorem Picsum
    tech_images = [
        "https://picsum.photos/id/2/800/400",  # Laptop
        "https://picsum.photos/id/3/800/400",  # Tech workspace
        "https://picsum.photos/id/4/800/400",  # Office desk
        "https://picsum.photos/id/180/800/400",  # Computer setup
        "https://picsum.photos/id/160/800/400"   # Modern office
    ]
    import random
    return random.choice(tech_images)

app.secret_key = 'your-secret-key-here'  # Change this in production
JWT_SECRET = 'your-256-bit-secret'  # Change this in production

# Load flags from external file
with open('flags.json') as f:
    FLAGS = json.load(f)

def get_db():
    db = sqlite3.connect('blog.db')
    db.row_factory = sqlite3.Row
    return db

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # Create users table with MD5 hashed passwords (intentionally weak)
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,  -- MD5 hashed (vulnerable)
            role TEXT DEFAULT 'user'
        )
    ''')
    
    # Create posts table
    c.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            content TEXT,  -- Vulnerable to XSS
            author TEXT,
            is_private INTEGER DEFAULT 0,
            FOREIGN KEY (author) REFERENCES users (username)
        )
    ''')
    
    # Add admin user if not exists
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        c.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ('admin', hashlib.md5('admin123'.encode()).hexdigest(), 'admin')
        )
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    conn = get_db()
    c = conn.cursor()
    
    # Get latest public posts with user roles
    c.execute("""
        SELECT posts.*, users.role 
        FROM posts 
        JOIN users ON posts.author = users.username 
        WHERE is_private = 0 
        ORDER BY id DESC LIMIT 10
    """)
    posts = c.fetchall()
    
    # Get featured post (admin's latest post)
    c.execute("""
        SELECT posts.*, users.role 
        FROM posts 
        JOIN users ON posts.author = users.username 
        WHERE users.role = 'admin' AND is_private = 0 
        ORDER BY id DESC LIMIT 1
    """)
    featured_post = c.fetchone()
    
    # Get post categories (simulated)
    categories = [
        {"name": "Python", "count": 15, "icon": "bi-filetype-py"},
        {"name": "JavaScript", "count": 12, "icon": "bi-filetype-js"},
        {"name": "Web Security", "count": 8, "icon": "bi-shield-lock"},
        {"name": "DevOps", "count": 10, "icon": "bi-gear-wide-connected"},
        {"name": "Machine Learning", "count": 5, "icon": "bi-cpu"}
    ]
    
    conn.close()
    
    return render_template('index.html', posts=posts, featured_post=featured_post, categories=categories, get_random_tech_image=get_random_tech_image)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        c = conn.cursor()
        
        # Check if username exists
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        if c.fetchone():
            error = 'Username already exists'
        else:
            # Vulnerability: Weak password hashing (MD5)
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                     (username, hashlib.md5(password.encode()).hexdigest(), 'user'))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        conn.close()
    
    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        c = conn.cursor()
        
        # Vulnerability 1: SQL Injection
        # Example exploit: ' OR '1'='1' --
        query = f"SELECT username, password, role FROM users WHERE username = '{username}' AND password = '{hashlib.md5(password.encode()).hexdigest()}'"
        try:
            print(f"Executing query: {query}")  # For debugging
            c.execute(query)
            user = c.fetchone()
            
            if user:
                session['username'] = user['username']
                session['role'] = user['role']
                # Check if this was a SQL injection attempt
                if "'" in username and " OR " in username.upper():
                    return f'SQL Injection successful! Flag: {FLAGS["sql_injection"]}'
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid credentials'
        except sqlite3.Error as e:
            error = f'Database error: {str(e)}'
            print(f"SQL Error: {str(e)}")  # For debugging
        finally:
            conn.close()
    
    return render_template('login.html', error=error)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    error = None
    success = None
    
    conn = get_db()
    c = conn.cursor()
    
    if request.method == 'POST':
        title = request.form.get('title', '')
        content = request.form.get('content', '')
        is_private = request.form.get('private', '0')
        
        # Create new post
        try:
            c.execute(
                'INSERT INTO posts (title, content, author, is_private) VALUES (?, ?, ?, ?)',
                (title, content, session['username'], is_private == '1')
            )
            conn.commit()
            success = 'Post created successfully!'
            
            # If XSS payload detected, show flag
            if '<script>' in content.lower():
                success = f'XSS payload detected! Flag: {FLAGS["xss_stored"]}'
        except Exception as e:
            error = f'Error creating post: {str(e)}'
    
    # Get user's posts
    c.execute('''
        SELECT posts.*, users.role 
        FROM posts 
        JOIN users ON posts.author = users.username 
        WHERE author = ? OR is_private = 0
        ORDER BY id DESC
    ''', (session['username'],))
    posts = c.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', error=error, success=success, posts=posts)

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    conn = get_db()
    c = conn.cursor()
    
    # Get user info
    c.execute("SELECT username, role FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    
    if not user:
        # Handle case where user is in session but not in database
        session.clear()
        return redirect(url_for('login'))
    
    # Get user's total posts
    c.execute("SELECT COUNT(*) FROM posts WHERE author = ?", (username,))
    total_posts = c.fetchone()[0]
    
    # Get user's latest posts
    c.execute("SELECT * FROM posts WHERE author = ? ORDER BY id DESC LIMIT 3", (username,))
    latest_posts = c.fetchall()
    
    conn.close()
    
    return render_template('profile.html', user=user, total_posts=total_posts, latest_posts=latest_posts)

@app.route('/admin')
def admin():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    conn = get_db()
    c = conn.cursor()
    
    # Get all users
    c.execute('SELECT username, role FROM users')
    users = c.fetchall()
    
    # Get all posts
    c.execute('''
        SELECT posts.*, users.role 
        FROM posts 
        JOIN users ON posts.author = users.username 
        ORDER BY id DESC
    ''')
    posts = c.fetchall()
    
    conn.close()
    
    return render_template(template_name_or_list='admin.html', users=users, posts=posts)

@app.route('/api/secret')
def api_secret():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return jsonify({
            'error': 'No token provided',
            'hint': 'Add Authorization: Bearer <token> header'
        }), 401
    
    try:
        # Vulnerability 3: JWT None algorithm
        # Try: header = {"alg":"none"}, payload = {"role":"admin"}
        header = jwt.get_unverified_header(token)
        if header['alg'].lower() == 'none':
            # This is the vulnerability - accepting 'none' algorithm
            payload = jwt.decode(token, options={'verify_signature': False})
        else:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        
        if payload.get('role') == 'admin':
            return jsonify({
                'message': 'Access granted!',
                'flag': FLAGS['jwt_none'],
                'secret': 'The treasure is buried under the palm tree'
            })
        
        return jsonify({
            'error': 'Access denied',
            'hint': 'Only admins can access this endpoint'
        }), 403
        
    except jwt.InvalidTokenError as e:
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

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host='127.0.0.1', port=5000)