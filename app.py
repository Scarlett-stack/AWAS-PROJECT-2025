from flask import Flask, render_template_string, request, session, redirect, url_for, jsonify
import sqlite3
import hashlib
import json
import jwt
import os
import base64

app = Flask(__name__, static_url_path='/static')

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

app = Flask(__name__)
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
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>TechBlog - Share Your Knowledge</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
            <style>
                .hero-section {
                    background: linear-gradient(rgba(0,0,0,0.7), rgba(0,0,0,0.7)),
                                url('https://picsum.photos/id/180/1920/600');
                    background-size: cover;
                    background-position: center;
                    color: white;
                    padding: 100px 0;
                    margin-bottom: 40px;
                }
                .featured { 
                    border-left: 4px solid #0d6efd;
                    background-color: #f8f9fa;
                }
                .tech-tag { 
                    font-size: 0.8em;
                    color: #6c757d;
                    background: #e9ecef;
                    padding: 2px 8px;
                    border-radius: 12px;
                    margin-right: 5px;
                }
                .post-card {
                    transition: transform 0.2s;
                    margin-bottom: 20px;
                }
                .post-card:hover {
                    transform: translateY(-5px);
                }
                .post-image {
                    height: 200px;
                    object-fit: cover;
                    width: 100%;
                }
                .category-icon {
                    font-size: 1.5rem;
                    margin-right: 10px;
                }
            </style>
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
                <div class="container">
                    <a class="navbar-brand" href="/">
                        <i class="bi bi-code-square"></i> TechBlog
                    </a>
                    <div class="navbar-nav ms-auto">
                        {% if 'username' in session %}
                            <a class="nav-link" href="/dashboard">
                                <i class="bi bi-speedometer2"></i> Dashboard
                            </a>
                            <a class="nav-link" href="/profile">
                                <i class="bi bi-person"></i> Profile
                            </a>
                            <a class="nav-link" href="/logout">
                                <i class="bi bi-box-arrow-right"></i> Logout
                            </a>
                        {% else %}
                            <a class="nav-link" href="/login">
                                <i class="bi bi-box-arrow-in-right"></i> Login
                            </a>
                            <a class="nav-link" href="/register">
                                <i class="bi bi-person-plus"></i> Register
                            </a>
                        {% endif %}
                    </div>
                </div>
            </nav>
            
            <div class="hero-section text-center">
                <div class="container">
                    <h1 class="display-4">Welcome to TechBlog</h1>
                    <p class="lead">Share your technical knowledge, tutorials, and insights with the tech community.</p>
                    {% if not 'username' in session %}
                        <a href="/register" class="btn btn-primary btn-lg mt-3">
                            <i class="bi bi-person-plus"></i> Join the Community
                        </a>
                    {% endif %}
                </div>
            </div>
            
            <div class="container">
                <div class="row">
                    <div class="col-md-8">
                        {% if featured_post %}
                        <div class="card featured mb-4">
                            <img src="{{ get_random_tech_image() }}" class="card-img-top" alt="Featured post image">
                            <div class="card-body">
                                <span class="badge bg-primary mb-2">Featured Article</span>
                                <h2 class="card-title">{{ featured_post[1] }}</h2>
                                <div class="card-text">{{ featured_post[2] | safe }}</div>
                                <div class="mt-3">
                                    <span class="tech-tag">#technology</span>
                                    <span class="tech-tag">#featured</span>
                                </div>
                                <small class="text-muted">By {{ featured_post[3] }} (Editor's Pick)</small>
                            </div>
                        </div>
                        {% endif %}
                        
                        <h2 class="mb-4">Latest Articles</h2>
                        <div class="row">
                        {% for post in posts %}
                            <div class="col-md-6">
                                <div class="card post-card">
                                    <img src="{{ get_random_tech_image() }}" class="post-image" alt="Article image">
                                    <div class="card-body">
                                        <h3 class="h5 card-title">{{ post[1] }}</h3>
                                        <div class="card-text text-truncate">{{ post[2] | safe }}</div>
                                        <div class="mt-2">
                                            <span class="tech-tag">#technology</span>
                                            <span class="tech-tag">#programming</span>
                                        </div>
                                        <small class="text-muted">By {{ post[3] }}</small>
                                    </div>
                                </div>
                            </div>
                        {% endfor %}
                        </div>
                    </div>
                    
                    <div class="col-md-4">
                        <div class="card mb-4">
                            <div class="card-body">
                                <h5 class="card-title">About TechBlog</h5>
                                <p class="card-text">TechBlog is a community-driven platform where tech enthusiasts can share their knowledge and learn from others.</p>
                                {% if not 'username' in session %}
                                    <a href="/register" class="btn btn-primary">
                                        <i class="bi bi-person-plus"></i> Join the Community
                                    </a>
                                {% endif %}
                            </div>
                        </div>
                        
                        <div class="card mb-4">
                            <div class="card-body">
                                <h5 class="card-title">Categories</h5>
                                <div class="list-group list-group-flush">
                                    {% for category in categories %}
                                    <a href="#" class="list-group-item list-group-item-action d-flex justify-content-between align-items-center">
                                        <div>
                                            <i class="bi {{ category.icon }} category-icon"></i>
                                            {{ category.name }}
                                        </div>
                                        <span class="badge bg-primary rounded-pill">{{ category.count }}</span>
                                    </a>
                                    {% endfor %}
                                </div>
                            </div>
                        </div>
                        
                        <div class="card">
                            <div class="card-body">
                                <h5 class="card-title">Newsletter</h5>
                                <p class="card-text">Stay updated with the latest tech articles and tutorials.</p>
                                <form class="mt-3">
                                    <div class="mb-3">
                                        <input type="email" class="form-control" placeholder="Enter your email">
                                    </div>
                                    <button type="submit" class="btn btn-primary w-100">
                                        <i class="bi bi-envelope"></i> Subscribe
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <footer class="bg-dark text-white mt-5 py-4">
                <div class="container">
                    <div class="row">
                        <div class="col-md-6">
                            <h5><i class="bi bi-code-square"></i> TechBlog</h5>
                            <p>Share your knowledge. Learn from others.</p>
                        </div>
                        <div class="col-md-6 text-md-end">
                            <div class="h4">
                                <a href="#" class="text-white me-3"><i class="bi bi-twitter"></i></a>
                                <a href="#" class="text-white me-3"><i class="bi bi-github"></i></a>
                                <a href="#" class="text-white"><i class="bi bi-linkedin"></i></a>
                            </div>
                        </div>
                    </div>
                </div>
            </footer>
        </body>
        </html>
    ''', posts=posts, featured_post=featured_post, categories=categories, get_random_tech_image=get_random_tech_image)

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
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Register - TechBlog</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
            <style>
                .register-section {
                    background: linear-gradient(rgba(0,0,0,0.7), rgba(0,0,0,0.7)),
                                url('https://picsum.photos/id/3/1920/1080');
                    background-size: cover;
                    background-position: center;
                    min-height: calc(100vh - 56px);
                    display: flex;
                    align-items: center;
                }
                .register-card {
                    background: rgba(255, 255, 255, 0.95);
                    border-radius: 15px;
                    box-shadow: 0 0 20px rgba(0,0,0,0.2);
                }
                .register-header {
                    background: #198754;
                    color: white;
                    padding: 20px;
                    border-radius: 15px 15px 0 0;
                    text-align: center;
                }
                .error-message {
                    background-color: rgba(255, 0, 0, 0.1);
                    border-left: 4px solid #dc3545;
                    padding: 10px;
                    margin-bottom: 15px;
                }
                .feature-item {
                    display: flex;
                    align-items: center;
                    margin-bottom: 10px;
                }
                .feature-icon {
                    width: 24px;
                    margin-right: 10px;
                    color: #198754;
                }
            </style>
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
                <div class="container">
                    <a class="navbar-brand" href="/">
                        <i class="bi bi-code-square"></i> TechBlog
                    </a>
                    <div class="navbar-nav ms-auto">
                        <a class="nav-link" href="/login">
                            <i class="bi bi-box-arrow-in-right"></i> Login
                        </a>
                        <a class="nav-link" href="/register">
                            <i class="bi bi-person-plus"></i> Register
                        </a>
                    </div>
                </div>
            </nav>
            
            <div class="register-section">
                <div class="container">
                    <div class="row justify-content-center">
                        <div class="col-md-8">
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="text-white mb-4">
                                        <h2 class="display-6">Join Our Tech Community</h2>
                                        <p class="lead">Share your knowledge and learn from others.</p>
                                        
                                        <div class="mt-4">
                                            <div class="feature-item">
                                                <i class="bi bi-pencil-square feature-icon"></i>
                                                <span>Write and share technical articles</span>
                                            </div>
                                            <div class="feature-item">
                                                <i class="bi bi-people feature-icon"></i>
                                                <span>Connect with other tech enthusiasts</span>
                                            </div>
                                            <div class="feature-item">
                                                <i class="bi bi-book feature-icon"></i>
                                                <span>Access exclusive tutorials</span>
                                            </div>
                                            <div class="feature-item">
                                                <i class="bi bi-chat-dots feature-icon"></i>
                                                <span>Engage in technical discussions</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="col-md-6">
                                    <div class="register-card">
                                        <div class="register-header">
                                            <h2 class="m-0">
                                                <i class="bi bi-person-plus"></i> Register
                                            </h2>
                                        </div>
                                        <div class="card-body p-4">
                                            {% if error %}
                                                <div class="error-message">
                                                    <i class="bi bi-exclamation-triangle"></i> {{ error }}
                                                </div>
                                            {% endif %}
                                            
                                            <form method="post">
                                                <div class="mb-3">
                                                    <label class="form-label">Username</label>
                                                    <div class="input-group">
                                                        <span class="input-group-text">
                                                            <i class="bi bi-person"></i>
                                                        </span>
                                                        <input type="text" name="username" class="form-control" required>
                                                    </div>
                                                </div>
                                                <div class="mb-4">
                                                    <label class="form-label">Password</label>
                                                    <div class="input-group">
                                                        <span class="input-group-text">
                                                            <i class="bi bi-key"></i>
                                                        </span>
                                                        <input type="password" name="password" class="form-control" required>
                                                    </div>
                                                </div>
                                                <button type="submit" class="btn btn-success w-100 mb-3">
                                                    <i class="bi bi-person-plus"></i> Create Account
                                                </button>
                                                <div class="text-center">
                                                    <small class="text-muted">
                                                        Already have an account? 
                                                        <a href="/login" class="text-decoration-none">Login here</a>
                                                    </small>
                                                </div>
                                            </form>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
    ''', error=error)

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
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login - TechBlog</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
            <style>
                .login-section {
                    background: linear-gradient(rgba(0,0,0,0.7), rgba(0,0,0,0.7)),
                                url('https://picsum.photos/id/4/1920/1080');
                    background-size: cover;
                    background-position: center;
                    min-height: calc(100vh - 56px);
                    display: flex;
                    align-items: center;
                }
                .login-card {
                    background: rgba(255, 255, 255, 0.95);
                    border-radius: 15px;
                    box-shadow: 0 0 20px rgba(0,0,0,0.2);
                }
                .login-header {
                    background: #0d6efd;
                    color: white;
                    padding: 20px;
                    border-radius: 15px 15px 0 0;
                    text-align: center;
                }
                .error-message {
                    background-color: rgba(255, 0, 0, 0.1);
                    border-left: 4px solid #dc3545;
                    padding: 10px;
                    margin-bottom: 15px;
                }
                .success-message {
                    background-color: rgba(0, 255, 0, 0.1);
                    border-left: 4px solid #198754;
                    padding: 10px;
                    margin-bottom: 15px;
                }
            </style>
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
                <div class="container">
                    <a class="navbar-brand" href="/">
                        <i class="bi bi-code-square"></i> TechBlog
                    </a>
                    <div class="navbar-nav ms-auto">
                        <a class="nav-link" href="/login">
                            <i class="bi bi-box-arrow-in-right"></i> Login
                        </a>
                        <a class="nav-link" href="/register">
                            <i class="bi bi-person-plus"></i> Register
                        </a>
                    </div>
                </div>
            </nav>
            
            <div class="login-section">
                <div class="container">
                    <div class="row justify-content-center">
                        <div class="col-md-6 col-lg-5">
                            <div class="login-card">
                                <div class="login-header">
                                    <h2 class="m-0">
                                        <i class="bi bi-box-arrow-in-right"></i> Login
                                    </h2>
                                </div>
                                <div class="card-body p-4">
                                    {% if error %}
                                        <div class="{{ 'success-message' if 'Flag' in error else 'error-message' }}">
                                            <i class="{{ 'bi bi-check-circle' if 'Flag' in error else 'bi bi-exclamation-triangle' }}"></i> 
                                            {{ error }}
                                        </div>
                                    {% endif %}
                                    
                                    <form method="post">
                                        <div class="mb-3">
                                            <label class="form-label">Username</label>
                                            <div class="input-group">
                                                <span class="input-group-text">
                                                    <i class="bi bi-person"></i>
                                                </span>
                                                <input type="text" name="username" class="form-control" required>
                                            </div>
                                        </div>
                                        <div class="mb-4">
                                            <label class="form-label">Password</label>
                                            <div class="input-group">
                                                <span class="input-group-text">
                                                    <i class="bi bi-key"></i>
                                                </span>
                                                <input type="password" name="password" class="form-control" required>
                                            </div>
                                        </div>
                                        <button type="submit" class="btn btn-primary w-100 mb-3">
                                            <i class="bi bi-box-arrow-in-right"></i> Login
                                        </button>
                                        <div class="text-center">
                                            <small class="text-muted">
                                                Don't have an account? 
                                                <a href="/register" class="text-decoration-none">Register here</a>
                                            </small>
                                        </div>
                                    </form>
                                </div>
                            </div>
                            
                            <div class="text-center mt-4 text-white">
                                <h5>Test Credentials</h5>
                                <p class="mb-0">Username: admin</p>
                                <p>Password: admin123</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <footer class="bg-dark text-white py-4">
                <div class="container">
                    <div class="row">
                        <div class="col-md-6">
                            <h5><i class="bi bi-code-square"></i> TechBlog</h5>
                            <p>Share your knowledge. Learn from others.</p>
                        </div>
                        <div class="col-md-6 text-md-end">
                            <div class="h4">
                                <a href="#" class="text-white me-3"><i class="bi bi-twitter"></i></a>
                                <a href="#" class="text-white me-3"><i class="bi bi-github"></i></a>
                                <a href="#" class="text-white"><i class="bi bi-linkedin"></i></a>
                            </div>
                        </div>
                    </div>
                </div>
            </footer>
        </body>
        </html>
    ''', error=error)

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
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard - TechBlog</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
            <style>
                .dashboard-header {
                    background: linear-gradient(rgba(0,0,0,0.7), rgba(0,0,0,0.7)),
                                url('https://picsum.photos/id/180/1920/1080');
                    background-size: cover;
                    background-position: center;
                    padding: 100px 0;
                    color: white;
                }
                .post-card {
                    border: none;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    transition: transform 0.2s;
                }
                .post-card:hover {
                    transform: translateY(-5px);
                }
                .success-message {
                    background-color: rgba(0, 255, 0, 0.1);
                    border-left: 4px solid #198754;
                    padding: 10px;
                    margin-bottom: 15px;
                }
                .error-message {
                    background-color: rgba(255, 0, 0, 0.1);
                    border-left: 4px solid #dc3545;
                    padding: 10px;
                    margin-bottom: 15px;
                }
            </style>
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
                <div class="container">
                    <a class="navbar-brand" href="/">
                        <i class="bi bi-code-square"></i> TechBlog
                    </a>
                    <div class="navbar-nav ms-auto">
                        {% if session.get('role') == 'admin' %}
                            <a class="nav-link" href="/admin">
                                <i class="bi bi-shield-lock"></i> Admin
                            </a>
                        {% endif %}
                        <a class="nav-link" href="/profile">
                            <i class="bi bi-person"></i> Profile
                        </a>
                        <a class="nav-link" href="/logout">
                            <i class="bi bi-box-arrow-right"></i> Logout
                        </a>
                    </div>
                </div>
            </nav>
            
            <header class="dashboard-header text-center">
                <h1><i class="bi bi-pencil-square"></i> Welcome, {{ session.username }}!</h1>
                <p class="lead">Share your thoughts with the community</p>
            </header>
            
            <div class="container py-5">
                <div class="row">
                    <div class="col-md-4 mb-4">
                        <div class="card">
                            <div class="card-body">
                                <h5 class="card-title mb-3">Create New Post</h5>
                                
                                {% if error %}
                                    <div class="error-message">
                                        <i class="bi bi-exclamation-triangle"></i> {{ error }}
                                    </div>
                                {% endif %}
                                
                                {% if success %}
                                    <div class="success-message">
                                        <i class="bi bi-check-circle"></i> {{ success }}
                                    </div>
                                {% endif %}
                                
                                <form method="post">
                                    <div class="mb-3">
                                        <label class="form-label">Title</label>
                                        <input type="text" name="title" class="form-control" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Content</label>
                                        <textarea name="content" class="form-control" rows="5" required></textarea>
                                        <div class="form-text text-muted">
                                            HTML tags are allowed for formatting
                                        </div>
                                    </div>
                                    <div class="mb-3 form-check">
                                        <input type="checkbox" name="private" value="1" class="form-check-input" id="private">
                                        <label class="form-check-label" for="private">Private post</label>
                                    </div>
                                    <button type="submit" class="btn btn-primary w-100">
                                        <i class="bi bi-plus-circle"></i> Create Post
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-8">
                        <h3 class="mb-4">Recent Posts</h3>
                        {% for post in posts %}
                            <div class="card post-card mb-4">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between align-items-center mb-2">
                                        <h5 class="card-title mb-0">{{ post.title }}</h5>
                                        {% if post.is_private %}
                                            <span class="badge bg-warning">
                                                <i class="bi bi-lock"></i> Private
                                            </span>
                                        {% endif %}
                                    </div>
                                    <p class="card-text">{{ post.content | safe }}</p>
                                    <div class="d-flex justify-content-between align-items-center">
                                        <small class="text-muted">
                                            By {{ post.author }}
                                            {% if post.role == 'admin' %}
                                                <span class="badge bg-danger">Admin</span>
                                            {% endif %}
                                        </small>
                                        <div>
                                            <a href="#" class="btn btn-sm btn-outline-primary me-2">
                                                <i class="bi bi-chat"></i> Comment
                                            </a>
                                            {% if session.username == post.author %}
                                                <a href="#" class="btn btn-sm btn-outline-danger">
                                                    <i class="bi bi-trash"></i> Delete
                                                </a>
                                            {% endif %}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
            
            <footer class="bg-dark text-white py-4 mt-5">
                <div class="container">
                    <div class="row">
                        <div class="col-md-6">
                            <h5><i class="bi bi-code-square"></i> TechBlog</h5>
                            <p>Share your knowledge. Learn from others.</p>
                        </div>
                        <div class="col-md-6 text-md-end">
                            <div class="h4">
                                <a href="#" class="text-white me-3"><i class="bi bi-twitter"></i></a>
                                <a href="#" class="text-white me-3"><i class="bi bi-github"></i></a>
                                <a href="#" class="text-white"><i class="bi bi-linkedin"></i></a>
                            </div>
                        </div>
                    </div>
                </div>
            </footer>
        </body>
        </html>
    ''', error=error, success=success, posts=posts)

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
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Profile - TechBlog</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
            <style>
                .profile-header {
                    background: linear-gradient(rgba(0,0,0,0.7), rgba(0,0,0,0.7)),
                                url('https://picsum.photos/id/3/1920/400');
                    background-size: cover;
                    background-position: center;
                    color: white;
                    padding: 60px 0;
                    margin-bottom: 40px;
                }
                .profile-avatar {
                    width: 120px;
                    height: 120px;
                    background: #0d6efd;
                    border-radius: 60px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin: 0 auto 20px;
                }
                .profile-avatar i {
                    font-size: 60px;
                }
                .stat-card {
                    border-radius: 15px;
                    transition: transform 0.2s;
                }
                .stat-card:hover {
                    transform: translateY(-5px);
                }
                .latest-post {
                    border-left: 4px solid #0d6efd;
                }
            </style>
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
                <div class="container">
                    <a class="navbar-brand" href="/">
                        <i class="bi bi-code-square"></i> TechBlog
                    </a>
                    <div class="navbar-nav ms-auto">
                        <a class="nav-link" href="/dashboard">
                            <i class="bi bi-speedometer2"></i> Dashboard
                        </a>
                        <a class="nav-link active" href="/profile">
                            <i class="bi bi-person"></i> Profile
                        </a>
                        <a class="nav-link" href="/logout">
                            <i class="bi bi-box-arrow-right"></i> Logout
                        </a>
                    </div>
                </div>
            </nav>
            
            <div class="profile-header text-center">
                <div class="container">
                    <div class="profile-avatar">
                        <i class="bi bi-person text-white"></i>
                    </div>
                    <h1>{{ user[0] }}</h1>
                    <span class="badge bg-{{ 'primary' if user[1] == 'admin' else 'secondary' }} mb-3">
                        {{ user[1].title() }}
                    </span>
                    <p class="lead mb-0">Tech enthusiast and knowledge sharer</p>
                </div>
            </div>
            
            <div class="container">
                <div class="row">
                    <div class="col-md-4">
                        <div class="card stat-card mb-4">
                            <div class="card-body text-center">
                                <div class="display-4 text-primary mb-2">
                                    <i class="bi bi-pencil-square"></i>
                                </div>
                                <h3>{{ total_posts }}</h3>
                                <p class="text-muted mb-0">Articles Published</p>
                            </div>
                        </div>
                        
                        <div class="card mb-4">
                            <div class="card-body">
                                <h5 class="card-title">Account Information</h5>
                                <ul class="list-group list-group-flush">
                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                        Username
                                        <span class="text-muted">{{ user[0] }}</span>
                                    </li>
                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                        Role
                                        <span class="badge bg-{{ 'primary' if user[1] == 'admin' else 'secondary' }}">
                                            {{ user[1].title() }}
                                        </span>
                                    </li>
                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                        Member Since
                                        <span class="text-muted">April 2025</span>
                                    </li>
                                </ul>
                            </div>
                        </div>
                        
                        {% if user[1] == 'admin' %}
                        <div class="card mb-4">
                            <div class="card-body">
                                <h5 class="card-title">Admin Tools</h5>
                                <p>Access the admin panel to manage users and content.</p>
                                <a href="/admin" class="btn btn-primary w-100">
                                    <i class="bi bi-shield-lock"></i> Admin Panel
                                </a>
                            </div>
                        </div>
                        {% endif %}
                    </div>
                    
                    <div class="col-md-8">
                        <h3 class="mb-4">Latest Articles</h3>
                        {% if latest_posts %}
                            {% for post in latest_posts %}
                            <div class="card latest-post mb-4">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between align-items-center mb-3">
                                        <h4 class="card-title mb-0">{{ post[1] }}</h4>
                                        {% if post[4] %}
                                        <span class="badge bg-secondary">Private</span>
                                        {% endif %}
                                    </div>
                                    <div class="card-text">{{ post[2] | safe }}</div>
                                </div>
                            </div>
                            {% endfor %}
                        {% else %}
                            <div class="card">
                                <div class="card-body text-center py-5">
                                    <i class="bi bi-journal-text display-4 text-muted mb-3"></i>
                                    <h4>No Articles Yet</h4>
                                    <p class="text-muted">Start sharing your knowledge with the community.</p>
                                    <a href="/dashboard" class="btn btn-primary">
                                        <i class="bi bi-plus-circle"></i> Create Your First Article
                                    </a>
                                </div>
                            </div>
                        {% endif %}
                    </div>
                </div>
            </div>
            
            <footer class="bg-dark text-white mt-5 py-4">
                <div class="container">
                    <div class="row">
                        <div class="col-md-6">
                            <h5><i class="bi bi-code-square"></i> TechBlog</h5>
                            <p>Share your knowledge. Learn from others.</p>
                        </div>
                        <div class="col-md-6 text-md-end">
                            <div class="h4">
                                <a href="#" class="text-white me-3"><i class="bi bi-twitter"></i></a>
                                <a href="#" class="text-white me-3"><i class="bi bi-github"></i></a>
                                <a href="#" class="text-white"><i class="bi bi-linkedin"></i></a>
                            </div>
                        </div>
                    </div>
                </div>
            </footer>
        </body>
        </html>
    ''', user=user, total_posts=total_posts, latest_posts=latest_posts)

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
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Panel - TechBlog</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
            <style>
                .admin-header {
                    background: linear-gradient(rgba(0,0,0,0.8), rgba(0,0,0,0.8)),
                                url('https://picsum.photos/id/201/1920/1080');
                    background-size: cover;
                    background-position: center;
                    padding: 100px 0;
                    color: white;
                }
                .stats-card {
                    border: none;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    transition: transform 0.2s;
                }
                .stats-card:hover {
                    transform: translateY(-5px);
                }
                .user-table, .post-table {
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                }
            </style>
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
                <div class="container">
                    <a class="navbar-brand" href="/">
                        <i class="bi bi-code-square"></i> TechBlog
                    </a>
                    <div class="navbar-nav ms-auto">
                        <a class="nav-link active" href="/admin">
                            <i class="bi bi-shield-lock"></i> Admin
                        </a>
                        <a class="nav-link" href="/dashboard">
                            <i class="bi bi-house"></i> Dashboard
                        </a>
                        <a class="nav-link" href="/profile">
                            <i class="bi bi-person"></i> Profile
                        </a>
                        <a class="nav-link" href="/logout">
                            <i class="bi bi-box-arrow-right"></i> Logout
                        </a>
                    </div>
                </div>
            </nav>
            
            <header class="admin-header text-center">
                <h1><i class="bi bi-shield-lock"></i> Admin Panel</h1>
                <p class="lead">Manage users and content</p>
            </header>
            
            <div class="container py-5">
                <div class="row mb-5">
                    <div class="col-md-4">
                        <div class="card stats-card text-center mb-4">
                            <div class="card-body">
                                <h1 class="display-4">{{ users|length }}</h1>
                                <p class="text-muted mb-0">Total Users</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card stats-card text-center mb-4">
                            <div class="card-body">
                                <h1 class="display-4">{{ posts|length }}</h1>
                                <p class="text-muted mb-0">Total Posts</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card stats-card text-center mb-4">
                            <div class="card-body">
                                <h1 class="display-4">{{ users|selectattr('role', 'equalto', 'admin')|list|length }}</h1>
                                <p class="text-muted mb-0">Admin Users</p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-md-6">
                        <div class="card user-table mb-4">
                            <div class="card-header bg-dark text-white">
                                <h5 class="card-title mb-0">
                                    <i class="bi bi-people"></i> Users
                                </h5>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-hover">
                                        <thead>
                                            <tr>
                                                <th>Username</th>
                                                <th>Role</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {% for user in users %}
                                                <tr>
                                                    <td>{{ user.username }}</td>
                                                    <td>
                                                        <span class="badge bg-{{ 'danger' if user.role == 'admin' else 'secondary' }}">
                                                            {{ user.role }}
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <button class="btn btn-sm btn-outline-primary">
                                                            <i class="bi bi-pencil"></i>
                                                        </button>
                                                        <button class="btn btn-sm btn-outline-danger">
                                                            <i class="bi bi-trash"></i>
                                                        </button>
                                                    </td>
                                                </tr>
                                            {% endfor %}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="card post-table">
                            <div class="card-header bg-dark text-white">
                                <h5 class="card-title mb-0">
                                    <i class="bi bi-file-text"></i> Recent Posts
                                </h5>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-hover">
                                        <thead>
                                            <tr>
                                                <th>Title</th>
                                                <th>Author</th>
                                                <th>Status</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {% for post in posts %}
                                                <tr>
                                                    <td>{{ post.title }}</td>
                                                    <td>
                                                        {{ post.author }}
                                                        {% if post.role == 'admin' %}
                                                            <span class="badge bg-danger">Admin</span>
                                                        {% endif %}
                                                    </td>
                                                    <td>
                                                        <span class="badge bg-{{ 'warning' if post.is_private else 'success' }}">
                                                            {{ 'Private' if post.is_private else 'Public' }}
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <button class="btn btn-sm btn-outline-primary">
                                                            <i class="bi bi-eye"></i>
                                                        </button>
                                                        <button class="btn btn-sm btn-outline-danger">
                                                            <i class="bi bi-trash"></i>
                                                        </button>
                                                    </td>
                                                </tr>
                                            {% endfor %}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <footer class="bg-dark text-white py-4 mt-5">
                <div class="container">
                    <div class="row">
                        <div class="col-md-6">
                            <h5><i class="bi bi-code-square"></i> TechBlog</h5>
                            <p>Share your knowledge. Learn from others.</p>
                        </div>
                        <div class="col-md-6 text-md-end">
                            <div class="h4">
                                <a href="#" class="text-white me-3"><i class="bi bi-twitter"></i></a>
                                <a href="#" class="text-white me-3"><i class="bi bi-github"></i></a>
                                <a href="#" class="text-white"><i class="bi bi-linkedin"></i></a>
                            </div>
                        </div>
                    </div>
                </div>
            </footer>
        </body>
        </html>
    ''', users=users, posts=posts)

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
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>About - TechBlog</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
            <style>
                .about-header {
                    background: linear-gradient(rgba(0,0,0,0.7), rgba(0,0,0,0.7)),
                                url('https://picsum.photos/id/2/1920/400');
                    background-size: cover;
                    background-position: center;
                    padding: 80px 0;
                    margin-bottom: 60px;
                }
                .feature-card {
                    border: none;
                    border-radius: 15px;
                    transition: transform 0.3s;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                }
                .feature-card:hover {
                    transform: translateY(-10px);
                }
                .feature-icon {
                    width: 60px;
                    height: 60px;
                    background: #0d6efd;
                    color: white;
                    border-radius: 30px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin: 0 auto 20px;
                }
                .feature-icon i {
                    font-size: 24px;
                }
                .team-member {
                    text-align: center;
                    margin-bottom: 30px;
                }
                .team-avatar {
                    width: 120px;
                    height: 120px;
                    border-radius: 60px;
                    margin: 0 auto 15px;
                    overflow: hidden;
                }
                .team-avatar img {
                    width: 100%;
                    height: 100%;
                    object-fit: cover;
                }
                .social-links a {
                    color: #6c757d;
                    margin: 0 10px;
                    transition: color 0.3s;
                    text-decoration: none;
                }
                .social-links a:hover {
                    color: #0d6efd;
                }
            </style>
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
                <div class="container">
                    <a class="navbar-brand" href="/">
                        <i class="bi bi-code-square"></i> TechBlog
                    </a>
                    <div class="navbar-nav ms-auto">
                        <a class="nav-link" href="/dashboard">
                            <i class="bi bi-speedometer2"></i> Dashboard
                        </a>
                        <a class="nav-link" href="/profile">
                            <i class="bi bi-person"></i> Profile
                        </a>
                        <a class="nav-link" href="/logout">
                            <i class="bi bi-box-arrow-right"></i> Logout
                        </a>
                    </div>
                </div>
            </nav>
            
            <div class="about-header text-center">
                <div class="container">
                    <h1 class="display-4">About TechBlog</h1>
                    <p class="lead mb-0">A community of tech enthusiasts sharing knowledge and experiences</p>
                </div>
            </div>
            
            <div class="container mb-5">
                <div class="row mb-5">
                    <div class="col-md-4">
                        <div class="card feature-card text-center p-4">
                            <div class="feature-icon">
                                <i class="bi bi-people"></i>
                            </div>
                            <h4>Community Driven</h4>
                            <p class="text-muted">Join a vibrant community of developers, sharing insights and experiences.</p>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card feature-card text-center p-4">
                            <div class="feature-icon">
                                <i class="bi bi-book"></i>
                            </div>
                            <h4>Rich Content</h4>
                            <p class="text-muted">Access high-quality technical articles, tutorials, and case studies.</p>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card feature-card text-center p-4">
                            <div class="feature-icon">
                                <i class="bi bi-shield-check"></i>
                            </div>
                            <h4>Secure Platform</h4>
                            <p class="text-muted">Your data and content are protected with industry-standard security.</p>
                        </div>
                    </div>
                </div>
                
                <h2 class="text-center mb-4">Meet Our Team</h2>
                <div class="row">
                    <div class="col-md-4">
                        <div class="team-member">
                            <div class="team-avatar">
                                <img src="https://picsum.photos/id/1005/200" alt="Team Member">
                            </div>
                            <h5>Sarah Johnson</h5>
                            <p class="text-muted">Lead Developer</p>
                            <div class="social-links">
                                <a href="#"><i class="bi bi-twitter"></i></a>
                                <a href="#"><i class="bi bi-linkedin"></i></a>
                                <a href="#"><i class="bi bi-github"></i></a>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="team-member">
                            <div class="team-avatar">
                                <img src="https://picsum.photos/id/1012/200" alt="Team Member">
                            </div>
                            <h5>Michael Chen</h5>
                            <p class="text-muted">Security Expert</p>
                            <div class="social-links">
                                <a href="#"><i class="bi bi-twitter"></i></a>
                                <a href="#"><i class="bi bi-linkedin"></i></a>
                                <a href="#"><i class="bi bi-github"></i></a>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="team-member">
                            <div class="team-avatar">
                                <img src="https://picsum.photos/id/1027/200" alt="Team Member">
                            </div>
                            <h5>Emma Davis</h5>
                            <p class="text-muted">Content Manager</p>
                            <div class="social-links">
                                <a href="#"><i class="bi bi-twitter"></i></a>
                                <a href="#"><i class="bi bi-linkedin"></i></a>
                                <a href="#"><i class="bi bi-github"></i></a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <footer class="bg-dark text-white py-4">
                <div class="container">
                    <div class="row">
                        <div class="col-md-6">
                            <h5><i class="bi bi-code-square"></i> TechBlog</h5>
                            <p>Share your knowledge. Learn from others.</p>
                        </div>
                        <div class="col-md-6 text-md-end">
                            <div class="h4">
                                <a href="#" class="text-white me-3"><i class="bi bi-twitter"></i></a>
                                <a href="#" class="text-white me-3"><i class="bi bi-github"></i></a>
                                <a href="#" class="text-white"><i class="bi bi-linkedin"></i></a>
                            </div>
                        </div>
                    </div>
                </div>
            </footer>
        </body>
        </html>
    ''')

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5001)