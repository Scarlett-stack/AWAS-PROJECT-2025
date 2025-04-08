from flask import Flask, render_template, request, session, redirect, url_for, jsonify, send_from_directory
import sqlite3
import hashlib
import json
import jwt
from datetime import datetime, timedelta


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
    db = get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    ''')
    
    db.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author TEXT NOT NULL,
            is_private BOOLEAN NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author) REFERENCES users (username)
        )
    ''')

    # Check if admin user exists
    admin = query_db('SELECT * FROM users WHERE username = ?', ['admin'], one=True)
    if not admin:
        # Create admin user with MD5 hashed password (intentionally vulnerable)
        admin_pass = hashlib.md5('admin123'.encode()).hexdigest()
        db.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                  ['admin', admin_pass, 'admin'])
    
    db.commit()

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
    
    # Get user information
    c.execute('SELECT * FROM users WHERE username = ?', (session['username'],))
    user = c.fetchone()
    
    conn.close()
    
    return render_template('dashboard.html', error=error, success=success, posts=posts, user=user)

@app.route('/create_post', methods=['POST'])
def create_post():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    title = request.form.get('title')
    content = request.form.get('content')
    
    if not title or not content:
        return redirect(url_for('dashboard', error='Title and content are required'))
    
    try:
        db = get_db()
        cursor = db.cursor()
        # Intentionally vulnerable to SQL injection
        query = f"INSERT INTO posts (title, content, author) VALUES ('{title}', '{content}', '{session['username']}')"
        print("Executing query:", query)  # Log the query for debugging
        cursor.execute(query)
        db.commit()
        return redirect(url_for('dashboard', success='Post created successfully'))
    except Exception as e:
        print("Error creating post:", str(e))
        return redirect(url_for('dashboard', error='Error creating post'))

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Intentionally vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE username = '{session['username']}'"
    user = query_db(query, one=True)

    # Get user's posts ordered by id instead of created_at for now
    if session.get('role') == 'admin':
        posts = query_db('SELECT * FROM posts ORDER BY id DESC')
    else:
        posts = query_db('SELECT * FROM posts WHERE author = ? ORDER BY id DESC',
                        [session['username']])

    total_posts = len(posts) if posts else 0

    return render_template('profile.html', 
                         user=[user['username'], user['role']],
                         posts=posts,
                         total_posts=total_posts,
                         error=request.args.get('error'),
                         success=request.args.get('success'))

@app.route('/update-profile', methods=['POST'])
def update_profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not current_password or not new_password or not confirm_password:
        return redirect(url_for('profile', error='All fields are required'))

    if new_password != confirm_password:
        return redirect(url_for('profile', error='New passwords do not match'))

    # Intentionally vulnerable: using MD5 for password hashing
    current_password_hash = hashlib.md5(current_password.encode()).hexdigest()
    
    # SQL Injection vulnerability in the query
    query = f"SELECT * FROM users WHERE username = '{session['username']}' AND password = '{current_password_hash}'"
    user = query_db(query, one=True)

    if not user:
        return redirect(url_for('profile', error='Current password is incorrect'))

    # Update password with MD5 hash (intentionally vulnerable)
    new_password_hash = hashlib.md5(new_password.encode()).hexdigest()
    db = get_db()
    db.execute("UPDATE users SET password = ? WHERE username = ?", 
               [new_password_hash, session['username']])
    db.commit()

    return redirect(url_for('profile', success='Password updated successfully'))

@app.route('/api/posts/<int:post_id>', methods=['PUT'])
def update_post(post_id):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    title = data.get('title')
    content = data.get('content')
    is_private = data.get('is_private', False)

    if not title or not content:
        return jsonify({'error': 'Title and content are required'}), 400

    db = get_db()
    post = query_db('SELECT * FROM posts WHERE id = ?', [post_id], one=True)

    if not post:
        return jsonify({'error': 'Post not found'}), 404

    # Check if user is admin or post owner
    if session.get('role') != 'admin' and post['author'] != session['username']:
        return jsonify({'error': 'Unauthorized'}), 401

    # Update the post
    db.execute(
        'UPDATE posts SET title = ?, content = ?, is_private = ? WHERE id = ?',
        [title, content, is_private, post_id]
    )
    db.commit()

    return jsonify({'success': True, 'message': 'Post updated successfully'})

@app.route('/api/posts/<int:post_id>', methods=['DELETE'])
def delete_post(post_id):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    db = get_db()
    post = query_db('SELECT * FROM posts WHERE id = ?', [post_id], one=True)

    if not post:
        return jsonify({'error': 'Post not found'}), 404

    # Check if user is admin or post owner
    if session.get('role') != 'admin' and post['author'] != session['username']:
        return jsonify({'error': 'Unauthorized'}), 401

    # Delete the post
    db.execute('DELETE FROM posts WHERE id = ?', [post_id])
    db.commit()

    return jsonify({'success': True, 'message': 'Post deleted successfully'})

@app.route('/api/posts', methods=['GET'])
def get_posts():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    # If admin, show all posts
    if session.get('role') == 'admin':
        posts = query_db('SELECT * FROM posts ORDER BY id DESC')
    else:
        # Show public posts and user's own private posts
        posts = query_db('''
            SELECT * FROM posts 
            WHERE is_private = 0 
            OR (is_private = 1 AND author = ?) 
            ORDER BY id DESC
        ''', [session['username']])

    return jsonify({'posts': posts})

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

def query_db(query, args=(), one=False):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    conn.close()
    return (rv[0] if rv else None) if one else rv

JWT_SECRET = 'your-secret-key'  # Intentionally simple secret

def generate_token(username, role):
    payload = {
        'username': username,
        'role': role,
        'exp': datetime.utcnow() + timedelta(days=1)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_token(token):
    try:
        # Intentionally vulnerable: accepts 'none' algorithm
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256', 'none'])
        return payload
    except jwt.InvalidTokenError:
        return None

@app.route('/api/token', methods=['POST'])
def get_token():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    token = generate_token(session['username'], session.get('role', 'user'))
    return jsonify({'token': token})

@app.route('/api/admin/verify', methods=['GET'])
def verify_admin():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'error': 'No token provided'}), 401

    token = token.split(' ')[1]
    payload = verify_token(token)
    
    if not payload:
        return jsonify({'error': 'Invalid token'}), 401

    # Check if user is admin (vulnerable to JWT none algorithm)
    if payload.get('role') == 'admin':
        return jsonify({
            'success': True,
            'message': 'Admin access granted',
            'flag': 'FLAG{JWT_N0n3_Alg_Byp4ss_2025}'
        })
    
    return jsonify({'error': 'Admin access required'}), 403

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host='127.0.0.1', port=5000)