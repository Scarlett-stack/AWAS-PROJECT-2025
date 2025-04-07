from flask import Flask, request, make_response
import sqlite3, os

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return '''<form method="post" action="/login">
                Username: <input name="user"><br>
                Password: <input name="pass"><br>
                <input type="submit" value="Login">
              </form>
              <p>Don't have an account? <a href="/register">Register here</a></p>'''

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = request.form['user']
        passwd = request.form['pass']

        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user, passwd))
            conn.commit()
            conn.close()
            return f"User {user} registered! <a href='/'>Login</a>"
        except sqlite3.IntegrityError:
            return "Username already taken!"

    return '''<form method="post">
                New Username: <input name="user"><br>
                New Password: <input name="pass"><br>
                <input type="submit" value="Register">
              </form>'''

@app.route('/login', methods=['POST'])
def login():
    user = request.form['user']
    passwd = request.form['pass']

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username=? AND password=?", (user, passwd))
    result = c.fetchone()
    conn.close()

    if result:
        uid = 1015 if user == 'admin' else 1000 + result[0]
        resp = make_response(f"Logged in as {user}")
        resp.set_cookie('user_id', str(uid))
        return resp
    return "Invalid credentials"

@app.route('/admin')
def admin():
    uid = request.cookies.get('user_id')
    if uid == '1015':
        return "Welcome admin! FLAG{you_got_admin_access}"
    return "Access denied."

@app.route('/show_users')
def show_users():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id, username FROM users")
    users = c.fetchall()
    conn.close()

    output = "<h2>Registered Users:</h2><ul>"
    for uid, uname in users:
        output += f"<li>ID: {uid} - Username: {uname}</li>"
    output += "</ul>"

    return output

if __name__ == "__main__":
    init_db()
    app.run(debug=True)