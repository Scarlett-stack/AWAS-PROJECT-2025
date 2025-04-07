from flask import Flask, request, make_response
import sqlite3, os

app = Flask(__name__)

sneaky_flag = "CTF{gu3ss_ur_n0t_a_r00k1e_aft3r_a11}"
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

    # Vulnerable SQL query — intentionally injectable
    query = f"SELECT id, username FROM users WHERE username='{user}' AND password='{passwd}'"
    c.execute(query)
    result = c.fetchone()
    conn.close()

    if result:
        db_id, db_user = result
        uid = 1015 if db_user == 'admin' else 1000 + db_id
        resp = make_response(f"Logged in as {db_user}")
        resp.set_cookie('user_id', str(uid))
        return resp

    return "Invalid credentials"


@app.route('/admin')
def admin():
    uid = request.cookies.get('user_id')
    if uid == '1015':
        return "Welcome admin! CTF{you_got_admin_access}"
    return "Access denied."

@app.route('/show_users')
def show_users():
    uid = request.cookies.get('user_id')
    if uid != '1015':
        return "Access denied."

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id, username, password FROM users")
    users = c.fetchall()
    conn.close()

    output = "<h2>All Registered Users (Admin View):</h2><ul>"
    for uid, uname, pwd in users:
        output += f"<li>ID: {uid} - Username: {uname} - Password: {pwd}</li>"
    output += "</ul>"

    return output
@app.route('/read_file')
def read_file():
    filename = request.args.get('name')

    try:
        safe_path = os.path.join("files", filename)
        with open(safe_path, "r") as f:
            content = f.read()
        return f"<h3>Contents of {filename}:</h3><pre>{content}</pre>"
    except Exception as e:
        return f"<b>Error:</b> {e}"


if __name__ == "__main__":
    init_db()
    app.run(debug=True)