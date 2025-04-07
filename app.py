from flask import Flask, request, make_response, send_from_directory
import os

app = Flask(__name__)

users = {
    'admin': 'admin123',
    'user': 'userpass'
}

@app.route('/')
def index():
    return '''<form method="post" action="/login">
                User: <input name="user"><br>
                Pass: <input name="pass"><br>
                <input type="submit">
              </form>'''

@app.route('/login', methods=['POST'])
def login():
    user = request.form.get('user')
    passwd = request.form.get('pass')
    if user in users and users[user] == passwd:
        resp = make_response(f"Logged in as {user}")
        resp.set_cookie('user_id', '1015' if user == 'admin' else '1001')
        return resp
    return "Invalid creds"

@app.route('/admin')
def admin():
    uid = request.cookies.get('user_id')
    if uid == '1015':
        return "Welcome admin! FLAG{you_got_admin_access}"
    return "Access denied."

@app.route('/read')
def read():
    file = request.args.get('file')
    try:
        with open(os.path.join("files", file), 'r') as f:
            return f"<pre>{f.read()}</pre>"
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/sqlmock', methods=['POST'])
def sqlmock():
    username = request.form.get('user')
    password = request.form.get('pass')
    if "admin" in username and "--" in username:
        return "SQLi Success! FLAG{sqli_bypass_works}"
    return "Invalid credentials."

@app.route('/files/secret.txt', methods=['GET'])
def display():  #admin like access control
    try:
        with open("files/secret.txt", "r") as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        return f"Error: {str(e)}"


if __name__ == "__main__":
    os.makedirs("files", exist_ok=True)
    app.run(debug=True)