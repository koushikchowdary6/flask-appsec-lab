from flask import Flask, request, session, redirect
from markupsafe import escape
import sqlite3
app = Flask(__name__)
app.secret_key = "12345"

def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, username TEXT, password TEXT)")
    c.execute("INSERT INTO users VALUES (1, 'admin', 'admin123')")
    conn.commit()
    conn.close()

init_db()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("users.db")
        c = conn.cursor()

        query = "SELECT * FROM users WHERE username=? AND password=?"
        result = c.execute(query, (username, password)).fetchone()

        if result:
            session["user"] = username
            return "Logged in!"
        else:
            return "Invalid credentials"

    return '''
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password"><br>
            <input type="submit">
        </form>
    '''

@app.route("/search")
def search():
    query = request.args.get("q", "")
    return f"Results for: {escape(query)}"

@app.route("/admin")
def admin():
    if session.get("user") != "admin":
        return redirect("/login")
    return "Welcome admin! Secret data here."

app.run(debug=True)