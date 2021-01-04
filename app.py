from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required
import json

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure Library to use SQLite database
db = SQL("sqlite:///pmanager.db")


@app.route("/")
def welcome():
    """Welcome page"""
    if 'user_id' in session:
        return redirect("/main")
    else:
        return render_template("welcome.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash('Incorrect username or password')
            return render_template("login.html")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/main")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete():
    """Delete data from database"""
    data = request.get_json(force="True")

    db.execute("DELETE FROM data WHERE id = :id", id=data)

    return "ok", 200


@app.route("/edit", methods=["GET", "POST"])
@login_required
def edit():
    """Handle edits to db on frontend"""

    data = request.get_json(force="true")

    id_entry = data['id']
    name = data['name']
    link = data['link']
    username = data['username']
    password = data['hash']

    db.execute("UPDATE data SET name =:name, link =:link, username=:username, hash=:hash WHERE id=:id",
               name=name, link=link, username=username, hash=password, id=id_entry)

    return "ok", 200


@app.route("/main", methods=["GET", "POST"])
@login_required
def main():

    user_id = session["user_id"]

    if request.method == "GET":
        data = db.execute(
            "SELECT * FROM data WHERE user_id=:user_id ORDER BY name", user_id=user_id)
        data_json = data
        password = session["user_pass"]

        return render_template("index.html", dataFromFlask=data_json, dataR=password)

    else:
        # new data entry
        name = request.form['name']
        link = request.form['link']
        username = request.form['username']
        password = request.form['password']

        data = db.execute(
            "SELECT * FROM data WHERE user_id=:user_id", user_id=user_id)

        for entry in data:
            if name == entry['name'] or link == entry['link']
            return "duplicate entry", 409

    db.execute("INSERT INTO data (user_id, name, link, username, hash) VALUES (:user_id, :name, :link, :username, :hash",
               user_id=user_id, name=name, link=link, username=username, hash=password)

    return "success", 202


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Check if a user with that username already exists
        if len(rows) != 0:
            return apology("username already exists.", 403)

        # Ensure password was submitted and matches the confirmation
        if not request.form.get("password"):
            return apology("must provide password", 403)

        if request.form.get("password") != request.form.get("confirmation"):
            return apology("confirmation must match password", 403)

        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=request.form.get(
            "username"), hash=generate_password_hash(request.form.get("password")))
        return redirect("login")
    else:
        return render_template("register.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to welcome page
    return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
