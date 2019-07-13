from flask import Flask, render_template, request, redirect, session, flash, get_flashed_messages
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import os
import re
from datetime import datetime

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.secret_key = 'darksecret'

dbname = 'login_users'
EMAIL_REGEXP = re.compile(r"^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9]+\.[a-zA-Z]+$")

REGISTRATION = [
    {
        'label': 'First name',
        'name': 'firstname',
        'type': 'text',
        'placeholder': 'Jane'
    },
    {
        'label': 'Last name',
        'name': 'lastname',
        'type': 'text',
        'placeholder': 'Doe'
    },
    {
        'label': 'Email',
        'name': 'email',
        'type': 'text',
        'placeholder': 'me@example.com',
        'small-text': "We'll never share your email with anyone else."
    },
    {
        'label': 'Password',
        'name': 'password',
        'type': 'password',
        'placeholder': 'Password'
    },
    {
        'label': 'Confirm password',
        'name': 'confirm',
        'type': 'password',
        'placeholder': 'Password'
    },
]

@app.route("/")
def mainpage():
    print(get_flashed_messages())
    if 'reg' not in session:
        session['reg'] = {
            'firstname': "",
            'lastname': "",
            'email': ""
        }
    return render_template("index.html", REGISTRATION=REGISTRATION)

@app.route("/login", methods=["POST"])
def login():
    mysql = connectToMySQL(dbname)
    users = mysql.query_db("SELECT * FROM users WHERE email = %(loginemail)s;", request.form)
    if len(users) > 0:
        if bcrypt.check_password_hash(users[0]['pswdhash'], request.form['loginpassword']):
            session['id'] = users[0]['id']
            session['logged_in'] = True
            session['firstname'] = users[0]['firstname']
            flash("You've been logged in", "success")
            return redirect("/success")
    flash("You could not be logged in", "error")
    return redirect("/")

@app.route("/register", methods=["POST"])
def register():
    errors = False
    if not EMAIL_REGEXP.match(request.form['email']):
        flash("Not a valid email", "email")
        errors = True
    if len(request.form['password']) < 8:
        flash("Your password must be at least eight characters", "password")
        errors = True
    if len(request.form['firstname']) < 2:
        flash("First name must have at least two characters", "firstname")
        errors = True
    if len(request.form['lastname']) < 2:
        flash("Last name must have at least two characters", "lastname")
        errors = True
    if request.form['password'] != request.form['confirm']:
        flash("Passwords do not match", "confirm")
        errors = True
    if not errors:
        mysql = connectToMySQL(dbname)
        if len(mysql.query_db("SELECT * FROM users WHERE email = %(email)s", request.form)) == 0:
            data = dict()
            for name in request.form.keys():
                data[name] = request.form[name]
            data['pswdhash'] = bcrypt.generate_password_hash(request.form['password'])
            status = mysql.query_db("INSERT INTO users ( firstname, lastname, email, pswdhash, created_at ) VALUES ( %(firstname)s, %(lastname)s, %(email)s, %(pswdhash)s, NOW() ) ;", data)
            if status:
                flash("Successfully registered "+request.form['email']+". Try logging in!", "success")
                if 'reg' in session:
                    del session['reg']
            else:
                flash("Something went wrong. It is us, not you! Try in a few hours", "error")
        else:
            flash(request.form['email']+" is already a user. Please login instead.", "error")
    else:
        session['reg'] = {
            'firstname': request.form['firstname'],
            'lastname': request.form['lastname'],
            'email': request.form['email']
        }
    return redirect("/")

@app.route("/success")
def success():
    return render_template("success.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/viewprofile")
def viewprofile():
    mysql = connectToMySQL(dbname)
    users = mysql.query_db("SELECT id, firstname, lastname, email, created_at FROM users WHERE id = %(id)s", {'id': session['id']})
    if len(users) > 0:
        return render_template("profile.html", user = users[0])
    else:
        flash("Aw snap! Something went wrong. Try again in a few hours", "error")
        return redirect("/success")

@app.route("/editprofile")
def editprofile():
    mysql = connectToMySQL(dbname)
    users = mysql.query_db("SELECT id, firstname, lastname, email, created_at FROM users WHERE id = %(id)s", {'id': session['id']})
    if len(users) > 0:
        return render_template("editprofile.html", user = users[0])
    else:
        flash("Aw snap! Something went wrong. Try again in a few hours", "error")
        return redirect("/success")

@app.route("/updateprofile")
def updateprofile():
    mysql = connectToMySQL(dbname)
    errors = False
    if len(request.form['firstname']) < 2:
        flash("First name must have at least two characters", "error")
        errors = True
    if not errors:
        mysql.query_db("UPDATE users SET firstname = %(firstname)s, lastname = %(lastname)s, email = %(email)s WHERE id = %(id)s;", request.form)
        flash("Updated your profile", "success")
        return redirect("/success")
    else:
        return redirect("editprofile")

if __name__ == "__main__":
    app.run(debug=True)