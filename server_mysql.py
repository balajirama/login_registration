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

EDITPROFILE = [
    {
        'name': 'id',
        'label': "",
        'type': 'hidden'
    },
    {
        'name': 'firstname',
        'label': 'First name',
        'type': 'text'
    },
    {
        'name': 'lastname',
        'label': 'Last name',
        'type': 'text'
    },
    {
        'name': 'email',
        'label': 'Email',
        'type': 'email',
        'small-text': 'Your login will change if you change this.'
    },
]

EDITPASSWORD = [
    {
        'name': 'currentpassword',
        'label': 'Current password',
    },
    {
        'name': 'newpassword',
        'label': 'New password',
    },
    {
        'name': 'confirm',
        'label': 'Confirm password'
    }
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
    if (request.form['confirm'] == "") or (request.form['password'] != request.form['confirm']):
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
        return render_template("editprofile.html", user = users[0], EDITPROFILE=EDITPROFILE)
    else:
        flash("Aw snap! Something went wrong. Try again in a few hours", "error")
        return redirect("/success")

@app.route("/updateprofile", methods=['POST'])
def updateprofile():
    mysql = connectToMySQL(dbname)
    is_valid = True
    if len(request.form['firstname']) < 2:
        flash("First name must have at least two characters", "firstname")
        is_valid = False
    if len(request.form['lastname']) < 2:
        is_valid = False
        flash("Last name must have at least two characters", "lastname")
    if not EMAIL_REGEXP.match(request.form['email']):
        is_valid = False
        flash("Email not in correct format", 'email')
    if is_valid:
        status = mysql.query_db("UPDATE users SET firstname = %(firstname)s, lastname = %(lastname)s, email = %(email)s WHERE id = %(id)s;", request.form)
        if status:
            flash("Updated your profile", "success")
        else:
            flash("Something went wrong. It's us, not you. Try again later.", "error")
        return redirect("/success")
    else:
        return redirect("/editprofile")

@app.route("/changepasswd")
def changepasswd():
    return render_template("change_password.html", EDITPASSWORD=EDITPASSWORD)

@app.route("/updatepassword", methods=['POST'])
def updatepassword():
    mysql = connectToMySQL(dbname)
    rows = mysql.query_db("SELECT id, pswdhash FROM users WHERE id = %(id)s", {'id': session['id']})
    is_valid = True
    if len(rows) == 0:
        is_valid = False
        flash("Passwords cannot be updated now. Please try again later", "error")
        return redirect("/success")
    if not bcrypt.check_password_hash(rows[0]['pswdhash'], request.form['currentpassword']):
        is_valid = False
        flash('Current password does not match', 'currentpassword')
    if len(request.form['newpassword']) < 2:
        is_valid = False
        flash("Password must be at least two characters long", "newpassword")
    if (request.form == "") or (request.form['newpassword'] != request.form['confirm']):
        is_valid = False
        flash("Password confirmation must match", "confirm")
    if not is_valid:
        return redirect("/changepasswd")
    else:
        status = mysql.query_db("UPDATE users SET pswdhash = %(pswdhash)s WHERE id = %(id)s", rows[0])
        if status:
            flash('Password changed', 'success')
        else:
            flash("Something went wrong in saving your new password. Password did not change.", "error")
        return redirect("/success")

@app.route("/deleteprofile")
def deleteprofile():
    mysql = connectToMySQL(dbname)
    mysql.query_db("DELETE FROM users WHERE id = %(id)s", {'id': session['id']})
    return redirect("/logout")

if __name__ == "__main__":
    app.run(debug=True)