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
NUM_REGEX = re.compile(r"^.*[0-9]+.*")
CAP_REGEX = re.compile(r"^.*[A-Z]+.*")

not_logged_in = "You're not logged in"

sql = {'db': connectToMySQL(dbname)}
EDITPASSWORD = sql['db'].query_db("SELECT * FROM editpassword_form ORDER BY itemid;")
REGISTRATION = sql['db'].query_db("SELECT * FROM registration_form ORDER BY itemid;")
EDITPROFILE  = sql['db'].query_db("SELECT * FROM editprofile_form ORDER BY itemid;")
LANGUAGES    = sql['db'].query_db("SELECT * FROM languages ORDER BY itemid;")
del sql['db']

@app.route("/")
def mainpage():
    if 'id' in session:
        return redirect("/success")
    print(get_flashed_messages())
    if 'reg' not in session:
        session['reg'] = {
            'firstname': "",
            'lastname': "",
            'email': ""
        }
    return render_template("index.html", REGISTRATION=REGISTRATION, LANGUAGES=LANGUAGES)

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

def is_age_over(num, dob):
    dob = datetime.strptime(dob, '%Y-%m-%d')
    year = dob.year + num
    nth_bday = datetime.strptime(f"{year}-{dob.month}-{dob.day}", "%Y-%m-%d")
    today = datetime.today()
    return (today - nth_bday).days >= 0

def get_age(dob):
    age = -1
    while(is_age_over(age+1, dob)):
        age += 1
    return age

def get_selected_languages(fields):
    langs = []
    for language in LANGUAGES:
        if language['name'] in fields:
            langs.append(language['name'])
    return langs

def validate_nonpassword(fields):
    is_valid = True
    if not EMAIL_REGEXP.match(fields['email']):
        flash("Not a valid email", "email")
        is_valid = False
    if len(fields['firstname']) < 2:
        flash("First name must have at least two characters", "firstname")
        is_valid = False
    if len(fields['lastname']) < 2:
        flash("Last name must have at least two characters", "lastname")
        is_valid = False
    if not is_age_over(10, fields['dob']):
        is_valid = False
        flash("You're too young to register", "dob")
    if len(get_selected_languages(fields)) < 2:
        flash("Select at least two languages", "languages")
        is_valid = False
    return is_valid

def validate_password(fields, categories=['password', 'confirm']):
    is_valid = True
    if len(fields[categories[0]]) < 8:
        flash("Your password must be at least eight characters", categories[0])
        is_valid = False
    if not(NUM_REGEX.match(fields[categories[0]]) and CAP_REGEX.match(fields[categories[0]])):
        flash("Password must contain at least one capital letter and one digit", categories[0])
        is_valid = False
    if (fields['confirm'] == "") or (fields[categories[0]] != fields[categories[1]]):
        flash("Passwords do not match", categories[1])
        is_valid = False
    return is_valid

def gen_lang_str():
    langstr = ""
    for language in LANGUAGES:
        if language['name'] in request.form:
            if len(langstr) > 0:
                langstr += " "
            langstr += language['name']
    return langstr

def validate_all_fields(fields):
    return (validate_nonpassword(fields) and validate_password(fields))

@app.route("/register", methods=["POST"])
def register():
    print(request.form)
    is_valid = validate_all_fields(request.form)
    if is_valid:
        mysql = connectToMySQL(dbname)
        if len(mysql.query_db("SELECT * FROM users WHERE email = %(email)s", request.form)) == 0:
            data = dict()
            for name in request.form.keys():
                data[name] = request.form[name]
            data['pswdhash'] = bcrypt.generate_password_hash(request.form['password'])
            dob = datetime.strptime(request.form['dob'], "%Y-%m-%d")
            data['dob'] = dob
            data['languages'] = gen_lang_str()
            status = mysql.query_db("INSERT INTO users ( firstname, lastname, email, pswdhash, created_at, updated_at, dob, languages ) VALUES ( %(firstname)s, %(lastname)s, %(email)s, %(pswdhash)s, NOW(), NOW(), %(dob)s, %(languages)s ) ;", data)
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
    if 'id' not in session:
        flash(not_logged_in, "error")
        return redirect("/")
    return render_template("success.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/viewprofile")
def viewprofile():
    if 'id' not in session:
        flash(not_logged_in, "error")
        return redirect("/")
    mysql = connectToMySQL(dbname)
    users = mysql.query_db("SELECT id, firstname, lastname, email, created_at, dob FROM users WHERE id = %(id)s", {'id': session['id']})
    if len(users) > 0:
        return render_template("profile.html", user = users[0])
    else:
        flash("Aw snap! Something went wrong. Try again in a few hours", "error")
        return redirect("/success")

@app.route("/editprofile")
def editprofile():
    if 'id' not in session:
        flash(not_logged_in, "error")
        return redirect("/")
    mysql = connectToMySQL(dbname)
    users = mysql.query_db("SELECT id, firstname, lastname, email, created_at, dob FROM users WHERE id = %(id)s", {'id': session['id']})
    userdata = dict()
    for key in users[0].keys():
        userdata[key] = users[0][key]
    userdata['dob'] = userdata['dob'].strftime("%Y-%m-%d")
    print(userdata)
    if len(users) > 0:
        return render_template("editprofile.html", user = userdata, EDITPROFILE=EDITPROFILE)
    else:
        flash("Aw snap! Something went wrong. Try again in a few hours", "error")
        return redirect("/success")

@app.route("/updateprofile", methods=['POST'])
def updateprofile():
    if 'id' not in session:
        flash(not_logged_in, "error")
        return redirect("/")
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
    if 'id' not in session:
        flash(not_logged_in, "error")
        return redirect("/")
    return render_template("change_password.html", EDITPASSWORD=EDITPASSWORD)

@app.route("/updatepassword", methods=['POST'])
def updatepassword():
    if 'id' not in session:
        flash(not_logged_in, "error")
        return redirect("/")
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
        return redirect("/changepasswd")
    if not validate_password(request.form, categories=['newpassword', 'confirm']):
        is_valid = False
    if not is_valid:
        return redirect("/changepasswd")
    else:
        pswdhash = bcrypt.generate_password_hash(request.form['newpassword'])
        status = mysql.query_db("UPDATE users SET pswdhash = %(pswdhash)s WHERE id = %(id)s", {'id': rows[0]['id'], 'pswdhash': pswdhash})
        if status:
            flash('Password changed', 'success')
        else:
            flash("Something went wrong in saving your new password. Password did not change.", "error")
        return redirect("/success")

@app.route("/deleteprofile")
def deleteprofile():
    if 'id' not in session:
        flash(not_logged_in, "error")
        return redirect("/")
    mysql = connectToMySQL(dbname)
    mysql.query_db("DELETE FROM users WHERE id = %(id)s", {'id': session['id']})
    return redirect("/logout")

if __name__ == "__main__":
    app.run(debug=True)