from flask import Flask, render_template, request, redirect, session, flash, get_flashed_messages
from mysqlconnection import connectToMySQL
import os
app = Flask(__name__)

app.secret_key = 'darksecret'

dbname = 'dbname'

@app.route("/")
def mainpage():
    print(get_flashed_messages())
    session.clear()
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)