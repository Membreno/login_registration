from flask import Flask, render_template, request, redirect,session,flash
from mysqlconnection import connectToMySQL
import re
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = "logReg"
app.secret_key = 'unicorn'
bcrypt = Bcrypt(app)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')


@app.route('/')
def index():
    print('*' * 50)
    print('In the root route')
    return render_template('index.html')

@app.route('/success')
def success():
    mysql = connectToMySQL(db)
    print('*' * 50)
    print('In the success route')
    query = "SELECT * FROM users WHERE id = " + str(session['id']) + ";"
    row = mysql.query_db(query)
    print(row)
    name = row[0]['first_name']
    return render_template('success.html', name = name)

@app.route('/register', methods=['POST'])
def register():
    print('*' * 50)
    print('In the register route')
    print(request.form)
    fName = request.form['first_name']

    is_valid = True # assume True
    if len(request.form['password']) > 5:
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        print(pw_hash)
    if len(fName) < 1:
        is_valid = False # display validation error
        flash("Please enter a first name", "first")
    elif not fName.isalpha():
        is_valid = False
        flash("Name can only contain letters", "letter_check")
    if len(request.form['last_name']) < 1:
        is_valid = False
        flash("Please enter a last name", "last")
    if len(request.form['email']) < 1:
        is_valid = False
        flash("field cannot be left blank", "email")
    elif not EMAIL_REGEX.match(request.form['email']):
        is_valid = False
        flash("Invalid email address. Please try again.", "invalid")
    if len(request.form['password']) < 1:
        is_valid = False
        flash("field cannot be left blank", "password")
    elif len(request.form['password']) < 5:
        is_valid = False
        flash("password must be at least 6 characters", "password_length")
    if len(request.form['confirm_password']) < 1:
        is_valid = False
        flash("field cannot be left blank", "confirm")
    elif request.form['confirm_password'] != request.form['password']:
        is_valid = False
        flash("passwords must match", "confirm")
    if not is_valid:    # if any of the fields switched our is_valid toggle to False
        return redirect('/')    # redirect back to the method that displays the index page
    else:
        mysql = connectToMySQL(db)
        query = "INSERT INTO users (first_name, last_name, email, password) VALUES (%(first)s, %(last)s, %(email)s, %(password_hash)s);"
        data = {
            "first": request.form['first_name'],
            "last": request.form['last_name'],
            "email": request.form["email"],
            "password_hash" : pw_hash
        }
        session['id'] = mysql.query_db(query, data) # Tied a unique session ID directly to the user (stored with-ish the browser/database)
        print("*" * 50)
        print(session['id'])
        return redirect('/success')

@app.route('/login', methods=['POST'])
def login():
    print('*' * 50)
    print('In the login route')
    print(request.form)

    is_valid = True # assume True
    if len(request.form['log_email']) < 1:
        is_valid = False
        flash("field cannot be left blank", "log_email")
    elif not EMAIL_REGEX.match(request.form['log_email']):
        is_valid = False
        flash("Invalid email address. Please try again.", "invalid_log")
    if len(request.form['log_password']) < 1:
        is_valid = False
        flash("field cannot be left blank", "log_password")
    if not is_valid:    # if any of the fields switched our is_valid toggle to False
        return redirect('/')
    else:
        mysql = connectToMySQL(db)
        query = "SELECT * FROM users WHERE email = %(em)s;"
        data = {'em' : request.form['log_email']}
        result = mysql.query_db(query,data)        
        if len(result) > 0:
            if bcrypt.check_password_hash(result[0]['password'], request.form['log_password']): # used to check if password typed matches database
                session['id'] = result[0]['id']
                session['temp'] = bcrypt.generate_password_hash(str(session['id']))
                return redirect('/success')
            else: # Used if the input doesn't find a match
                flash("You could not be logged in", "fail")
                return redirect('/')
        else: # Set outside of the about conditions, but under original if so if NO EMAIL EXIST we can show flash message
            flash("No such email exist", "none")
            return redirect('/')
@app.route('/logout')
def logout():
    print('*' * 50)
    print('User has been logged out')
    session.clear()
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)