from flask import Flask, render_template, url_for, redirect, jsonify, request
from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from datetime import timedelta
import mysql.connector

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'secretkey'
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

db = mysql.connector.connect(
    host = "localhost",
    user = "root",
    password = "",
    database = "tst_house",
    )

db_cursor = db.cursor()

# Page Awal
@app.route('/')
def loginPage():
    return render_template('login.html')

# Register
@app.route("/register", methods = ["POST" , "GET"])
def register():
    if request.method == "POST" :
        username = request.form['username']
        password = request.form['password']

        db_cursor.execute("SELECT * FROM user_data WHERE username = %s", [username])
        user = db_cursor.fetchone()
        if user:
            return render_template('register.html', session_info = "Username already registered")
        
        hashed = generate_password_hash(password)
        db_cursor.execute("INSERT INTO user_data (username, password) VALUES (%s,%s)", [username, hashed])
        db.commit()

        return render_template('register.html')

    return render_template('register.html')

# Login
@app.route("/login", methods = ["POST" , "GET"])
def login():
    if request.method == "POST" :
        username = request.form['username']
        password = request.form['password']

        db_cursor.execute("SELECT * FROM user_data WHERE username = %s", [username])
        user = db_cursor.fetchone()

        if check_password_hash(user[2], password):
            token = create_access_token(identity = user[1], expires_delta = timedelta(minutes = 30))
            return jsonify({'Token' : token}), 200
        return render_template('login.html', session_info = "Wrong Password")

    return render_template('login.html')

@app.route("/view", methods=["GET"])
@jwt_required()
def read():
    db_cursor.execute("SELECT * FROM melb_data")
    return jsonify(db_cursor.fetchall())

@app.route("/add", methods=["POST"])
@jwt_required()
def create():
    db_cursor.execute("INSERT INTO melb_data (suburb, address, rooms, price, seller, date, distance, bedroom, bathroom, car, landsize) \
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                       (request.json["suburb"], request.json["address"], request.json["rooms"], request.json["price"], request.json["seller"], 
                       request.json["date"], request.json["distance"], request.json["bedroom"],
                       request.json["bathroom"], request.json["car"], request.json["landsize"]))
    db.commit()
    return jsonify({"Message" : "House Succesfully Added"})

@app.route("/updatePrice", methods=["PUT"])
@jwt_required()
def update():
    db_cursor.execute("UPDATE melb_data SET price = %s WHERE address = %s", (request.json["price"], request.json["address"]))
    db.commit()
    return jsonify({"Message" : "House Succesfully Updated"})

@app.route("/delete", methods=["DELETE"])
@jwt_required()
def delete():
    db_cursor.execute("DELETE FROM melb_data WHERE address = %s", (request.json["address"],))
    db.commit()
    return jsonify({"Message" : "House Succesfully Deleted"})

if __name__ == "__main__":
    app.run(debug = True)