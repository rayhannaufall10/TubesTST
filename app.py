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

# class User(db_cursor.Model, UserMixin):
#     id = db_cursor.Column(db_cursor.Integer, primary_key=True)
#     username = db_cursor.Column(db_cursor.String(20), nullable=False, unique=True)
#     password = db_cursor.Column(db_cursor.String(80), nullable=False)

# class RegisterForm(FlaskForm):
#     username = StringField(validators=[
#                            InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

#     password = PasswordField(validators=[
#                              InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

#     submit = SubmitField('Register')

#     def validate_username(self, username):
#         existing_user_username = User.query.filter_by(
#             username=username.data).first()
#         if existing_user_username:
#             raise ValidationError(
#                 'That username already exists. Please choose a different one.')


# class LoginForm(FlaskForm):
#     username = StringField(validators=[
#                            InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

#     password = PasswordField(validators=[
#                              InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

#     submit = SubmitField('Login')

# Dashboard
# @app.route('/')
# def home():
#     return render_template('home.html')

# Register
@app.route("/register", methods = ["POST"])
def register():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    db_cursor.execute("SELECT * FROM user_data WHERE username = %s", [username])
    user = db_cursor.fetchone()
    if user:
        return jsonify({'Message' : 'User Already Exist'}), 403
    
    hashed = generate_password_hash(password)
    db_cursor.execute("INSERT INTO user_data (username, password) VALUES (%s,%s)", [username, hashed])
    db.commit()

    return jsonify({'Message' : 'Account Registed'}), 200

# Login
@app.route("/login", methods = ["POST"])
def login():
    # authorization = request.authorization
    # if not authorization or not authorization.username or not authorization.password:
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    db_cursor.execute("SELECT * FROM user_data WHERE username = %s", [username])
    user = db_cursor.fetchone()

    if check_password_hash(user[2], password):
        token = create_access_token(identity = user[1], expires_delta = timedelta(minutes = 1))
        return jsonify({'Token' : token}), 200
    return jsonify({'Message' : 'Login Failed, Wrong Password'})

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