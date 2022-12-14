from flask import Flask, make_response, render_template, url_for, redirect, jsonify, request
from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, set_access_cookies, unset_jwt_cookies
from datetime import timedelta
import os
import psycopg2
from dotenv import load_dotenv
import requests

load_dotenv()

app = Flask(__name__)
url = os.getenv("DATABASE_URL")

host = "rosie.db.elephantsql.com"
databae = "hstlocax"
user = "hstlocax"
password = "o5q34FQ_ukM3DPGx2K4QvK4wC7Is4MRL"

db = psycopg2.connect(host=host, database=databae, user=user, password=password)

# app configurtion
app.config['JWT_SECRET_KEY'] = 'secretkey'
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = False

jwt = JWTManager(app)
bcrypt = Bcrypt(app)

db_cursor = db.cursor()

# Page Awal
@app.route('/')
def loginPage():
    return make_response(redirect('/login'))

# Register
@app.route("/register", methods = ["POST" , "GET"])
def register():
    if request.method == "POST" :
        username = request.form['username']
        password = request.form['password']

        db_cursor.execute("SELECT * FROM users WHERE username = %s", [username])
        user = db_cursor.fetchone()
        if user:
            return render_template('register.html', session_info = "Username already registered")
        
        hashed = generate_password_hash(password).decode('utf-8')
        db_cursor.execute("INSERT INTO users (username, password) VALUES (%s,%s)", [username, hashed])
        db.commit()

        return render_template('register.html')

    return render_template('register.html')

# Login
@app.route("/login", methods = ["GET"])
def login():
    return render_template('login.html')

@app.post('/login')
def login_post():
    username = request.form['username']
    password = request.form['password']

    db_cursor.execute("SELECT * FROM users WHERE username = %s", [username])
    user = db_cursor.fetchone()

    if check_password_hash(user[2], password):
        token = create_access_token(identity = user[1], expires_delta = timedelta(minutes = 5))
        resp = make_response(redirect('/recommendation'))
        resp.set_cookie('access_token_cookie', token)
        return resp
    return render_template('login.html', session_info = "Wrong Password")

# Login Akmal
@app.route("/loginuser", methods=["POST"])
def loginuser():
    username = request.form['username']
    password = request.form['password']

    if not username or not password:
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    db_cursor.execute("select * from users where username=%s", (username,))
    user = db_cursor.fetchone()
    if not user:
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    if check_password_hash(user[2], password):
        access_token = create_access_token(identity=user[1], expires_delta=timedelta(minutes=30))
        return jsonify({'token': access_token}), 200
    return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

# Logout
@app.get("/logout")
def logout():
    # resp = make_response('remove cookie')
    # resp.set_cookie('access_token', '', max_age=0)
    # resp = jsonify({'logout':True})
    resp = make_response(redirect('/login'))
    unset_jwt_cookies(resp)
    return resp

@app.get('/roomarea')
def roomareaget():
    return render_template('test.html')

@app.post("/roomarea")
@jwt_required(locations="headers")
def roomarea():
    landsize = request.json.get('landsize', None)
    bedroom = request.json.get('bedroom', None)

    db_cursor.execute("SELECT rooms, bedroom, bathroom, car, landsize FROM house WHERE landsize <= %s and landsize IS NOT NULL and bedroom = %s ORDER BY landsize DESC", [landsize, bedroom])
    house = db_cursor.fetchall()
    houseList = []

    for i in range(len(house)):
        car_area = float(house[i][3]) * 10
        
        rooms_area = (float(house[i][4]) - car_area) * 0.4
        bathroom_area = (float(house[i][4]) - car_area - rooms_area) * 0.1
        bedroom_area = (((float(house[i][4]) - car_area - rooms_area - bathroom_area)/float(house[i][1]))*10000)

        newItem = {
            "rooms": house[i][0],
            "bedroom": house[i][1],
            "bathroom": house[i][2],
            "car": house[i][3],
            "landsize": house[i][4],
            "bedroom_area": bedroom_area
        }
        
        houseList.append(newItem)
    
    return jsonify(houseList)

@app.route("/recommendation", methods=["GET" , "POST"])
def recommendation():
    if (request.method=="POST"):
        budget = float(request.form['user-budget'])
        house = float(request.form['house-saving'])
        furniture = float(request.form['furniture-saving'])

        url_login = requests.post("https://tubeststakmal.azurewebsites.net/api/v1/login", data = {"username" : "admin" ,"password" : "pwadmin"})
        tokenAkmal = url_login.json().get("token")

        recommendation_url = "https://tubeststakmal.azurewebsites.net/api/v1/rekomendasi"
        jar = requests.cookies.RequestsCookieJar()
        jar.set('access_token_cookie', tokenAkmal, domain='tubeststakmal.azurewebsites.net', path='/')

        rec_furniture = requests.post(recommendation_url, cookies=jar, headers={'Authorization' : 'Bearer ' + tokenAkmal, 'Content-type' : 'application/json'} ,json={"price" : budget, "bobot" : furniture})
        furniture_list = rec_furniture.json()
        
        price_house = str((house/100) * budget)
        db_cursor.execute("SELECT * FROM house WHERE price <= %s and landsize > '0' ", [price_house])
        house = db_cursor.fetchall()

        return render_template('recommendation.html', output_house = house, output_furniture = furniture_list)
    else:
        return render_template('home.html')

@app.route("/view", methods=["GET"])
@jwt_required()
def read():
    db_cursor.execute("SELECT * FROM house")
    return jsonify({'data':db_cursor.fetchall()})

@app.route("/add", methods=["POST"])
@jwt_required()
def create():
    db_cursor.execute("INSERT INTO house (suburb, address, rooms, price, seller, date, distance, bedroom, bathroom, car, landsize) \
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                       (request.json["suburb"], request.json["address"], request.json["rooms"], request.json["price"], request.json["seller"], 
                       request.json["date"], request.json["distance"], request.json["bedroom"],
                       request.json["bathroom"], request.json["car"], request.json["landsize"]))
    db.commit()
    return jsonify({"Message" : "House Succesfully Added"})

@app.route("/updatePrice", methods=["PUT"])
@jwt_required()
def update():
    db_cursor.execute("UPDATE house SET price = %s WHERE address = %s", (request.json["price"], request.json["address"]))
    db.commit()
    return jsonify({"Message" : "House Succesfully Updated"})

@app.route("/delete", methods=["DELETE"])
@jwt_required()
def delete():
    db_cursor.execute("DELETE FROM house WHERE address = %s", (request.json["address"],))
    db.commit()
    return jsonify({"Message" : "House Succesfully Deleted"})

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5002)