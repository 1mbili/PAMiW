"""
Main app file
"""
import bleach
import secrets
import bcrypt
import string

from os import getenv
from flask_sse import sse
from jwt import decode 
from redis import Redis
from time import sleep
from flask import Flask, request, redirect, make_response
from flask import render_template
from dotenv import load_dotenv
from .create_jwt import create_username_jwt
from .send_email import send_temp_code
load_dotenv(verbose=True)


JWT_SECRET = getenv("JWT_SECRET")
SECRET_CREDENTIALS = getenv("SECRET_CREDENTIALS")
PEPPER = getenv("PEPPER")
CLIENT_ID = getenv("CLIENT_ID")
CLIENT_SECRET = getenv("CLIENT_SECRET")
REDIRECT_URI= "http://127.0.0.1:5050/callback"
REDIS_URL = "redis://redis:6379/0"
app = Flask(__name__)
app.config["REDIS_URL"] = REDIS_URL
db = Redis(host='redis', port=6379)

app.register_blueprint(sse, url_prefix="/stream")

db.echo("ping")


@app.route("/", methods=["GET"])
def index():
    jwt = request.cookies.get("jwt")
    jwt_data = valid_token(jwt)
    if jwt_data:
        return render_template("homepage.html", username=jwt_data["username"])
    return redirect("/authenticate", code=302)


def valid_token(token):
    try:
        print(token)
        decoded = decode(token, JWT_SECRET, algorithms=["HS256"])
        return decoded
    except Exception as err:
        print(err)
        return False



@app.route("/user_passwords", methods=["GET"]) #POST
def user_passwords():
    jwt = request.cookies.get("jwt")
    username = valid_token(jwt)['username']
    klucz = "dane:hasla:"+username
    user_password = db.smembers(klucz)
    sse.publish(get_items(user_passwords), type="msg")
    while True:
        sleep(3)
        user_passwords_new = db.smembers(klucz)
        if user_passwords_new != user_password:
            sse.publish(get_items(user_passwords_new), type="msg")
            user_passwords = user_passwords_new


def get_items(redis_set):
  return [x.decode() for x in redis_set]


@app.route("/sse")
def server_sent_events():
    return render_template("homepage.html")


@app.route("/authenticate", methods=["GET", "POST"])
def authenticate():
    if request.method == "GET":
        return render_template("login-form.html")
    if "register" in request.form.keys():
        return redirect("/register", code=302)
    if "restore_acces" in request.form.keys():
        return redirect("/restore_acces", code=302)
    username = bleach.clean(request.form.get("username", ""))
    password = bleach.clean(request.form.get("password", ""))
    password_in_db = db.get("klient:" + username + ":haslo")
    if password_in_db and bcrypt.checkpw(bytes(password+PEPPER, "utf-8"), password_in_db):
        response = redirect("/", code=302)
        response.set_cookie("jwt", create_username_jwt(username, JWT_SECRET))
        return response
    return "Wrong username or password", 400

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register-form.html")
    username = bleach.clean(request.form.get("username", ""))
    password = encrypt_password(bleach.clean(request.form.get("password", "")))
    email = bleach.clean(request.form.get("email", ""))
    msg, creds_check = validate_creds(username, email)
    if creds_check is False:
        return msg, 400
    pass_key = "klient:" + username + ":haslo"
    email_key = "klient:" + username + ":e-mail"
    if db.get(pass_key) is not None or db.get(email_key) is not None:
        return "User already exists", 400
    db.set(pass_key, password)
    db.set(email_key, email)
    response = redirect("/authenticate", code=302)
    return response


@app.route("/restore_acces", methods=["GET", "POST"])
def restore_acces():
    if request.method == "GET":
        response = make_response(render_template("restore_acces.html"))
        response.set_cookie("email", "", expires=0)
        response.set_cookie("username", "", expires=0)
        return response
    username = bleach.clean(request.form.get("username", ""))
    email = db.get("klient:" + username + ":email").decode()
    key = "tempCode:" + email
    auth_secret = secrets.token_urlsafe(12)
    db.set(key, auth_secret)
    db.expire(key, 3600)
    mail_list = [email]
    send_temp_code(mail_list, auth_secret)
    response = redirect("/restore_acces/verify", code=302)
    response.set_cookie("email", email)
    response.set_cookie("username", username)
    return response


@app.route("/restore_acces/verify", methods=["GET", "POST"])
def set_new_password():
    """Update password for user"""
    if request.method == "GET":
        return render_template("verify.html")
    token = bleach.clean(request.form.get("token", ""))
    new_password = bleach.clean(request.form.get("new_password", ""))
    new_password_conf = bleach.clean(request.form.get("new_password_conf", ""))
    if new_password != new_password_conf:
        return "Passwords do not match", 400
    email = request.cookies.get("email")
    username = request.cookies.get("username")
    msg, creds_check = validate_creds(new_password, email)
    if creds_check is False:
        return msg, 400 
    if token != db.get("tempCode:" + email).decode():
        return "Wrong temporary code", 400
    db.set("klient:" + username + ":haslo", encrypt_password(new_password))
    response = redirect("/", code=302)
    response.set_cookie("email", "", expires=0)
    response.set_cookie("username", "", expires=0)
    return response


@app.route("/oauth")
def authorize_with_github():
    random_State = generate_state()
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "user repo",
        "state" : random_State
    }


def validate_creds(password: str, email: str) -> bool:
    """Check if user credentials are valid"""
    if len(password) < 8:
        return "Too short pass", False
    if "@" not in email:
        return "Invalid email",False
    if not all(" " not in x for x in (password, email)):
        return "Fields cannot contain empty spaces",False
    return "", True


def encrypt_password(password):
    """Encrypt password with bcrypt"""
    return bcrypt.hashpw(bytes(password+PEPPER, "utf-8"), bcrypt.gensalt())


def generate_state(length=30):
    """Generate random state"""
    return "".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(length))