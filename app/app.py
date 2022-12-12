"""
Main app file
"""
import bleach
import secrets
import bcrypt

from os import getenv
from flask_sse import sse
from redis import Redis
from requests import Request, post
from time import sleep
from flask import Flask, flash, request, redirect, make_response, url_for
from flask import render_template
from dotenv import load_dotenv
from .create_jwt import create_username_jwt
from .send_email import send_temp_code
from .utils import validate_creds, encrypt_password, generate_state, allowed_file, update_passwords, get_items, validate_token
load_dotenv(verbose=True)


JWT_SECRET = getenv("JWT_SECRET")
SECRET_CREDENTIALS = getenv("SECRET_CREDENTIALS")
PEPPER = getenv("PEPPER")
CLIENT_ID = getenv("CLIENT_ID")
CLIENT_SECRET = getenv("CLIENT_SECRET")
REDIRECT_URI = "http://127.0.0.1:5050/callback"
REDIS_URL = "redis://redis:6379/0"

app = Flask(__name__)
app.config["REDIS_URL"] = REDIS_URL
app.secret_key = getenv("FLASK_SECRET_KEY")
db = Redis(host='redis', port=6379)

app.register_blueprint(sse, url_prefix="/stream")

db.echo("ping")


@app.route("/", methods=["GET"])
def index():
    jwt = request.cookies.get("jwt")
    jwt_data = validate_token(jwt)
    if jwt_data:
        return redirect(url_for('user', username=jwt_data["username"]), code=302)
    return redirect("/authenticate", code=302)


@app.route("/user/<username>", methods=["GET"])
def user(username):
    return render_template("homepage.html", username=username)


@app.route("/user_passwords", methods=["GET"])  # POST
def user_passwords():
    jwt = request.cookies.get("jwt")
    username = validate_token(jwt)['username']
    klucz = "dane:hasla:"+username
    user_password = db.smembers(klucz)
    sse.publish(get_items(user_password), type="msg")
    while True:
        sleep(3)
        user_passwords_new = db.smembers(klucz)
        if user_passwords_new != user_password:
            sse.publish(get_items(user_passwords_new), type="msg")
            user_password = user_passwords_new


@app.route("/sse")
def server_sent_events():
    return render_template("homepage.html")


@app.route("/authenticate", methods=["GET", "POST"])
def authenticate():
    if request.method == "GET":
        return render_template("login-form.html")
    subpages = ["register", "restore_acces", "oauth"]
    if "auth" not in request.form.keys():
        for subpage in subpages:
            if subpage in request.form.keys():
                return redirect("/" + subpage, code=302)
    username = bleach.clean(request.form.get("username", ""))
    password = bleach.clean(request.form.get("password", ""))
    password_in_db = db.get("klient:" + username + ":haslo")
    if password_in_db and bcrypt.checkpw(bytes(password+PEPPER, "utf-8"), password_in_db):
        response = redirect("/", code=302)
        response.set_cookie("jwt", create_username_jwt(username, JWT_SECRET))
        return response
    flash('Niepoprawna nazwa użytkownika lub hasło')
    return redirect("/authenticate", code=302)


@app.route("/logout", methods=["GET"])
def logout():
    flash('Wylogowano pomyślnie')
    response = redirect("/", code=302)
    response.set_cookie("jwt", '', expires=0)
    response.set_cookie("state", '', expires=0)
    return response


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
        flash("Hasła nie są takie same")
        return redirect(request.url)
    email = request.cookies.get("email")
    username = request.cookies.get("username")
    msg, creds_check = validate_creds(new_password, email)
    if creds_check is False:
        flash(msg)
        return redirect(request.url)
    if token != db.get("tempCode:" + email).decode():
        flash("Zły Token")
        return redirect(request.url)
    db.set("klient:" + username + ":haslo", encrypt_password(new_password))
    response = redirect("/", code=302)
    response.set_cookie("email", "", expires=0)
    response.set_cookie("username", "", expires=0)
    return response


@app.route("/callback")
def callback():
    args = request.args
    cookies = request.cookies

    if args.get("state") != cookies.get("state"):
        return "State does not match. Possible authorization_code injection attempt", 400

    params = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": args.get("code")
    }

    access_token = post("https://github.com/login/oauth/access_token",
                        params=params)
    params_username = {"Authorization": "Bearer " +
                       access_token.text.split("&")[0].split("=")[1]}
    username = post("https://api.github.com/user",
                    headers=params_username)
    github_response = username.json()
    if 'login' in github_response.keys():
        response = redirect("/", code=302)
        response.set_cookie("jwt", create_username_jwt(
            github_response['login'], JWT_SECRET))
        return response
    return "SMT went wrong", 400


@app.route("/oauth")
def authorize_with_github():
    random_state = generate_state()
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "user",
        "state": random_state
    }
    authorize = Request("GET", "https://github.com/login/oauth/authorize",
                        params=params).prepare()

    response = redirect(authorize.url)
    response.set_cookie("state", random_state)
    return response


@app.route("/user/addPass", methods=["POST"])
def add_password():
    name = bleach.clean(request.form.get("name", ""))
    new_password = bleach.clean(request.form.get("new_password", ""))
    if name == "" or new_password == "":
        return redirect(request.url)
    jwt = request.cookies.get("jwt")
    jwt_data = validate_token(jwt)
    if jwt_data:
        print(name + ":" + new_password)
        db.sadd("dane:hasla:" +
                jwt_data["username"], name + ":" + new_password)
        return redirect(url_for('user', username=jwt_data["username"]), code=302)
    return "Unauthorized", 401


@app.route("/user/upload", methods=["POST"])
def upload_passwords():
    print("DUPA")
    jwt = request.cookies.get("jwt")
    jwt_data = validate_token(jwt)
    if jwt_data:
        print(request.files.keys())
        if 'name' not in request.files:
            flash('Pusty plik')
            return redirect(request.url)
        file = request.files['name']
        if file.filename == '':
            flash('Plik bez nazwy')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            content = file.stream.read()
            update_passwords(content, jwt_data["username"])
            return ('', 204)
        return ('', 204)
    return "Unauthorized", 401
