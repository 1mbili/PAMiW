"""
Utils functions for flask app
"""
import secrets
import bcrypt
import string

from os import getenv
from redis import Redis
from dotenv import load_dotenv
from jwt import decode
load_dotenv(verbose=True)

ALLOWED_EXTENSIONS = {'csv'}
PEPPER = getenv("PEPPER")
JWT_SECRET = getenv("JWT_SECRET")

db = Redis(host='redis', port=6379)


def validate_creds(password: str, email: str) -> bool:
    """Check if user credentials are valid"""
    if len(password) < 8:
        return "Zbyt krótkie hasło", False
    if "@" not in email:
        return "Zły format emaila", False
    if not all(" " not in x for x in (password, email)):
        return "Usuń spacje w loginie i haśle", False
    return "", True


def encrypt_password(password):
    """Encrypt password with bcrypt"""
    return bcrypt.hashpw(bytes(password+PEPPER, "utf-8"), bcrypt.gensalt())


def generate_state(length=30):
    """Generate random state"""
    return "".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(length))


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def update_passwords(content, username):
    content = content.decode("utf-8")
    for line in content.splitlines():
        if line[1:]:
            vals = line.split(",")
            if len(vals) != 4:
                continue
            db.sadd("dane:hasla:" + username, vals[0] + "6:" + vals[3])


def get_items(redis_set):
    return [x.decode() for x in redis_set]


def validate_token(token):
    if token == "":
        return False
    try:
        decoded = decode(token, JWT_SECRET, algorithms=["HS256"])
        return decoded
    except Exception as err:
        print(err)
        return False
