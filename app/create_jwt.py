import jwt
from datetime import datetime, timedelta


def create_username_jwt(username, secret):
    dt = datetime.now() + timedelta(days=1)           
    dane = {"username": username, "exp": dt}
    zeton = jwt.encode(dane, secret, "HS256")
    return zeton
