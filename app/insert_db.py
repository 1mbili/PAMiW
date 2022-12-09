import os
import sys
from redis import StrictRedis
from bcrypt import hashpw, gensalt
from dotenv import load_dotenv
load_dotenv(verbose=True)


PEPPER = os.getenv("PEPPER")
print(PEPPER)
redis_url = "redis://127.0.0.1"
db = StrictRedis.from_url(redis_url, decode_responses=True)

try:
    db.echo("ping")
except:
    print("ERROR communicating with Redis database.")
    print("Start Redis instance first. Exiting.")
    sys.exit(1)

def main(filename):
    with open(filename, encoding="utf-8") as f:
        for line in f:
            key, value = line.split()
            if  key.split(":")[-1]:
                value = hashpw(bytes(value+PEPPER, "utf-8" ), salt=gensalt())
            db.set(key, value)
    db.delete("dane:hasla:michalek")
    db.sadd("dane:hasla:michalek", "Faebook:123michal", "Google:admin123")
    db.set("klient:michalek:email", "m.bilinskimichal@gmail.com")

if __name__ == "__main__":
    filename = os.path.join(os.getcwd(), "user_list", "users.txt")
    main(filename)
