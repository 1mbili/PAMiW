import os
from redis import StrictRedis
redis_url = "redis://127.0.0.1"
db = StrictRedis.from_url(redis_url, decode_responses=True)

try:
    db.echo("ping")
except:
    print("ERROR communicating with Redis database.")
    print("Start Redis instance first. Exiting.")
    exit(1)

def main(filename):
    with open(filename, encoding="utf-8") as f:
        content = f.read().splitlines()
        print(content)
        db.sadd("dane:hasla:michalek", *content)
            


if __name__ == "__main__":
    filename = os.path.join(os.getcwd(), "user_list", "users", "michalek.txt")
    main(filename)
