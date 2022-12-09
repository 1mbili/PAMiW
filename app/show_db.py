import redis

db = redis.StrictRedis.from_url("redis://127.0.0.1")

print(db.get("jajuszko"))
for klucz in db.keys():
    try:
      print(klucz, db.get(klucz))
    except:
      print(klucz, db.smembers(klucz))
