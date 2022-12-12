import redis

db = redis.StrictRedis.from_url("redis://127.0.0.1")
db.delete("dane:hasla:PW-Michal-Bilinski")
print(db.sadd("dane:hasla:PW-Michal-Bilinski" ,""))
