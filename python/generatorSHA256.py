
import hashlib

tekst = "zzzz"

password = hashlib.sha256(tekst.encode()).hexdigest()
print(password)