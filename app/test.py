from email.message import EmailMessage
from dotenv import load_dotenv

from os import getenv
import smtplib
import ssl
load_dotenv(verbose=True)

sender = getenv("GMAIL_USER")
password = getenv("GMAIL_PASS")
receiver = ['m.bilinskimichal@gmail.com']

subject="AGRAFKA"
message = """DONNA MAMA ES HUJOCZITA"""

em = EmailMessage()
em["From"] = sender
em["To"] = receiver
em["Subject"] = subject
em.set_content(message)

context = ssl.create_default_context()

with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
    server.login(sender, password)
    server.send_message(em)