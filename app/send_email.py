"""
Module for sending emails
"""

import smtplib
import ssl
from email.message import EmailMessage
from os import getenv
from dotenv import load_dotenv
load_dotenv(verbose=True)


def send_temp_code(recivers: list, code: str):
    """Function for sending emails"""
    message = f"""
    Witaj,
    Poniżej przesyłam kod do zmiany hasła:
    {code}
    Pozdrawiamy!
    """
    sender = getenv("GMAIL_USER")
    password = getenv("GMAIL_PASS")
    email_msg = EmailMessage()
    email_msg["From"] = sender
    email_msg["To"] = recivers
    email_msg["Subject"] = "Link do zmiany hasła"
    email_msg.set_content(message)
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender, password)
        server.send_message(email_msg)
