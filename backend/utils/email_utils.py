from flask_mail import Message
from mail import mail

def send_notification_email(subject, recipient, body):
    msg = Message(subject, recipients=[recipient], body=body)
    mail.send(msg)