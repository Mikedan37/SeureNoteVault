import smtplib
from email.mime.text import MIMEText

def send_email(to_email, subject, body):
    sender_email = "your-email@example.com"
    sender_password = "your-password"
    smtp_server = "smtp.example.com"

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = to_email

    with smtplib.SMTP(smtp_server, 587) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, to_email, msg.as_string())