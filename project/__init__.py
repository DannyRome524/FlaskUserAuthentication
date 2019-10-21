from flask import Flask
from project.functions.email_sender import Mail
# from flask_mail import Mail

app = Flask(__name__)

app.config['MAIL_DEFAULT_SENDER'] = 'twoway1115@gmail.com'
app.config['SECURITY_PASSWORD_SALT'] = "my_precious_two"

mail = Mail()