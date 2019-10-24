from flask import Flask
from project.functions.email_sender import Mail

app = Flask(__name__)

app.config['MAIL_DEFAULT_SENDER'] = 'default@example.com'
app.config['SECURITY_PASSWORD_SALT'] = "my_precious_two"

mail = Mail()