# from flask_mail import Message, Mail, _Mail, Connection, _MailMixin
from project.functions.email_sender import Message


from project import app
from project import mail

# class CustomMail(Mail):
#   def init_mail(self, service, debug=False, testing=False)
#     service = Service.objects.filter(asdfasdf)
#     return _Mail(service.mail_service)



def send_email(to, subject, template):
  msg = Message(
    subject,
    recipients=[to],
    html=template,
    sender = app.config['MAIL_DEFAULT_SENDER']
  )
  mail.send(msg)