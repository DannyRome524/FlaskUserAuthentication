from project.database.db import db


class UserModel(db.Model):
  __tablename__ = "user"
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(255), nullable=False, index=True)
  email = db.Column(db.String(255), nullable=False, index=True)
  password = db.Column(db.String(255), nullable=False)
  country = db.Column(db.String(2))
  lang = db.Column(db.String(5))
  mobilenumber = db.Column(db.String(45))
  registered = db.Column(db.DateTime)
  registration_ip = db.Column(db.String(45))
  service = db.Column(db.String(45), nullable=False)
  b64_img = db.Column(db.BLOB)
  account_status = db.Column(db.String(45))
  valid_until = db.Column(db.DateTime)
  verified = db.Column(db.Boolean)
  payment_reference = db.Column(db.String(255), index=True)
    
  def __init__(self, username, email, password, country, service, lang=None, mobilenumber=None, registered=None, registration_ip=None, b64_img=None, account_status=None, valid_until=None, verified=None, payment_reference=None):
    self.username = username
    self.email = email
    self.password = password
    self.country = country
    self.service = service
    self.lang = lang
    self.mobilenumber = mobilenumber
    self.registered = registered
    self.registration_ip = registration_ip
    self.b64_img = b64_img
    self.account_status = account_status
    self.valid_until = valid_until
    self.verified = verified
    self.payment_reference = payment_reference

  def json(self):
    return {
        "id": self.id,
        "username": self.username
    }, 200

  # Method to save user to DB
  def save_to_db(self):
    db.session.add(self)
    db.session.commit()

  # Method to remove user from DB
  def remove_from_db(self):
    db.session.delete(self)
    db.session.commit()

  # Class method which finds user from DB by username
  @classmethod
  def find_user_by_username(cls, username):
    return cls.query.filter_by(username=username).first()

  # Class method which finds user from DB by id
  @classmethod
  def find_user_by_id(cls, _id):
    return cls.query.filter_by(id=_id).first()


class Login_History(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  user_id = db.Column(db.Integer)
  login_date = db.Column(db.DateTime)
  ip = db.Column(db.String(45))
  useragent = db.Column(db.String(255))

  def __init__(self, user_id, login_date=None, ip=None, useragent=None):
    self.user_id=user_id
    self.login_date = login_date
    self.ip = ip
    self.useragent = useragent

  def save_to_db(self):
    db.session.add(self)
    db.session.commit()

# class Api_Users(db.Model):
#   id = db.Column(db.Integer, primary_key=True, nullable=False)
#   username = db.Column(db.String(45), default=NULL)
#   password = db.Column(db.String(255), default=NULL)
#   service = db.Column(db.String(45), default=NULL)

# class Html_Templates(db.Model):
#   id = db.Column(db.Integer, primary_key=True, nullable=False)
#   service = db.Column(db.String(45), default=NULL)
#   type = db.Column(db.String(45), default=NULL)
#   template = db.Column(db.String(255), default=NULL)

class Email_Settings(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  service = db.Column(db.String(45), nullable=False)
  smtpserver = db.Column(db.String(45))
  port = db.Column(db.Integer)
  username = db.Column(db.String(45))
  password = db.Column(db.String(255))

  def __init__(self, service, smtpserver, port, username, password):
    self.service = service
    self.smtpserver = smtpserver
    self.port = port
    self.username = username
    self.password = password


