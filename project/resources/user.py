from flask import request, url_for, render_template
from flask_mail import Mail
from flask_restful import Resource, reqparse
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_refresh_token_required, get_jwt_identity, fresh_jwt_required, jwt_required
import datetime

from project.models.user import UserModel, Email_Settings, Login_History
from project.functions.token import generate_confirmation_token, confirm_token
from project.functions.email import send_email
from project import app, mail
from project.auth import auth
from project.database.db import db

import hashlib


_user_parser = reqparse.RequestParser()
_user_parser.add_argument(
  "username",
  type=str,
  required=True,
  help="This field cannot be blank"
)

_user_parser.add_argument(
  "email",
  type=str,
  required=True,
  help="This field cannot be blank"
)

_user_parser.add_argument(
  "password",
  type=str,
  required=True,
  help="This field cannot be blank"
)

_user_parser.add_argument(
  "mobilenumber",
  type=str
)

_user_parser.add_argument(
  "country",
  type=str,
  required=True,
  help="This field cannot be blank"
)

_user_parser.add_argument(
  "service",
  type=str,
  required=True,
  help="This field cannot be blank"
)

_user_parser.add_argument(
  "lang",
  type=str
)

_user_parser.add_argument(
  "registration_ip",
  type=str
)

_user_parser.add_argument(
  "b64_img"
)

_user_parser.add_argument(
  "payment_reference",
  type=str
)

class User(Resource):
  @auth.login_required
  def get(self, user_id):
    user = UserModel.find_user_by_id(user_id)
    if user:
      return user.json()

    
    return {
      "message": "User not found!"
    }, 404


  @fresh_jwt_required
  def delete(self, user_id):
    user = UserModel.find_user_by_id(user_id)
    if user:
      user.remove_from_db()
      return {
        "message": "User deleted!"
      }, 200


    return {
      "message": "User not found!"
    }, 404



class UserRegister(Resource):
  def post(self):
    data = _user_parser.parse_args()

    username = data["username"]
    email = data["email"]
    password = hashlib.sha256(data["password"].encode("utf-8")).hexdigest()
    country = data["country"]
    service = data["service"]
    lang = data["lang"]
    mobilenumber = data["mobilenumber"]
    registered = datetime.datetime.now()
    registration_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    b64_img = data["b64_img"]
    account_status = "pending"
    valid_until = datetime.datetime.now() + datetime.timedelta(hours=1)
    verified = False
    payment_reference = data["payment_reference"]

    if UserModel.find_user_by_username(data["username"]):
      return {
        "message": "User exists!"
      }, 400
    
    user = UserModel(
      username,
      email,
      password,
      country,
      service,
      lang,
      mobilenumber,
      registered,
      registration_ip,
      b64_img,
      account_status,
      valid_until,
      verified,
      payment_reference
    )
    print(user)
    user.save_to_db()
    
    email_confirmation_data = Email_Settings.query.filter_by(service=user.service).first()
    mail.init_app(app, email_confirmation_data)

    token = generate_confirmation_token(user.email)
    confirm_url = url_for('confirmationview', token=token, _external=True)
    html = render_template('confirmation.html', confirm_url=confirm_url)
    subject = "Please confirm your email"
    send_email(user.email, subject, html)

    return {
      "message": "User {} created!".format(data["username"])
    }


_user_login = reqparse.RequestParser()
_user_login.add_argument(
  "username",
  type=str,
  required=True,
  help="This field cannot be blank"
)

_user_login.add_argument(
  "password",
  type=str,
  required=True,
  help="This field cannot be blank"
)

_user_login.add_argument(
  "service",
  type=str,
  required=True,
  help="This field cannot be blank"
)

class UserLogin(Resource):
  def post(self):
    data = _user_login.parse_args()
    username = data['username']
    password = data['password']
    service = data['service']

    if not username or not password or not service:
      return {
        "message": "Request data is not correct"
      }, 400

    user = UserModel.find_user_by_username(username)
    print(user.id)

    if user and user.password == hashlib.sha256(password.encode("utf-8")).hexdigest() and user.service == service:

      ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
      user_agent = request.headers.get('User-Agent')

      login_history = Login_History(user.id, datetime.datetime.now(), ip, user_agent) 
      login_history.save_to_db()

      access_token = create_access_token(identity=user.id, fresh=True)
      refresh_token = create_refresh_token(identity=user.id)

      return {
        "access_token": access_token,
        "refresh_token": refresh_token
      }, 200

    
    return {
      "message": "Invalid credentials!"
    }, 401



class UserExtension(Resource):
  # @jwt_required
  def put(self, id):
    valid_until = request.json.get('valid_until')

    user = UserModel.find_user_by_id(id)
    if user:
      user.valid_until = valid_until
      user.save_to_db()
      return {
        "message": "Successfully Updated"
      }, 200
    return 'User not found', 404

class UserTermination(Resource):
  def put(self, id):
    user = UserModel.find_user_by_id(id)
    if user:
      user.account_status = "terminated"
      user.save_to_db()
      return {
        "message": "Successfully Terminated"
      }, 200
    return 'User not found', 404


# class PwResetRequest(Resource):
#   def post(self):
#     username = request.json.get('username')
#     email = request.json.get('email')
#     service = request.json.get('service')
#     print(username, email, service)

#     if not username or not email or not service:
#       return {
#         "message": "Request data is not correct!"
#       }, 400
    
#     email_confirmation_data = Email_Settings.query.filter_by(service=service).first()
#     mail.init_app(app, email_confirmation_data)

#     token = generate_confirmation_token(user.email)
#     confirm_url = url_for('pwresetconfirmview', token=token, _external=True)
#     html = render_template('pwresetconfirmation.html', confirm_url=confirm_url)
#     subject = "Password Reset Request"
#     send_email(email, subject, html)

#     return {
#       "message": "Password reset request was sent successfully."
#     }, 200


class TokenRefresh(Resource):
  @jwt_refresh_token_required
  def post(self):
    current_user_id = get_jwt_identity()
    new_token = create_access_token(identity=current_user_id, fresh=False)
    return {
      "access_token": new_token
    }, 200
  
class SecretResource(Resource):
  @jwt_required
  def get(self):
    return {
        'answer': 412
    }

# class PwResetConfirmationView(Resource):
#   def get(self, token):
#     email = confirm_token(token)
#     user = UserModel.query.filter_by(email=email).first()
#     if user:
#       return 'success', 200
#     return 'Invalid confirmation token.', 406


class ConfirmationView(Resource):
  def get(self, token):
    """Check confirmation token."""
    email = confirm_token(token)
    user = UserModel.query.filter_by(email=email).first()
    if user:
        if user.verified:
            return 'Account is already confirmed.', 200
        user.verified = True
        user.save_to_db()
        return 'Account confirmation was successful.', 200
    return 'Invalid confirmation token.', 406