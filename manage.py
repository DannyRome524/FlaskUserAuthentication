from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager

from project.resources.user import User, UserLogin, UserRegister, ConfirmationView, SecretResource, TokenRefresh, UserExtension, UserTermination, PasswordReset
from project import app

import os

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:''@localhost/user_authentication'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["PROPAGATE_EXCEPTIONS"] = True

app.secret_key = "v3ry_s3cr3t_k3y"

api = Api(app)

jwt = JWTManager(app)


@jwt.expired_token_loader
def expired_token_callback():
    return jsonify(
        {
            "description": "Token has expired!",
            "error": "token_expired"
        }, 401
    )


@jwt.invalid_token_loader
def invalid_token_callback():
    return jsonify(
        {
            "description": "Signature verification failed!",
            "error": "invalid_token"
        }, 401
    )


@jwt.unauthorized_loader
def unauthorized_loader_callback(error):
    return jsonify(
        {
            "description": "Access token not found!",
            "error": "unauthorized_loader"
        }, 401
    )


@jwt.needs_fresh_token_loader
def fresh_token_loader_callback():
    return jsonify(
        {
            "description": "Token is not fresh. Fresh token needed!",
            "error": "needs_fresh_token"
        }, 401
    )


api.add_resource(User, "/user/<int:user_id>")
api.add_resource(UserRegister, "/register")
api.add_resource(UserLogin, "/login")
api.add_resource(ConfirmationView, "/confirmation/<token>")
api.add_resource(UserExtension, "/extension/<int:id>")
api.add_resource(UserTermination, "/termination/<int:id>")
api.add_resource(PasswordReset, "/passwordreset/<int:id>")
api.add_resource(SecretResource, '/secret')
api.add_resource(TokenRefresh, '/token/refresh')


if __name__ == '__main__':
    from project.database.db import db

    db.init_app(app)

    with app.app_context():
        db.create_all()

    app.run(debug=True, port=8000)