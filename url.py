from project.resources.user import User, UserLogin, UserRegister, ConfirmationView, SecretResource, TokenRefresh, UserExtension, UserTermination, PasswordReset
from manage import api

api.add_resource(User, "/user/<int:user_id>")
api.add_resource(UserRegister, "/register")
api.add_resource(UserLogin, "/login")
api.add_resource(ConfirmationView, "/confirmation/<token>")
api.add_resource(UserExtension, "/extension/<int:id>")
api.add_resource(UserTermination, "/termination/<int:id>")
api.add_resource(PasswordReset, "/passwordreset/<int:id>")
api.add_resource(SecretResource, '/secret')
api.add_resource(TokenRefresh, '/token/refresh')