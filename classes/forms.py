from wtforms import (
    BooleanField,
    Form,
    PasswordField,
    RadioField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField
)
from wtforms.validators import InputRequired, Email, Length, Optional


class LoginForm(Form):
    username = StringField("Username", [InputRequired(), Length(min=4, max=15)])
    password = PasswordField("Password", [InputRequired(), Length(min=8, max=80)])
    remember = BooleanField("Remember")


class RegisterForm(Form):
    email = StringField("Email", [InputRequired(), Email("Please enter your email address"), Length(max=120)])
    username = StringField("Username", [InputRequired(), Length(min=4, max=25)])
    password = PasswordField("Password", [InputRequired(), Length(min=8, max=80)])


class UpdateForm(Form):
    email = StringField("Email", [Email("Please enter your email address"), Length(max=120), Optional()])
    username = StringField("Username", [Length(min=4, max=25), Optional()])
    currentpassword = PasswordField("Current Password", [InputRequired(), Length(min=8, max=80)])
    newpassword = PasswordField("New Password", [Length(min=8, max=80), Optional()])


class AdminCreateForm(Form):
    email = StringField("Email", [InputRequired(), Email("Please enter your email address"), Length(max=120)])
    username = StringField("Username", [InputRequired(), Length(min=4, max=25)])
    password = PasswordField("Password", [InputRequired(), Length(min=8, max=80)])
