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
from wtforms.validators import InputRequired, Email, Length


class LoginForm(Form):
    username = StringField("Username", [InputRequired(), Length(min=4, max=15)])
    password = PasswordField("Password", [InputRequired(), Length(min=8, max=80)])
    remember = BooleanField("Remember")


class RegisterForm(Form):
    email = StringField("Email", [InputRequired(), Email("Please enter your email address"), Length(max=120)])
    username = StringField("Username", [InputRequired(), Length(min=4, max=25)])
    password = PasswordField("Password", [InputRequired(), Length(min=8, max=80)])
