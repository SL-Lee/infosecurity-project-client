from wtforms import (
    BooleanField,
    Form,
    PasswordField,
    RadioField,
    SelectField,
    StringField,
    SubmitField,
    FloatField,
    IntegerField,
    TextAreaField,
    FieldList,
    FormField,
    DateField,
    ValidationError
)
from wtforms.validators import InputRequired, Email, Length, Optional
from flask_wtf.file import FileField


def integer_length_check(min=-1, max=-1):
    message = "The length of the integer must be between %d and %d characters." % (min, max)

    def _integer_length_check(form, field):
        l = len(str(field.data))
        if l < min or (max != -1 and l > max):
            raise ValidationError(message)

    return _integer_length_check


class LoginForm(Form):
    username = StringField("Username", [InputRequired(), Length(min=4, max=15)])
    password = PasswordField("Password", [InputRequired(), Length(min=8, max=80)])
    remember = BooleanField("Remember")


class RegisterForm(Form):
    email = StringField("Email", [InputRequired(), Email("Please enter your email address"), Length(max=120)])
    username = StringField("Username", [InputRequired(), Length(min=4, max=25)])
    password = PasswordField("Password", [InputRequired(), Length(min=8, max=80)])


class ReviewForm(Form):
    review_rating = SelectField("Review Rating", [InputRequired()], choices=[("1", "1"), ("2", "2"), ("3", "3"), ("4", "4"), ("5", "5")], default="5", render_kw={"class": "form-control"})
    review_contents = TextAreaField("Review Contents", [Length(max=255)], render_kw={"class": "form-control", "placeholder": "Review contents (255 characters max)"})


class UpdateForm(Form):
    email = StringField("Email", [Email("Please enter your email address"), Length(max=120), Optional()])
    username = StringField("Username", [Length(min=4, max=25), Optional()])
    currentpassword = PasswordField("Current Password", [InputRequired(), Length(min=8, max=80)])
    newpassword = PasswordField("New Password", [Length(min=8, max=80), Optional()])


class AddressForm(Form):
    address = StringField("Address", [Length(max=120), InputRequired()])
    zip_code = IntegerField("Zip Code", [InputRequired(), integer_length_check(max=10)])
    city = StringField("City", [InputRequired(), Length(min=1, max=176)])
    state = StringField("State", [InputRequired(), Length(min=4, max=100)])


class CreditForm(Form):
    cardnumber = IntegerField("Card Number", [InputRequired(), integer_length_check(min=13, max=19)])
    cvv = IntegerField("CVV", [InputRequired(), integer_length_check(min=3, max=4)])
    expiry = DateField("Expiry (mm/yy)", [InputRequired()], format="%m/%y")


class AdminCreateForm(Form):
    email = StringField("Email", [InputRequired(), Email("Please enter your email address"), Length(max=120)])
    username = StringField("Username", [InputRequired(), Length(min=4, max=25)])
    password = PasswordField("Password", [InputRequired(), Length(min=8, max=80)])


class addProductForm(Form):
    productName = StringField('Product Name:', [InputRequired(), Length(max=100)])
    productDescription = TextAreaField('Product Description:', [InputRequired()])
    productPrice = FloatField('Product Price:', [InputRequired()])
    productQuantity = IntegerField('Product Quantity:', [InputRequired()])
    image = FileField('Product Image:', [InputRequired()])
    submit = SubmitField('Save')

class Checkout(Form):
    name = StringField("Name on card")
    cardNum = TextAreaField("Credit Card Number")
    CVV = IntegerField("CVV")
    expiry_month = IntegerField("Expiry Month")
    expiry_year = IntegerField("Expiry Year")
    billing_address = StringField("Billing Address")
    postal_code = IntegerField("Postal Code")


class cartForm(Form):
    productQuantity = FieldList(IntegerField(""), min_entries=1, max_entries=10)
