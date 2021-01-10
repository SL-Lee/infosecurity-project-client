from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_wtf.file import FileAllowed, FileField
from wtforms import (
    BooleanField,
    DateField,
    FieldList,
    FloatField,
    IntegerField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
    ValidationError,
)
from wtforms.validators import Email, InputRequired, Length, Optional

csrf = CSRFProtect()


def integer_length_check(min=-1, max=-1):
    message = (
        "The length of the integer must be between %d and %d characters."
        % (min, max)
    )

    def _integer_length_check(form, field):
        length = len(str(field.data))
        if length < min or (max != -1 and length > max):
            raise ValidationError(message)

    return _integer_length_check


class LoginForm(FlaskForm):
    username = StringField("Username", [InputRequired(), Length(min=4, max=15)])
    password = PasswordField(
        "Password", [InputRequired(), Length(min=8, max=80)]
    )
    remember = BooleanField("Remember")


class RegisterForm(FlaskForm):
    email = StringField(
        "Email",
        [
            InputRequired(),
            Email("Please enter your email address"),
            Length(max=120),
        ],
    )
    username = StringField("Username", [InputRequired(), Length(min=4, max=25)])
    password = PasswordField(
        "Password", [InputRequired(), Length(min=8, max=80)]
    )


class ReviewForm(FlaskForm):
    review_rating = SelectField(
        "Review Rating",
        [InputRequired()],
        choices=[("1", "1"), ("2", "2"), ("3", "3"), ("4", "4"), ("5", "5")],
        default="5",
        render_kw={"class": "form-control"},
    )
    review_contents = TextAreaField(
        "Review Contents",
        [Length(max=255)],
        render_kw={
            "class": "form-control",
            "placeholder": "Review contents (255 characters max)",
        },
    )


class UpdateForm(FlaskForm):
    email = StringField(
        "Email",
        [Email("Please enter your email address"), Length(max=120), Optional()],
    )
    username = StringField("Username", [Length(min=4, max=25), Optional()])
    current_password = PasswordField(
        "Current Password", [InputRequired(), Length(min=8, max=80)]
    )
    new_password = PasswordField(
        "New Password", [Length(min=8, max=80), Optional()]
    )


class AddressForm(FlaskForm):
    address = StringField("Address", [Length(max=120), InputRequired()])
    zip_code = IntegerField(
        "Zip Code", [InputRequired(), integer_length_check(max=10)]
    )
    city = StringField("City", [InputRequired(), Length(min=1, max=176)])
    state = StringField("State", [InputRequired(), Length(min=4, max=100)])


class CreditForm(FlaskForm):
    card_number = IntegerField(
        "Card Number", [InputRequired(), integer_length_check(min=13, max=19)]
    )
    cvv = IntegerField(
        "CVV", [InputRequired(), integer_length_check(min=3, max=4)]
    )
    expiry = DateField("Expiry (mm/yy)", [InputRequired()], format="%m/%y")


class AdminCreateForm(FlaskForm):
    email = StringField(
        "Email",
        [
            InputRequired(),
            Email("Please enter your email address"),
            Length(max=120),
        ],
    )
    username = StringField("Username", [InputRequired(), Length(min=4, max=25)])
    password = PasswordField(
        "Password", [InputRequired(), Length(min=8, max=80)]
    )


class AddProductForm(FlaskForm):
    product_name = StringField(
        "Product Name:", [InputRequired(), Length(max=100)]
    )
    product_description = TextAreaField(
        "Product Description:", [InputRequired()]
    )
    product_price = FloatField("Product Price:", [InputRequired()])
    product_quantity = IntegerField("Product Quantity:", [InputRequired()])
    image = FileField("Product Image:", validators=[FileAllowed("jpg", "png")])
    submit = SubmitField("Save")


class Checkout(FlaskForm):
    credit_card = SelectField("Credit Card")
    address = SelectField("Address")


class CartForm(FlaskForm):
    product_quantity = FieldList(
        IntegerField(""), InputRequired(), min_entries=0, max_entries=10
    )


class ProductQuantity(FlaskForm):
    product_quantity = IntegerField("", default=1)
    submit = SubmitField(label="")
