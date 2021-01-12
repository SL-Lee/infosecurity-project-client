import datetime
import os
import secrets
import string
from functools import wraps
from urllib.parse import urljoin, urlparse

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from werkzeug.datastructures import CombinedMultiDict
from werkzeug.security import check_password_hash, generate_password_hash

from classes import aes, forms
from classes.forms import csrf
from classes.models import (
    Address,
    CreditCard,
    OrderProduct,
    Orders,
    Product,
    Review,
    User,
    UserRole,
    client_db,
)
from secure_db import SecureDB

app = Flask(__name__)

app.secret_key = os.urandom(16)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///client_db.sqlite3"
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "danger"

client_db.init_app(app)
csrf.init_app(app)

SecureDB.set_api_url("http://localhost:4999/api/database")
SecureDB.set_api_key(os.environ["ISPJ_API_KEY"])


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return (
        test_url.scheme in ("http", "https")
        and ref_url.netloc == test_url.netloc
    )


def restricted(access_level):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            current_user_roles = [i.role.name for i in current_user.roles]

            if access_level == "admin page" and not any(
                i in current_user_roles for i in ["Admin", "Seller", "Staff"]
            ):
                abort(404)
            elif access_level == "admin" and "Admin" not in current_user_roles:
                abort(404)
            elif (
                access_level == "seller" and "Seller" not in current_user_roles
            ):
                abort(404)
            elif access_level == "staff" and "Staff" not in current_user_roles:
                abort(404)
            return func(*args, **kwargs)

        return wrapper

    return decorator


@login_manager.user_loader
def load_user(user_id):
    return SecureDB.retrieve(model="User", filter_=f"User.id == {user_id}")[0]


@app.route("/")
def index():
    products = SecureDB.retrieve(
        model="Product", filter_="Product.product_id > 0"
    )
    return render_template("index.html", products=products)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = forms.LoginForm(request.form)

    if request.method == "POST" and form.validate():
        try:
            user = SecureDB.retrieve(
                model="User",
                filter_=f"User.username == '{form.username.data}'",
            )[0]
        except:
            flash(
                "Incorrect username and/or password. Please try again.",
                "danger",
            )
            return redirect(url_for("login"))

        salt = user.password[-6:]
        salted_password = form.password.data + salt

        if not check_password_hash(user.password[:-6], salted_password):
            flash(
                "Incorrect username and/or password. Please try again.",
                "danger",
            )
            return redirect(url_for("login"))

        redirect_to_profile = False

        with open("PwnedPasswordTop100k.txt", "r", encoding="UTF-8") as file:
            for i in file.read().splitlines():
                if form.password.data == i:
                    flash(
                        "Your password is easily guessable or has been "
                        "compromised in a data breach. Please change your "
                        "password as soon as possible.",
                        "danger",
                    )
                    redirect_to_profile = True

        if not user.status:
            SecureDB.update(
                model="User",
                filter_=f"User.username == '{form.username.data}'",
                values={"status": True},
            )

        login_user(user, remember=form.remember.data)

        if redirect_to_profile:
            return redirect(url_for("profile"))

        next_url = request.args.get("next")

        if next_url is not None and is_safe_url(next_url):
            return redirect(next_url)

        return redirect(url_for("index"))

    return render_template(
        "login.html", form=form, next=request.args.get("next")
    )


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = forms.RegisterForm(request.form)

    if request.method == "POST" and form.validate():
        if not (
            SecureDB.retrieve(
                model="User",
                filter_=f"User.username == '{form.username.data}'",
            )
            or SecureDB.retrieve(
                model="User", filter_=f"User.email == '{form.email.data}'"
            )
        ):
            letters_and_digits = string.ascii_letters + string.digits
            salt = "".join(
                (secrets.choice(letters_and_digits) for i in range(6))
            )
            salted_password = form.password.data + salt
            hashed_password = generate_password_hash(
                salted_password, method="sha256"
            )
            hashed_password_with_salt = hashed_password + salt
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password=hashed_password_with_salt,
                date_created=datetime.datetime.now(),
                status=True,
            )

            created_user = SecureDB.create(model="User", object_=new_user)

            user_role = UserRole(
                user_id=created_user.id,
                role_id=SecureDB.retrieve(
                    model="Role", filter_="Role.name == 'Customer'"
                )[0].id,
                role=SecureDB.retrieve(
                    model="Role", filter_="Role.name == 'Customer'"
                )[0],
            )

            SecureDB.create(model="UserRole", object_=user_role)
            return redirect(url_for("login"))

        return redirect(url_for("signup"))

    return render_template("signup.html", form=form)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    form = forms.UpdateForm(request.form)

    if request.method == "POST" and form.validate():
        salt = current_user.password[-6:]
        salted_password = form.current_password.data + salt

        if check_password_hash(current_user.password[:-6], salted_password):
            if form.email.data != "":
                SecureDB.update(
                    model="User",
                    filter_=f"User.id == {current_user.id}",
                    values={"email": form.email.data},
                )

            if form.username.data != "":
                SecureDB.update(
                    model="User",
                    filter_=f"User.id == {current_user.id}",
                    values={"username": form.username.data},
                )

            if form.new_password.data != "":
                letters_and_digits = string.ascii_letters + string.digits
                salt = "".join(
                    (secrets.choice(letters_and_digits) for i in range(6))
                )
                salted_password = form.new_password.data + salt
                hashed_password = generate_password_hash(
                    salted_password, method="sha256"
                )
                hashed_password_with_salt = hashed_password + salt

                SecureDB.update(
                    model="User",
                    filter_=f"User.id == {current_user.id}",
                    values={"password": hashed_password_with_salt},
                )

            return redirect(url_for("profile"))

    return render_template("profile.html", current_user=current_user, form=form)


@app.route("/orders")
@login_required
def orders():
    return render_template("orders.html", current_user=current_user)


@app.route("/cards")
@login_required
def cards():
    user = SecureDB.retrieve(
        model="User", filter_=f"User.id == {current_user.id}"
    )[0]
    credit_cards = user.credit_cards
    key = aes.get_fixed_key()
    card_list = []

    for credit_card in credit_cards:
        card = aes.decrypt(key, credit_card.card_number, credit_card.iv).decode(
            "utf8"
        )
        card_list.append(card)

    print(card_list)
    return render_template(
        "cards.html",
        current_user=current_user,
        card_list=card_list,
        len=len,
        credit_cards=credit_cards,
    )


@app.route("/cards/add", methods=["GET", "POST"])
@login_required
def add_cards():
    try:
        if request.method == "POST":
            obj = request.json
            cardnum = obj["cardnum"]
            print(cardnum)

            if cardnum.isalpha() or len(cardnum) == 0:
                raise Exception("Integer only")

            key = aes.get_fixed_key()
            card_number, iv = aes.encrypt(key, cardnum.encode("utf8"))
            exp_date = obj["exp_date"]
            print(exp_date)
            year = exp_date[0:4]
            month = exp_date[5:7]
            day = exp_date[8:]
            date = datetime.datetime(int(year), int(month), int(day))

            credit_card = CreditCard(
                user_id=current_user.id,
                card_number=card_number,
                expiry=date,
                iv=iv,
            )
            SecureDB.create(model="CreditCard", object_=credit_card)

            return redirect(url_for("cards"))

        return render_template("add-cards.html", current_user=current_user)
    except:
        flash("An error has occurred", "danger")
        return redirect(url_for("add_cards"))


@app.route("/cards/remove/<int:card_id>", methods=["GET", "POST"])
@login_required
def remove_card(card_id):
    SecureDB.delete(model="CreditCard", filter_=f"CreditCard.id == {card_id}")
    return redirect(url_for("cards"))


@app.route("/cards/update/<int:card_id>", methods=["GET", "POST"])
@login_required
def update_card(card_id):
    try:
        form = forms.CreditForm(request.form)
        key = aes.get_fixed_key()

        try:
            card = SecureDB.retrieve(
                model="CreditCard", filter_=f"CreditCard.id == {card_id}"
            )[0]
        except:
            abort(404)

        credit_card_number = aes.decrypt(key, card.card_number, card.iv).decode(
            "utf8"
        )

        if request.method == "POST":
            obj = request.json
            cardnum = obj["cardnum"]

            if cardnum.isalpha() or len(cardnum) == 0:
                raise Exception("Integer only")

            key = aes.get_fixed_key()
            card_number, iv = aes.encrypt(key, cardnum.encode("utf8"))
            exp_date = obj["exp_date"]
            print(exp_date)
            year = exp_date[0:4]
            month = exp_date[5:7]
            day = exp_date[8:]
            date = datetime.datetime(int(year), int(month), int(day))

            SecureDB.update(
                model="CreditCard",
                filter_=f"CreditCard.id == {card_id}",
                values={
                    "card_number": card_number.hex(),
                    "iv": iv.hex(),
                    "expiry": date.strftime("%Y-%m-%d"),
                },
            )
            return redirect(url_for("cards"))

        return render_template(
            "update-card.html",
            current_user=current_user,
            form=form,
            card=card,
            credit_card_number=credit_card_number,
        )
    except:
        flash("An error has occurred", "danger")
        return redirect(url_for("cards"))


@app.route("/addresses")
@login_required
def addresses():
    return render_template("addresses.html", current_user=current_user)


@app.route("/addresses/add", methods=["GET", "POST"])
@login_required
def add_addresses():
    if request.method == "POST":
        obj = request.json
        address = obj["address"]
        state = obj["state"]
        city = obj["city"]
        zip_code = obj["zipCode"]

        address_object = Address(
            user_id=current_user.id,
            address=address,
            state=state,
            city=city,
            zip_code=int(zip_code),
        )
        SecureDB.create(model="Address", object_=address_object)

        return redirect(url_for("addresses"))

    return render_template("add-addresses.html", current_user=current_user)


@app.route("/addresses/remove/<int:address_id>")
@login_required
def remove_addresses(address_id):
    SecureDB.delete(model="Address", filter_=f"Address.id == {address_id}")
    return redirect(url_for("addresses"))


@app.route("/addresses/update/<int:address_id>", methods=["GET", "POST"])
@login_required
def update_address(address_id):
    form = forms.AddressForm(request.form)

    try:
        address = SecureDB.retrieve(
            model="Address", filter_=f"Address.id == {address_id}"
        )[0]
    except:
        abort(404)

    if request.method == "POST" and form.validate():
        SecureDB.update(
            model="Address",
            filter_=f"Address.id == {address_id}",
            values={
                "address": form.address.data,
                "state": form.state.data,
                "city": form.city.data,
                "zip_code": form.zip_code.data,
            },
        )
        return redirect(url_for("addresses"))

    return render_template(
        "update-address.html",
        current_user=current_user,
        form=form,
        address=address,
    )


@app.route("/profile/delete")
@login_required
def delete_profile():
    SecureDB.update(
        model="User",
        filter_=f"User.id == {current_user.id}",
        values={"status": False},
    )
    logout_user()
    return redirect(url_for("index"))


@app.route("/admin")
@login_required
@restricted(access_level="admin page")
def admin():
    context = {
        "current_user": current_user,
        "users": SecureDB.retrieve(model="User", filter_="User.id > 0"),
        "products": SecureDB.retrieve(
            model="Product", filter_="Product.product_id > 0"
        ),
        "current_user_roles": [i.role.name for i in current_user.roles],
    }
    return render_template("admin.html", **context)


@app.route("/admin/create/user", methods=["GET", "POST"])
@login_required
@restricted(access_level="admin")
def staff_signup():
    form = forms.AdminCreateForm(request.form)

    if request.method == "POST" and form.validate():
        if not (
            SecureDB.retrieve(
                model="User",
                filter_=f"User.username == '{form.username.data}'",
            )
            or SecureDB.retrieve(
                model="User", filter_=f"User.email == '{form.email.data}'"
            )
        ):
            letters_and_digits = string.ascii_letters + string.digits
            salt = "".join(
                (secrets.choice(letters_and_digits) for i in range(6))
            )
            salted_password = form.password.data + salt
            hashed_password = generate_password_hash(
                salted_password, method="sha256"
            )
            hashed_password_with_salt = hashed_password + salt

            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password=hashed_password_with_salt,
                date_created=datetime.datetime.now(),
                status=True,
            )

            created_user = SecureDB.create(model="User", object_=new_user)

            new_user_customer_role = UserRole(
                user_id=created_user.id,
                role_id=SecureDB.retrieve(
                    model="Role", filter_="Role.name == 'Customer'"
                )[0].id,
                role=SecureDB.retrieve(
                    model="Role", filter_="Role.name == 'Customer'"
                )[0],
            )

            new_user_staff_role = UserRole(
                user_id=created_user.id,
                role_id=SecureDB.retrieve(
                    model="Role", filter_="Role.name == 'Staff'"
                )[0].id,
                role=SecureDB.retrieve(
                    model="Role", filter_="Role.name == 'Staff'"
                )[0],
            )

            SecureDB.create(model="UserRole", object_=new_user_customer_role)
            SecureDB.create(model="UserRole", object_=new_user_staff_role)
            return redirect(url_for("admin"))

        return redirect(url_for("staff_signup"))

    return render_template("signup.html", form=form)


@app.route("/admin/delete/<int:user_id>")
@login_required
@restricted(access_level="admin")
def admin_delete(user_id):
    SecureDB.update(
        model="User",
        filter_=f"User.id == {user_id}",
        values={"status": False},
    )
    return redirect(url_for("admin"))


@app.route("/product/<int:product_id>", methods=["GET", "POST"])
def product(product_id):
    form = forms.ReviewForm(request.form)
    product_quantity = forms.ProductQuantity(request.form)

    try:
        product = SecureDB.retrieve(
            model="Product", filter_=f"Product.product_id == {product_id}"
        )[0]

        if product.deleted:
            raise Exception
    except:
        abort(404)

    reviews = sorted(
        SecureDB.retrieve(
            model="Review", filter_=f"Review.product_id == {product_id}"
        ),
        key=lambda x: x.rating,
    )
    reviews = list(
        zip(
            [
                SecureDB.retrieve(
                    model="User", filter_=f"User.id == {review.user_id}"
                )[0].username
                for review in reviews
            ],
            reviews,
        )
    )
    sort_by = request.args.get("sort-by")

    if sort_by != "lowest-rating":
        reviews.reverse()

    user_bought = False

    if current_user.is_authenticated:
        try:
            user_review = SecureDB.retrieve(
                model="Review",
                filter_=(
                    f"(Review.user_id == {current_user.id}) & (Review."
                    f"product_id == {product_id})"
                ),
            )[0]
            user_bought = True
            form.review_rating.data = str(user_review.rating)
            form.review_contents.data = user_review.contents
        except:
            user_review = None
            user_orders = SecureDB.retrieve(
                model="Orders", filter_=f"Orders.user_id == {current_user.id}"
            )

            for i in user_orders:
                break_outer_loop = False

                for j in i.order_product:
                    if j.product_id == product_id:
                        user_bought = True
                        break_outer_loop = True
                        break

                if break_outer_loop:
                    break
    else:
        user_review = None

    if product_quantity.submit.data and product_quantity.validate():
        quantity = product_quantity.product_quantity.data
        return redirect(
            url_for("add_to_cart", product_id=product_id, quantity=quantity)
        )

    return render_template(
        "product.html",
        product=product,
        form=form,
        reviews=reviews,
        user_review=user_review,
        user_bought=user_bought,
        product_quantity=product_quantity,
    )


@app.route("/add-review/<int:product_id>", methods=["POST"])
def add_review(product_id):
    if not current_user.is_authenticated:
        abort(400)

    form = forms.ReviewForm(request.form)

    if form.validate():
        try:
            product = SecureDB.retrieve(
                model="Product", filter_=f"Product.product_id == {product_id}"
            )[0]
        except:
            print("No such product.")
            return redirect(url_for("product", product_id=product_id))

        if SecureDB.retrieve(
            model="Review",
            filter_=(
                f"(Review.user_id == {current_user.id}) & (Review.product_id "
                f"== {product_id})"
            ),
        ):
            print("User already submitted a review for this product.")
            return redirect(url_for("product", product_id=product_id))

        user_orders = SecureDB.retrieve(
            model="Orders", filter_=f"Orders.user_id == {current_user.id}"
        )
        user_bought = False

        for i in user_orders:
            break_outer_loop = False

            for j in i.order_product:
                if j.product_id == product_id:
                    user_bought = True
                    break_outer_loop = True
                    break

            if break_outer_loop:
                break

        if not user_bought:
            print("User haven't bought the product.")
            return redirect(url_for("product", product_id=product_id))

        review = Review(
            user_id=current_user.id,
            product_id=product_id,
            rating=form.review_rating.data,
            contents=form.review_contents.data,
            product=product,
        )
        SecureDB.create(model="Review", object_=review)

        flash("Review added successfully.", "success")
    else:
        flash("There was an error while adding your review.", "danger")

    return redirect(url_for("product", product_id=product_id))


@app.route("/edit-review/<int:product_id>", methods=["POST"])
def edit_review(product_id):
    if not current_user.is_authenticated:
        abort(400)

    form = forms.ReviewForm(request.form)

    if form.validate():
        try:
            SecureDB.update(
                model="Review",
                filter_=(
                    f"(Review.user_id == {current_user.id}) & (Review."
                    f"product_id == {product_id})"
                ),
                values={
                    "rating": form.review_rating.data,
                    "contents": form.review_contents.data,
                },
            )
        except:
            print(
                "No such user and/or product, or user haven't submitted a "
                "review for this product."
            )
            return redirect(url_for("product", product_id=product_id))

        flash("Review edited successfully.", "success")
    else:
        flash("There was an error while editing your review.", "danger")

    return redirect(url_for("product", product_id=product_id))


@app.route("/delete-review/<int:product_id>", methods=["POST"])
def delete_review(product_id):
    if not current_user.is_authenticated:
        abort(400)

    try:
        SecureDB.delete(
            model="Review",
            filter_=(
                f"(Review.user_id == {current_user.id}) & (Review."
                f"product_id == {product_id})"
            ),
        )
    except:
        print(
            "No such user and/or product, or user haven't submitted a review "
            "for this product."
        )
        return redirect(url_for("product", product_id=product_id))

    flash("Review deleted successfully.", "success")
    return redirect(url_for("product", product_id=product_id))


@app.route(
    "/add-to-cart/<int:product_id>/<int:quantity>", methods=["GET", "POST"]
)
def add_to_cart(product_id, quantity):
    try:
        product = SecureDB.retrieve(
            model="Product", filter_=f"Product.product_id == {product_id}"
        )[0]
    except:
        abort(404)

    if quantity > product.quantity or product.quantity == 0:
        flash("There is not enough quantity", "warning")
        return redirect(url_for("index"))

    try:
        cart = session["cart"]
        product = cart[0]
        product = {int(k): int(v) for k, v in product.items()}

        if product_id in product:
            cart_quantity = product[product_id]
            product[product_id] = int(cart_quantity) + int(quantity)
            cart[0] = product
            session["cart"] = cart
            print(cart)
            return redirect(url_for("cart"))
    except:
        print("No other item")
        cart = []
        product = dict()

    product[int(product_id)] = int(quantity)
    print(product)

    if len(cart) == 0:
        cart.append(product)
    else:
        cart[0] = product

    session["cart"] = cart
    return redirect(url_for("cart"))


@app.route("/delete-from-cart/<int:product_id>", methods=["POST", "GET"])
def delete_from_cart(product_id):
    cart = session["cart"]
    product = cart[0]
    print(product)
    print(product_id)

    for i in product:
        print(i)

        if int(i) == int(product_id):
            product.pop(i)
            cart[0] = product
            break

    session["cart"] = cart
    return redirect(url_for("cart"))


@app.route("/cart", methods=["POST", "GET"])
def cart():
    try:
        cart = []
        product = {}
        cart.append(product)

        try:
            cart = session["cart"]
            print(cart)
            product = cart[0]
        except:
            print("No other item")

        product_list = []

        for i in product:
            products = SecureDB.retrieve(
                model="Product", filter_=f"Product.product_id == {i}"
            )[0]
            product_list.append(products)

        cart_form = forms.CartForm(request.form)

        while len(cart_form.product_quantity) != len(cart[0]):
            for i in cart[0]:
                cart_form.product_quantity.append_entry(cart[0][i])

        if request.method == "POST" and cart_form.validate():
            quantity = cart_form.product_quantity.data
            index = 0

            for product_id in product:
                product[product_id] = int(quantity[index])
                index += 1

            cart[0] = product
            session["cart"] = cart
            return redirect(url_for("checkout"))

        return render_template(
            "cart.html", len=len, cart=product_list, form=cart_form
        )
    except:
        flash("An error has occurred")
        return redirect(url_for("index"))


@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    checkout_form = forms.Checkout(request.form)
    user = User.query.filter_by(id=current_user.id).first()
    user = SecureDB.retrieve(
        model="User", filter_=f"User.id == {current_user.id}"
    )[0]
    credit_cards = user.credit_cards
    addresses = user.addresses
    key = aes.get_fixed_key()
    card_list = []

    for credit_card in credit_cards:
        card = aes.decrypt(key, credit_card.card_number, credit_card.iv).decode(
            "utf8"
        )
        card_list.append("Card " + card)

    checkout_form.credit_card.choices = card_list
    address_list = [
        (addresses, "%s" % (addresses[i].address))
        for i in range(len(addresses))
    ]

    checkout_form.address.choices = address_list
    cart = session["cart"]
    products = cart[0]
    product_list = []
    product_quantity = []

    for i in products:
        product = SecureDB.retrieve(
            model="Product", filter_=f"Product.product_id == {i}"
        )[0]
        product_list.append(product)
        product_quantity.append(products[i])

    if request.method == "POST":
        card = ""
        order_product = ""

        for i in credit_cards:
            if str(i) == checkout_form.credit_card.data:
                card = i
                break

        order = Orders(user_id=current_user.id)
        created_order = SecureDB.create(model="Orders", object_=order)

        for i in products:
            product = SecureDB.retrieve(
                model="Product", filter_=f"Product.product_id == {i}"
            )[0]

            if products[i] > product.quantity:
                flash("There is not enough stock", "warning")
                return redirect(url_for("cart"))

        for i in products:
            product = SecureDB.retrieve(
                model="Product", filter_=f"Product.product_id == {i}"
            )[0]

            order_product = OrderProduct(
                order_id=created_order.order_id,
                product_id=product.product_id,
                quantity=products[i],
                product=product,
            )
            SecureDB.create(model="OrderProduct", object_=order_product)
            SecureDB.update(
                model="Product",
                filter_=f"Product.product_id == {i}",
                values={"quantity": product.quantity - products[i]},
            )

        flash("Order successfully added", "success")
        return redirect(url_for("index"))

    return render_template(
        "checkout.html",
        form=checkout_form,
        cart=product_list,
        len=len,
        product_quantity=product_quantity,
    )


@app.route("/products", methods=["GET"])
def get_products():
    return redirect("admin")


@app.route("/products/new", methods=["GET", "POST"])
@login_required
@restricted(access_level="seller")
def add_product():
    form = forms.AddProductForm(
        CombinedMultiDict((request.files, request.form))
    )

    if request.method == "POST" and form.validate():
        if request.files:
            image = request.files[form.image.name]
            print(image)
            image.save(os.path.join("static/images", image.filename))
            print(os.path.join("static/images", image.filename))
            filename = "images/%s" % image.filename

        product = Product(
            product_name=form.product_name.data,
            description=form.product_description.data,
            image=filename,
            price=form.product_price.data,
            quantity=form.product_quantity.data,
            deleted=False,
        )
        created_product = SecureDB.create(model="Product", object_=product)
        flash(f"Product {form.product_name} added successfully", "success")
        return redirect(
            url_for("product", product_id=created_product.product_id)
        )

    return render_template("add-product.html", form=form)


@app.route("/products/<int:product_id>/update", methods=["GET", "POST"])
@login_required
@restricted(access_level="seller")
def update_product(product_id):
    product = SecureDB.retrieve(
        model="Product", filter_=f"Product.product_id == {product_id}"
    )[0]
    form = forms.AddProductForm(
        CombinedMultiDict((request.files, request.form))
    )

    if request.method == "POST" and form.validate():
        SecureDB.update(
            model="Product",
            filter_=f"Product.product_id == {product_id}",
            values={
                "product_name": form.product_name.data,
                "description": form.product_description.data,
                "image": form.image.data,
                "price": form.product_price.data,
                "quantity": form.product_quantity.data,
            },
        )
        flash("This product has been updated!", "success")
        return redirect((url_for("get_products")))

    if request.method == "GET":
        form.product_name.data = product.product_name
        form.product_description.data = product.description
        form.image.data = product.image
        form.product_price.data = product.price
        form.product_quantity.data = product.quantity

    return render_template(
        "add-product.html", legend="Update Product", form=form
    )


@app.route("/products/<int:product_id>/delete", methods=["GET", "POST"])
@login_required
@restricted(access_level="seller")
def delete_product(product_id):
    SecureDB.update(
        model="Product",
        filter_=f"Product.product_id == {product_id}",
        values={"deleted": True},
    )
    flash("Your product has been deleted!", "success")
    return redirect(url_for("get_products"))


@app.route("/search")
def search():
    query = request.args.get("q")

    if query is None:
        search_results = []
    else:
        query = query.strip().lower()
        products = SecureDB.retrieve(
            model="Product", filter_="Product.product_id > 0"
        )
        search_results = [
            i
            for i in products
            if query in i.product_name.lower() and not i.deleted
        ]

    return render_template(
        "search.html", query=query, search_results=search_results
    )


@app.after_request
def add_header(response):
    response.headers[
        "Strict-Transport-Security"
    ] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0")
