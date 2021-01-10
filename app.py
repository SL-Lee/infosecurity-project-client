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
    Role,
    User,
    db,
)

app = Flask(__name__)

app.secret_key = os.urandom(16)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "danger"

db.init_app(app)
csrf.init_app(app)

with app.app_context():
    db.create_all()

    if db.session.query(Role).count() == 0:
        admin_role = Role(
            name="Admin", description="This is the master admin account"
        )
        seller_role = Role(
            name="Seller",
            description=(
                "This is a seller account, it manages all product listings"
            ),
        )
        staff_role = Role(
            name="Staff",
            description=(
                "This is the staff account, it manages the reviews of the "
                "products"
            ),
        )
        customer_role = Role(
            name="Customer", description="This is a customer account"
        )

        def generate_salted_password_hash(password):
            letters_and_digits = string.ascii_letters + string.digits
            salt = "".join(
                (secrets.choice(letters_and_digits) for i in range(6))
            )
            salted_password = password + salt
            hashed_password = generate_password_hash(
                salted_password, method="sha256"
            )
            hashed_password_with_salt = hashed_password + salt
            return hashed_password_with_salt

        def generate_creditcard(card_number, expiry, user_id):
            user = User.query.filter_by(id=user_id).first_or_404()
            key = aes.get_fixed_key()
            card_number = str(card_number)
            card_number, iv = aes.encrypt(key, card_number.encode("utf8"))
            year = expiry[0:4]
            month = expiry[5:7]
            day = expiry[8:]
            date = datetime.datetime(int(year), int(month), int(day))
            user.credit_cards.append(
                CreditCard(card_number=card_number, expiry=date, iv=iv)
            )

        admin_user = User(
            username="admin",
            email="admin@example.com",
            password=generate_salted_password_hash("password"),
            date_created=datetime.datetime.now(),
            status=True,
        )
        seller_user = User(
            username="seller",
            email="seller@example.com",
            password=generate_salted_password_hash("password"),
            date_created=datetime.datetime.now(),
            status=True,
        )
        staff_user = User(
            username="staff",
            email="staff@example.com",
            password=generate_salted_password_hash("password"),
            date_created=datetime.datetime.now(),
            status=True,
        )
        customer_user = User(
            username="customer",
            email="customer@example.com",
            password=generate_salted_password_hash("password"),
            date_created=datetime.datetime.now(),
            status=True,
        )

        admin_user.roles.append(customer_role)
        admin_user.roles.append(seller_role)
        admin_user.roles.append(staff_role)
        admin_user.roles.append(admin_role)

        seller_user.roles.append(customer_role)
        seller_user.roles.append(seller_role)

        staff_user.roles.append(customer_role)
        staff_user.roles.append(staff_role)

        customer_user.roles.append(customer_role)

        db.session.add(admin_role)
        db.session.add(seller_role)
        db.session.add(staff_role)
        db.session.add(customer_role)
        db.session.add(admin_user)
        db.session.add(seller_user)
        db.session.add(staff_user)
        db.session.add(customer_user)

        db.session.add(
            Address(
                address="1377 Ridge Road",
                zip_code=67065,
                city="Isabel",
                state="Kansas",
                user_id=3,
            )
        )
        db.session.add(
            Address(
                address="2337 Millbrook Road",
                zip_code=60607,
                city="Chicago",
                state="Illinois",
                user_id=1,
            )
        )
        db.session.add(
            Address(
                address="4530 Freedom Lane",
                zip_code=95202,
                city="Stockton",
                state="California",
                user_id=2,
            )
        )
        db.session.add(
            Address(
                address="1053 Evergreen Lane",
                zip_code=92614,
                city="Irvine",
                state="California",
                user_id=4,
            )
        )

        generate_creditcard(4485940457238817, "2023-02-28", 1)
        generate_creditcard(7072719230673648, "2022-07-31", 1)
        generate_creditcard(4744367722519153, "2024-01-31", 2)
        generate_creditcard(7105735512242654, "2020-09-30", 3)
        generate_creditcard(6018736652340095, "2024-05-31", 4)
        generate_creditcard(2872570074384908, "2020-07-21", 1)

        db.session.add(
            Product(
                product_name="Carmen Shopper",
                description=(
                    "1 Adjustable & Detachable Crossbody Strap, 2 Handles"
                ),
                image="images/ZB7938001_main.jpg",
                price=218,
                quantity=120,
                deleted=False,
            )
        )
        db.session.add(
            Product(
                product_name="Rachel Tote",
                description="2 Handles",
                image="images/ZB7507200_main.jpg",
                price=198,
                quantity=250,
                deleted=False,
            )
        )
        db.session.add(
            Product(
                product_name="Fiona Crossbody",
                description="1 Adjustable & Detachable Crossbody Strap",
                image="images/ZB7669200_main.jpg",
                price=148,
                quantity=150,
                deleted=False,
            )
        )
        db.session.add(
            Product(
                product_name="Maya Hobo",
                description=(
                    "1 Adjustable & Detachable Crossbody Strap, 1 Short "
                    "Shoulder Strap"
                ),
                image="images/ZB6979200_main.jpg",
                price=238,
                quantity=200,
                deleted=False,
            )
        )

        db.session.add(
            Review(
                user_id=1,
                product_id=1,
                rating=5,
                contents="I love this product!",
            )
        )

        db.session.add(Orders(user_id=1))
        db.session.add(Orders(user_id=3))
        db.session.add(Orders(user_id=3))
        db.session.add(Orders(user_id=2))

        db.session.add(OrderProduct(order_id=1, product_id=1, quantity=2))
        db.session.add(OrderProduct(order_id=1, product_id=3, quantity=1))
        db.session.add(OrderProduct(order_id=2, product_id=1, quantity=4))
        db.session.add(OrderProduct(order_id=2, product_id=3, quantity=2))
        db.session.add(OrderProduct(order_id=3, product_id=2, quantity=1))
        db.session.add(OrderProduct(order_id=4, product_id=1, quantity=1))
        db.session.add(OrderProduct(order_id=4, product_id=4, quantity=1))
        db.session.commit()


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
            current_user_roles = [i.name for i in current_user.roles]

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
    return User.query.get(int(user_id))


@app.route("/")
def index():
    products = Product.query.all()
    return render_template("index.html", products=products)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = forms.LoginForm(request.form)

    if db.session.query(User).count() != 0:
        if request.method == "POST" and form.validate():
            user = User.query.filter_by(username=form.username.data).first()

            if not user:
                flash(
                    "Incorrect username and/or password. Please try again.",
                    "danger",
                )
                return redirect(url_for("login"))

            salt = user.password[-6:]
            salted_password = form.password.data + salt

            if check_password_hash(user.password[:-6], salted_password):
                redirect_to_profile = False

                with open(
                    "PwnedPasswordTop100k.txt", "r", encoding="UTF-8"
                ) as file:
                    for i in file.read().splitlines():
                        if form.password.data == i:
                            flash(
                                "Your password is easily guessable or has "
                                "been compromised in a data breach. Please "
                                "change your password as soon as possible.",
                                "danger",
                            )
                            redirect_to_profile = True

                if not user.status:
                    user.status = True
                    db.session.commit()

                login_user(user, remember=form.remember.data)

                if redirect_to_profile:
                    return redirect(url_for("profile"))
            else:
                flash(
                    "Incorrect username and/or password. Please try again.",
                    "danger",
                )
                return redirect(url_for("login"))

            next_url = request.args.get("next")

            if next_url is not None and is_safe_url(next_url):
                return redirect(next_url)

            return redirect(url_for("index"))
    else:
        return redirect(url_for("signup"))

    return render_template(
        "login.html", form=form, next=request.args.get("next")
    )


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = forms.RegisterForm(request.form)

    if request.method == "POST" and form.validate():
        if (
            User.query.filter_by(username=form.username.data).scalar() is None
            and User.query.filter_by(email=form.email.data).scalar() is None
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
            )

            new_user.roles.append(Role.query.filter_by(name="Customer").first())
            db.session.add(new_user)
            db.session.commit()
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
            user = User.query.filter_by(id=current_user.id).first_or_404()

            if form.email.data != "":
                user.email = form.email.data

            if form.username.data != "":
                user.username = form.username.data

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

                user.password = hashed_password_with_salt

            db.session.commit()
            return redirect(url_for("profile"))

    return render_template("profile.html", current_user=current_user, form=form)


@app.route("/orders")
@login_required
def orders():
    return render_template("orders.html", current_user=current_user)


@app.route("/cards")
@login_required
def cards():
    user = User.query.filter_by(id=current_user.id).first()
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
        user = User.query.filter_by(id=current_user.id).first_or_404()

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
            user.credit_cards.append(
                CreditCard(card_number=card_number, expiry=date, iv=iv)
            )
            db.session.commit()
            return redirect(url_for("cards"))

        return render_template("add-cards.html", current_user=current_user)
    except:
        flash("An error has occurred", "danger")
        return redirect(url_for("add_cards"))


@app.route("/cards/remove/<int:card_id>", methods=["GET", "POST"])
@login_required
def remove_card(card_id):
    user = User.query.filter_by(id=current_user.id).first_or_404()
    removed = CreditCard.query.filter_by(id=card_id).first_or_404()
    user.credit_cards.remove(removed)
    db.session.commit()
    return redirect(url_for("cards"))


@app.route("/cards/update/<int:card_id>", methods=["GET", "POST"])
@login_required
def update_card(card_id):
    try:
        form = forms.CreditForm(request.form)
        key = aes.get_fixed_key()
        card = CreditCard.query.filter_by(id=card_id).first_or_404()
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
            card.card_number = card_number
            card.iv = iv
            card.expiry = date
            db.session.commit()
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
    user = User.query.filter_by(id=current_user.id).first_or_404()

    if request.method == "POST":
        obj = request.json
        address = obj["address"]
        state = obj["state"]
        city = obj["city"]
        zip_code = obj["zipCode"]
        user.addresses.append(
            Address(
                address=address, state=state, city=city, zip_code=int(zip_code)
            )
        )
        db.session.commit()
        return redirect(url_for("addresses"))

    return render_template("add-addresses.html", current_user=current_user)


@app.route("/addresses/remove/<int:address_id>")
@login_required
def remove_addresses(address_id):
    user = User.query.filter_by(id=current_user.id).first_or_404()
    removed = Address.query.filter_by(id=address_id).first_or_404()
    user.addresses.remove(removed)
    db.session.commit()
    return redirect(url_for("addresses"))


@app.route("/addresses/update/<int:address_id>", methods=["GET", "POST"])
@login_required
def update_address(address_id):
    form = forms.AddressForm(request.form)
    address = Address.query.filter_by(id=address_id).first_or_404()

    if request.method == "POST" and form.validate():
        address.address = form.address.data
        address.state = form.state.data
        address.city = form.city.data
        address.zip_code = form.zip_code.data
        db.session.commit()
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
    deleted_user = User.query.filter_by(id=current_user.id).first_or_404()
    logout_user()
    deleted_user.status = False
    db.session.commit()
    return redirect(url_for("index"))


@app.route("/admin")
@login_required
@restricted(access_level="admin page")
def admin():
    context = {
        "current_user": current_user,
        "users": User.query.order_by(User.id).all(),
        "products": Product.query.order_by(Product.product_id).all(),
        "current_user_roles": [i.name for i in current_user.roles],
    }
    return render_template("admin.html", **context)


@app.route("/admin/create/user", methods=["GET", "POST"])
@login_required
@restricted(access_level="admin")
def staff_signup():
    form = forms.AdminCreateForm(request.form)

    if request.method == "POST" and form.validate():
        if (
            User.query.filter_by(username=form.username.data).scalar() is None
            and User.query.filter_by(email=form.email.data).scalar() is None
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
            )

            new_user.roles.append(Role.query.filter_by(name="Customer").first())
            new_user.roles.append(Role.query.filter_by(name="Staff").first())
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for("admin"))

        return redirect(url_for("staff_signup"))

    return render_template("signup.html", form=form)


@app.route("/admin/delete/<int:user_id>")
@login_required
@restricted(access_level="admin")
def admin_delete(user_id):
    deleted_user = User.query.filter_by(id=user_id).first_or_404()
    deleted_user.status = False
    db.session.commit()
    return redirect(url_for("admin"))


@app.route("/product/<int:product_id>", methods=["GET", "POST"])
def product(product_id):
    form = forms.ReviewForm(request.form)
    product_quantity = forms.ProductQuantity(request.form)
    product = Product.query.filter_by(product_id=product_id).first_or_404()
    reviews = (
        Review.query.filter_by(product_id=product_id)
        .order_by(Review.rating)
        .all()
    )
    sort_by = request.args.get("sort-by")

    if sort_by != "lowest-rating":
        reviews.reverse()

    user_bought = False

    if current_user.is_authenticated:
        user_review = Review.query.filter_by(
            user_id=current_user.id, product_id=product_id
        ).first()

        if user_review is None:
            user_orders = Orders.query.filter_by(user_id=current_user.id).all()

            if user_orders is not None:
                for i in user_orders:
                    break_outer_loop = False

                    for j in i.order_product:
                        if j.product == product:
                            user_bought = True
                            break_outer_loop = True
                            break

                    if break_outer_loop:
                        break
        else:
            user_bought = True
            form.review_rating.data = str(user_review.rating)
            form.review_contents.data = user_review.contents
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
        user = User.query.filter_by(id=current_user.id).first()
        product = Product.query.filter_by(product_id=product_id).first()

        if None in [user, product]:
            print("No such user and/or product.")
            return redirect(url_for("product", product_id=product_id))

        review = Review.query.filter_by(
            user_id=current_user.id, product_id=product_id
        ).first()

        if review is not None:
            print("User already submitted a review for this product.")
            return redirect(url_for("product", product_id=product_id))

        user_orders = Orders.query.filter_by(user_id=current_user.id).all()
        user_bought = False

        if user_orders is not None:
            for i in user_orders:
                break_outer_loop = False

                for j in i.order_product:
                    if j.product == product:
                        user_bought = True
                        break_outer_loop = True
                        break

                if break_outer_loop:
                    break

        if not user_bought:
            print("User haven't bought the product.")
            return redirect(url_for("product", product_id=product_id))

        review = Review(
            rating=form.review_rating.data, contents=form.review_contents.data
        )
        review.product = product
        user.reviews.append(review)
        db.session.add(review)
        db.session.commit()
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
        review = Review.query.filter_by(
            user_id=current_user.id, product_id=product_id
        ).first()

        if review is None:
            print(
                "No such user and/or product, or user haven't submitted a "
                "review for this product."
            )
            return redirect(url_for("product", product_id=product_id))

        review.rating = form.review_rating.data
        review.contents = form.review_contents.data
        db.session.commit()
        flash("Review edited successfully.", "success")
    else:
        flash("There was an error while editing your review.", "danger")

    return redirect(url_for("product", product_id=product_id))


@app.route("/delete-review/<int:product_id>", methods=["POST"])
def delete_review(product_id):
    if not current_user.is_authenticated:
        abort(400)

    review = Review.query.filter_by(
        user_id=current_user.id, product_id=product_id
    ).first()

    if review is None:
        print(
            "No such user and/or product, or user haven't submitted a review "
            "for this product."
        )
        return redirect(url_for("product", product_id=product_id))

    db.session.delete(review)
    db.session.commit()
    flash("Review deleted successfully.", "success")
    return redirect(url_for("product", product_id=product_id))


@app.route(
    "/add-to-cart/<int:product_id>/<int:quantity>", methods=["GET", "POST"]
)
def add_to_cart(product_id, quantity):
    product = Product.query.filter_by(product_id=product_id).first_or_404()

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
            products = Product.query.filter_by(product_id=i).first()
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
        product = Product.query.filter_by(product_id=i).first()
        product_list.append(product)
        product_quantity.append(products[i])

    if request.method == "POST":
        card = ""
        # address1 = ""
        order_product = ""

        for i in credit_cards:
            if str(i) == checkout_form.credit_card.data:
                card = i
                break

        # for i in addresses:
        #     if str(i) == checkout_form.address.data:
        #         address1 = i
        #         break

        # cardNum = card.card_number
        # CVV = card.cvv
        # expiry = card.expiry
        # address = address1.address
        # city = address1.city
        # state = address1.state
        # zip_code = address1.zip_code
        order = Orders()

        for i in products:
            product = Product.query.filter_by(product_id=i).first()
            if products[i] > product.quantity:
                flash("There is not enough stock", "warning")
                return redirect(url_for("cart"))

        for i in products:
            product = Product.query.filter_by(product_id=i).first()
            order_product = OrderProduct(quantity=products[i])
            order_product.product = product
            order.order_product.append(order_product)
            product.quantity -= products[i]
            db.session.commit()

        user.orders.append(order)

        db.session.add(order)
        db.session.add(order_product)
        db.session.commit()

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
        )
        db.session.add(product)
        db.session.commit()
        flash(f"Product {form.product_name} added successfully", "success")
        return redirect(url_for("product", product_id=product.product_id))

    return render_template("add-product.html", form=form)


@app.route("/products/<int:product_id>/update", methods=["GET", "POST"])
@login_required
@restricted(access_level="seller")
def update_product(product_id):
    products = Product.query.get(product_id)
    form = forms.AddProductForm(
        CombinedMultiDict((request.files, request.form))
    )

    if request.method == "POST" and form.validate():
        products.product_name = form.product_name.data
        products.description = form.product_description.data
        product.image = form.image.data
        products.price = form.product_price.data
        products.quantity = form.product_quantity.data
        db.session.commit()
        flash("This product has been updated!", "success")
        return redirect((url_for("get_products")))

    if request.method == "GET":
        form.product_name.data = products.product_name
        form.product_description.data = products.description
        form.image.data = products.image
        form.product_price.data = products.price
        form.product_quantity.data = products.quantity

    return render_template(
        "add-product.html", legend="Update Product", form=form
    )


@app.route("/products/<int:product_id>/delete", methods=["GET", "POST"])
@login_required
@restricted(access_level="seller")
def delete_product(product_id):
    products = Product.query.filter_by(product_id=product_id).first()
    products.deleted = True
    db.session.commit()
    flash("Your product has been deleted!", "success")
    return redirect(url_for("get_products"))


@app.route("/search")
def search():
    query = request.args.get("q")

    if query is None:
        search_results = []
    else:
        query = query.strip().lower()
        search_results = [
            i for i in Product.query.all() if query in i.product_name.lower()
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
    app.run()
