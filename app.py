import datetime, string, secrets
from flask import (
    abort,
    flash,
    Flask,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
    jsonify,
    session
)
from flask_login import (
    current_user,
    login_required,
    login_user,
    LoginManager,
    logout_user
)
from classes import forms, MyAes
from classes.forms import csrf
from classes.models import (
    db,
    User,
    Role,
    Product,
    Review,
    Orders,
    Orderproduct,
    CreditCard,
    Address
)
import json
from urllib.parse import urlparse, urljoin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.datastructures import CombinedMultiDict
from functools import wraps
import os


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
        admin_role = Role(name="Admin", description="This is the master admin account")
        seller_role = Role(name="Seller", description="This is a seller account, it manages all product listings")
        staff_role = Role(name="Staff", description="This is the staff account, it manages the reviews of the products")
        customer_role = Role(name="Customer", description="This is a customer account")

        def generate_saltpasswordhash(password):
            letters_and_digits = string.ascii_letters + string.digits
            salt = ''.join((secrets.choice(letters_and_digits) for i in range(6)))
            saltPassword = password + salt
            hashedPassword = generate_password_hash(saltPassword, method="sha256")
            saltedHashPassword = hashedPassword + salt

            return saltedHashPassword

        def generate_creditcard(cardnumber, expiry, user_id):
            user = User.query.filter_by(id=user_id).first_or_404()
            key = MyAes.get_fixed_key()
            cardnumber = str(cardnumber)
            cardnumber, iv = MyAes.encrypt(key, cardnumber.encode("utf8"))
            year = expiry[0:4]
            month = expiry[5:7]
            day = expiry[8:]
            date = datetime.datetime(int(year), int(month), int(day))
            user.creditcards.append(CreditCard(cardnumber=cardnumber, expiry=date, iv=iv))

        admin = User(username="admin", email="admin@example.com", password=generate_saltpasswordhash("password"), date_created=datetime.datetime.now(), status=True)
        seller = User(username="seller", email="seller@example.com", password=generate_saltpasswordhash("password"), date_created=datetime.datetime.now(), status=True)
        staff = User(username="staff", email="staff@example.com", password=generate_saltpasswordhash("password"), date_created=datetime.datetime.now(), status=True)
        customer = User(username="customer", email="customer@example.com", password=generate_saltpasswordhash("password"), date_created=datetime.datetime.now(), status=True)

        admin.roles.append(customer_role)
        admin.roles.append(seller_role)
        admin.roles.append(staff_role)
        admin.roles.append(admin_role)

        seller.roles.append(customer_role)
        seller.roles.append(seller_role)

        staff.roles.append(customer_role)
        staff.roles.append(staff_role)

        customer.roles.append(customer_role)

        db.session.add(admin_role)
        db.session.add(seller_role)
        db.session.add(staff_role)
        db.session.add(customer_role)
        db.session.add(admin)
        db.session.add(seller)
        db.session.add(staff)
        db.session.add(customer)

        db.session.add(Address(address="1377 Ridge Road", zip_code=67065, city="Isabel", state="Kansas", user_id=3))
        db.session.add(Address(address="2337 Millbrook Road", zip_code=60607, city="Chicago", state="Illinois", user_id=1))
        db.session.add(Address(address="4530 Freedom Lane", zip_code=95202, city="Stockton", state="California", user_id=2))
        db.session.add(Address(address="1053 Evergreen Lane", zip_code=92614, city="Irvine", state="California", user_id=4))


        generate_creditcard(4485940457238817, "2023-02-28", 1)
        generate_creditcard(7072719230673648, "2022-07-31", 1)
        generate_creditcard(4744367722519153, "2024-01-31", 2)
        generate_creditcard(7105735512242654, "2020-09-30", 3)
        generate_creditcard(6018736652340095, "2024-05-31", 4)
        generate_creditcard(2872570074384908, "2020-07-21", 1)


        db.session.add(Product(product_name="Carmen Shopper", description="1 Adjustable & Detachable Crossbody Strap, 2 Handles", image="images/ZB7938001_main.jpg", price=218, quantity=120, deleted=False))
        db.session.add(Product(product_name="Rachel Tote", description="2 Handles", image="images/ZB7507200_main.jpg", price=198, quantity=250, deleted=False))
        db.session.add(Product(product_name="Fiona Crossbody", description="1 Adjustable & Detachable Crossbody Strap", image="images/ZB7669200_main.jpg", price=148, quantity=150, deleted=False))
        db.session.add(Product(product_name="Maya Hobo", description="1 Adjustable & Detachable Crossbody Strap, 1 Short Shoulder Strap", image="images/ZB6979200_main.jpg", price=238, quantity=200, deleted=False))

        db.session.add(Review(user_id=1, product_id=1, rating=5, contents="I love this product!"))

        db.session.add(Orders(user_id=1))
        db.session.add(Orders(user_id=3))
        db.session.add(Orders(user_id=3))
        db.session.add(Orders(user_id=2))

        db.session.add(Orderproduct(order_id=1, product_id=1, quantity=2))
        db.session.add(Orderproduct(order_id=1, product_id=3, quantity=1))
        db.session.add(Orderproduct(order_id=2, product_id=1, quantity=4))
        db.session.add(Orderproduct(order_id=2, product_id=3, quantity=2))
        db.session.add(Orderproduct(order_id=3, product_id=2, quantity=1))
        db.session.add(Orderproduct(order_id=4, product_id=1, quantity=1))
        db.session.add(Orderproduct(order_id=4, product_id=4, quantity=1))
        db.session.commit()


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


def restricted(access_level):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            current_user_roles = [i.name for i in current_user.roles]
            if access_level == "admin page" and not any(i in current_user_roles for i in ["Admin", "Seller", "Staff"]):
                abort(404)
            elif access_level == "admin" and "Admin" not in current_user_roles:
                abort(404)
            elif access_level == "seller" and "Seller" not in current_user_roles:
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
            user = User.query.filter_by(username=form.username.data).first_or_404()
            if user:
                print(user.username)
                salt = user.password[-6:]
                saltPassword = form.password.data + salt
                if check_password_hash(user.password[:-6], saltPassword):
                    if user.status == False:
                        user.status = True
                        db.session.commit()
                    login_user(user, remember=form.remember.data)

                next_url = request.args.get("next")
                if next_url is not None and is_safe_url(next_url):
                    return redirect(next_url)

                return redirect(url_for("index"))
            else:
                flash("Username/Password is incorrect, please try again", category="danger")
                return redirect(url_for("login"))
    else:
        return redirect(url_for("signup"))
    return render_template("login.html", form=form, next=request.args.get("next"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = forms.RegisterForm(request.form)
    if request.method == "POST" and form.validate():
        if User.query.filter_by(username=form.username.data).scalar() is None and User.query.filter_by(email=form.email.data).scalar() is None:

            letters_and_digits = string.ascii_letters + string.digits
            salt = ''.join((secrets.choice(letters_and_digits) for i in range(6)))
            saltPassword = form.password.data + salt
            hashedPassword = generate_password_hash(saltPassword, method="sha256")
            saltedHashPassword = hashedPassword + salt
            newUser = User(username=form.username.data, email=form.email.data, password=saltedHashPassword)

            newUser.roles.append(Role.query.filter_by(name="Customer").first())
            db.session.add(newUser)
            db.session.commit()
            return redirect(url_for("login"))
        else:
            return redirect(url_for("signup"))
    return render_template("signup.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    form = forms.UpdateForm(request.form)
    if request.method == "POST" and form.validate():
        if check_password_hash(current_user.password, form.currentpassword.data):
            user = User.query.filter_by(id=current_user.id).first_or_404()
            if form.email.data != "":
                user.email = form.email.data
            if form.username.data != "":
                user.username = form.username.data
            if form.newpassword.data != "":
                hashedPassword = generate_password_hash(form.newpassword.data, method="sha256")
                user.password = hashedPassword
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
    creditcards = user.creditcards
    key = MyAes.get_fixed_key()
    cardlist = []
    for i in range(len(creditcards)):
        card = MyAes.decrypt(key, creditcards[i].cardnumber, creditcards[i].iv).decode("utf8")
        cardlist.append(card)
    print(cardlist)
    return render_template("cards.html", current_user=current_user, cardlist=cardlist, len=len, creditcards=creditcards)


@app.route("/cards/add", methods=["GET", "POST"])
@login_required
def addcards():
    try:
        user = User.query.filter_by(id=current_user.id).first_or_404()
        if request.method == "POST":
            obj = request.json
            cardnum = obj["cardnum"]
            print(cardnum)
            if cardnum.isalpha() or len(cardnum) == 0:
                raise Exception("Integer only")
            key = MyAes.get_fixed_key()
            cardnumber, iv = MyAes.encrypt(key, cardnum.encode("utf8"))
            exp_date = obj["exp_date"]
            print(exp_date)
            year = exp_date[0:4]
            month = exp_date[5:7]
            day = exp_date[8:]
            date = datetime.datetime(int(year), int(month), int(day))
            user.creditcards.append(CreditCard(cardnumber=cardnumber, expiry=date, iv=iv))
            db.session.commit()
            return redirect(url_for("cards"))

        return render_template("addcards.html", current_user=current_user)
    except:
        flash("An error has occurred", "danger")
        return redirect(url_for("addcards"))


@app.route("/cards/remove/<int:card_id>", methods=["GET", "POST"])
@login_required
def removecard(card_id):
    user = User.query.filter_by(id=current_user.id).first_or_404()
    removed = CreditCard.query.filter_by(id=card_id).first_or_404()
    user.creditcards.remove(removed)
    db.session.commit()
    return redirect(url_for("cards"))


@app.route("/cards/update/<int:card_id>", methods=["GET", "POST"])
@login_required
def updatecard(card_id):
    try:
        form = forms.CreditForm(request.form)
        key = MyAes.get_fixed_key()
        card = CreditCard.query.filter_by(id=card_id).first_or_404()
        creditcardnum = MyAes.decrypt(key, card.cardnumber, card.iv).decode("utf8")
        if request.method == "POST":
            obj = request.json
            cardnum = obj["cardnum"]
            if cardnum.isalpha() or len(cardnum) == 0:
                raise Exception("Integer only")
            key = MyAes.get_fixed_key()
            cardnumber, iv = MyAes.encrypt(key, cardnum.encode("utf8"))
            exp_date = obj["exp_date"]
            print(exp_date)
            year = exp_date[0:4]
            month = exp_date[5:7]
            day = exp_date[8:]
            date = datetime.datetime(int(year), int(month), int(day))
            card.cardnumber = cardnumber
            card.iv = iv
            card.expiry = date
            db.session.commit()
            return redirect(url_for("cards"))
        return render_template("updatecard.html", current_user=current_user, form=form, card=card, creditcardnum=creditcardnum)
    except:
        flash("An error has occurred", "danger")
        return redirect(url_for("cards"))

@app.route("/addresses")
@login_required
def addresses():
    return render_template("addresses.html", current_user=current_user)


@app.route("/addresses/add", methods=["GET", "POST"])
@login_required
def addaddresses():
    user = User.query.filter_by(id=current_user.id).first_or_404()
    if request.method == "POST":
        obj = request.json
        address = obj["address"]
        state = obj["state"]
        city = obj["city"]
        zipCode = obj["zipCode"]
        user.addresses.append(Address(address=address, state=state, city=city, zip_code=int(zipCode)))
        db.session.commit()
        return redirect(url_for("addresses"))

    return render_template("addaddresses.html", current_user=current_user)

@app.route("/addresses/remove/<int:addresse_id>")
@login_required
def removeaddresses(addresse_id):
    user = User.query.filter_by(id=current_user.id).first_or_404()
    removed = Address.query.filter_by(id=addresse_id).first_or_404()
    user.addresses.remove(removed)
    db.session.commit()
    return redirect(url_for("addresses"))


@app.route("/addresses/update/<int:address_id>", methods=["GET", "POST"])
@login_required
def updateaddress(address_id):
    form = forms.AddressForm(request.form)
    address = Address.query.filter_by(id=address_id).first_or_404()
    if request.method == "POST" and form.validate():
        address.address = form.address.data
        address.state = form.state.data
        address.city = form.city.data
        address.zip_code = form.zip_code.data
        db.session.commit()
        return redirect(url_for("addresses"))
    return render_template("updateaddress.html", current_user=current_user, form=form, address=address)


@app.route("/profile/delete")
@login_required
def deleteprofile():
    deletedUser = User.query.filter_by(id=current_user.id).first_or_404()
    logout_user()
    deletedUser.status = False
    db.session.commit()
    return redirect(url_for("index"))


@app.route("/admin")
@login_required
@restricted(access_level="admin page")
def admin():
    context = {
        "current_user": current_user,
        "users": User.query.order_by(User.id).all(),
        "products": Product.query.order_by(Product.productid).all(),
        "current_user_roles": [i.name for i in current_user.roles]
    }
    return render_template("admin.html", **context)


@app.route("/admin/create/user", methods=["GET", "POST"])
@login_required
@restricted(access_level="admin")
def staffsignup():
    form = forms.AdminCreateForm(request.form)
    if request.method == "POST" and form.validate():
        if User.query.filter_by(username=form.username.data).scalar() is None and User.query.filter_by(email=form.email.data).scalar() is None:
            hashedPassword = generate_password_hash(form.password.data, method="sha256")
            newUser = User(username=form.username.data, email=form.email.data, password=hashedPassword)
            newUser.roles.append(Role.query.filter_by(name="Customer").first())
            newUser.roles.append(Role.query.filter_by(name="Staff").first())
            db.session.add(newUser)
            db.session.commit()
            return redirect(url_for("admin"))
        else:
            return redirect(url_for("staffsignup"))
    return render_template("signup.html", form=form)


@app.route("/admin/delete/<int:user_id>")
@login_required
@restricted(access_level="admin")
def adminDelete(user_id):
    deletedUser = User.query.filter_by(id=user_id).first_or_404()
    deletedUser.status = False
    db.session.commit()
    return redirect(url_for("admin"))


@app.route("/product/<int:product_id>", methods=["GET", "POST"])
def product(product_id):
    form = forms.ReviewForm(request.form)
    productQuantity = forms.productQuantity(request.form)
    product = Product.query.filter_by(productid=product_id).first_or_404()
    reviews = Review.query.filter_by(product_id=product_id).order_by(Review.rating).all()
    sort_by = request.args.get("sort-by")
    if sort_by != "lowest-rating":
        reviews.reverse()

    user_bought = False
    if current_user.is_authenticated:
        user_review = Review.query.filter_by(user_id=current_user.id, product_id=product_id).first()
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

    if productQuantity.submit.data and productQuantity.validate():
        quantity = productQuantity.productQuantity.data
        return redirect(url_for("addtocart", product_id=product_id, quantity=quantity))


    return render_template("product.html", product=product, form=form, reviews=reviews, user_review=user_review, user_bought=user_bought, productQuantity=productQuantity)


@app.route("/add_review/<int:product_id>", methods=["POST"])
def add_review(product_id):
    if not current_user.is_authenticated:
        abort(400)

    form = forms.ReviewForm(request.form)
    if form.validate():
        user = User.query.filter_by(id=current_user.id).first()
        product = Product.query.filter_by(productid=product_id).first()
        if None in [user, product]:
            print("No such user and/or product.")
            return redirect(url_for("product", product_id=product_id))

        review = Review.query.filter_by(user_id=current_user.id, product_id=product_id).first()
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

        review = Review(rating=form.review_rating.data, contents=form.review_contents.data)
        review.product = product
        user.reviews.append(review)
        db.session.add(review)
        db.session.commit()
        flash("Review added successfully.", "success")
    else:
        flash("There was an error while adding your review.", "danger")

    return redirect(url_for('product', product_id=product_id))


@app.route("/edit_review/<int:product_id>", methods=["POST"])
def edit_review(product_id):
    if not current_user.is_authenticated:
        abort(400)

    form = forms.ReviewForm(request.form)
    if form.validate():
        review = Review.query.filter_by(user_id=current_user.id, product_id=product_id).first()
        if review is None:
            print("No such user and/or product, or user haven't submitted a review for this product.")
            return redirect(url_for("product", product_id=product_id))

        review.rating = form.review_rating.data
        review.contents = form.review_contents.data
        db.session.commit()
        flash("Review edited successfully.", "success")
    else:
        flash("There was an error while editing your review.", "danger")

    return redirect(url_for('product', product_id=product_id))


@app.route("/delete_review/<int:product_id>", methods=["POST"])
def delete_review(product_id):
    if not current_user.is_authenticated:
        abort(400)

    review = Review.query.filter_by(user_id=current_user.id, product_id=product_id).first()
    if review is None:
        print("No such user and/or product, or user haven't submitted a review for this product.")
        return redirect(url_for("product", product_id=product_id))

    db.session.delete(review)
    db.session.commit()
    flash("Review deleted successfully.", "success")
    return redirect(url_for('product', product_id=product_id))


@app.route("/addtocart/<int:product_id>/<int:quantity>", methods=["GET", "POST"])
def addtocart(product_id, quantity):
    product = Product.query.filter_by(productid=product_id).first_or_404()

    if quantity > product.quantity or product.quantity == 0:
        flash("There is not enough quantity", "warning")
        return redirect(url_for("index"))
    else:
        try:
            cart = session["cart"]
            product = cart[0]
            product = {int(k):int(v) for k,v in product.items()}
            if product_id in product:
                qt = product[product_id]
                product[product_id] = int(qt) + int(quantity)
                cart[0] = product
                session["cart"] = cart
                print(cart)
                return redirect(url_for('cart'))
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


        return redirect(url_for('cart'))


@app.route("/deletefromcart/<int:product_id>", methods=["POST", 'GET'])
def deletefromcart(product_id):
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
    return redirect(url_for('cart'))


@app.route("/cart", methods=['POST', 'GET'])
def cart():
    cart = []
    product = {}
    cart.append(product)
    try:
        cart = session["cart"]
        print(cart)
        product = cart[0]
    except:
        print("No other item")
    productlist = []
    for i in product:
        products = Product.query.filter_by(productid=i).first()
        productlist.append(products)
    cart_Form = forms.cartForm(request.form)
    while len(cart_Form.productQuantity) != len(cart[0]):
        for i in cart[0]:
            cart_Form.productQuantity.append_entry(cart[0][i])
    if request.method == "POST" and cart_Form.validate():

        quantity = cart_Form.productQuantity.data
        x = 0
        for i in product:
            product[i] = int(quantity[x])
            x += 1
        cart[0] = product
        session["cart"] = cart
        return redirect(url_for('checkout'))

    return render_template("cart.html", len=len, cart=productlist, form=cart_Form)


@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    checkoutForm = forms.Checkout(request.form)
    user = User.query.filter_by(id=current_user.id).first()
    creditcards = user.creditcards
    addresses = user.addresses
    key = MyAes.get_fixed_key()
    cardlist = []
    for i in range(len(creditcards)):
        card = MyAes.decrypt(key, creditcards[i].cardnumber, creditcards[i].iv).decode("utf8")
        cardlist.append("Card " + card)
    checkoutForm.creditcard.choices = cardlist
    addresslist=[(addresses, "%s" %(addresses[i].address)) for i in range(len(addresses))]


    checkoutForm.address.choices = addresslist
    cart = session["cart"]
    products = cart[0]
    productlist = []
    productquantity = []
    for i in products:
            product = Product.query.filter_by(productid=i).first()
            productlist.append(product)
            productquantity.append(products[i])
    if request.method == "POST":
        card = ""
        address1 = ""
        order_product = ""
        for i in creditcards:
            if str(i) == checkoutForm.creditcard.data:
                card = i
                break
        for i in addresses:
            if str(i) == checkoutForm.address.data:
                address1 = i
                break

        # cardNum = card.cardnumber
        # CVV = card.cvv
        # expiry = card.expiry
        # address = address1.address
        # city = address1.city
        # state = address1.state
        # zip_code = address1.zip_code
        order = Orders()

        for i in products:
            product = Product.query.filter_by(productid=i).first()
            if products[i] > product.quantity:
                flash("There is not enough stock", "warning")
                return redirect(url_for("cart"))
        for i in products:
            product = Product.query.filter_by(productid=i).first()
            order_product = Orderproduct(quantity=products[i])
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
    return render_template("checkout.html", form=checkoutForm, cart=productlist, len=len,productquantity=productquantity)


@app.route('/products', methods=['GET'])
def getProducts():
    return redirect('admin')


@app.route('/products/new', methods=['GET', 'POST'])
@login_required
@restricted(access_level="seller")
def addProduct():
    form = forms.addProductForm(CombinedMultiDict((request.files, request.form)))
    if request.method == "POST" and form.validate():
        if request.files:
            image = request.files[form.image.name]
            print(image)
            image.save(os.path.join('static/images', image.filename))
            print(os.path.join('static/images', image.filename))
            filename = "images/%s" % image.filename
        product = Product(product_name=form.productName.data, description=form.productDescription.data, image=filename, price=form.productPrice.data, quantity=form.productQuantity.data)
        db.session.add(product)
        db.session.commit()
        flash(f'Product {{ form.productName }} added successfully', 'success')
        return redirect(url_for("product", product_id=product.productid))
    return render_template('addProduct.html', form=form)


@app.route('/products/<int:product_id>/update', methods=['GET', 'POST'])
@login_required
@restricted(access_level="seller")
def update_product(product_id):
    products = Product.query.get(product_id)
    form = forms.addProductForm(CombinedMultiDict((request.files, request.form)))
    if request.method == 'POST' and form.validate():
        products.product_name = form.productName.data
        products.description = form.productDescription.data
        product.image = form.image.data
        products.price = form.productPrice.data
        products.quantity = form.productQuantity.data
        db.session.commit()
        flash('This product has been updated!', 'success')
        return redirect((url_for('getProducts')))
    elif request.method == 'GET':
        form.productName.data = products.product_name
        form.productDescription.data = products.description
        form.image.data = products.image
        form.productPrice.data = products.price
        form.productQuantity.data = products.quantity
    return render_template('addProduct.html', legend='Update Product', form=form)


@app.route('/products/<int:product_id>/delete', methods=["GET", "POST"])
@login_required
@restricted(access_level="seller")
def delete_product(product_id):
    products = Product.query.filter_by(productid=product_id).first()
    products.deleted = True
    db.session.commit()
    flash('Your product has been deleted!', 'success')
    return redirect(url_for('getProducts'))


@app.route("/search")
def search():
    query = request.args.get("q")
    if query is None:
        search_results = []
    else:
        query = query.strip().lower()
        search_results = [i for i in Product.query.all() if query in i.product_name.lower()]

    return render_template("search.html", query=query, search_results=search_results)


@app.after_request
def add_header(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


if __name__ == "__main__":
    app.run(debug=True)
