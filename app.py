from datetime import datetime
from flask import (
    flash,
    Flask,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
    jsonify
)
from flask_login import (
    current_user,
    login_required,
    login_user,
    LoginManager,
    logout_user
)
from classes import forms
from classes.models import db, User, Role, Product, Review
from werkzeug.security import generate_password_hash, check_password_hash


import os

app = Flask(__name__)

app.secret_key = os.urandom(16)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

db.init_app(app)
with app.app_context():
    db.create_all()
    if db.session.query(Role).count() == 0:
        customerrole = Role(name="Customer", description="This is a customer account")
        sellerrole = Role(name="Seller", description="This is a seller account, it manages all product listings")
        staffrole = Role(name="Staff", description="This is the staff account, it manages the reviews of the products")
        adminrole = Role(name="Admin", description="This is the master admin account")
        db.session.add(customerrole)
        db.session.add(staffrole)
        db.session.add(sellerrole)
        db.session.add(adminrole)
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def index():
    products = Product.query.all()
    return render_template("index.html", products=products)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = forms.LoginForm(request.form)
    if request.method == "POST" and form.validate():
        user = db.session.execute("SELECT * FROM user WHERE username = '%s' and password = '%s'" % (form.username.data, form.password.data))
        id = [row[0] for row in user]
        user = User.query.filter_by(id=id[0]).first()
        login_user(user, remember=form.remember.data)
        return redirect(url_for("profile"))
        """
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for("profile"))
        return redirect(url_for("login"))
        """
    return render_template("login.html", form=form)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = forms.RegisterForm(request.form)
    if request.method == "POST" and form.validate():
        hashedPassword = generate_password_hash(form.password.data, method="sha256")
        newUser = User(username=form.username.data, email=form.email.data, password=form.password.data)
        customer = Role.query.filter_by(name="Customer").first()
        customer.users.append(newUser)
        if User.query.filter_by(id="1").first().id == 1 and len(User.query.filter_by(id="1").first().roles) == 1:
            staff = Role.query.filter_by(name="Staff").first()
            staff.users.append(User.query.filter_by(id="1").first())
            seller = Role.query.filter_by(name="Seller").first()
            seller.users.append(User.query.filter_by(id="1").first())
            admin = Role.query.filter_by(name="Admin").first()
            admin.users.append(User.query.filter_by(id="1").first())
        elif User.query.filter_by(id="2").first().id == 2 and len(User.query.filter_by(id="2").first().roles) == 1:
            seller = Role.query.filter_by(name="Seller").first()
            seller.users.append(User.query.filter_by(id="2").first())
        db.session.add(newUser)
        db.session.commit()
        return redirect(url_for("login"))
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
            user = User.query.filter_by(id=current_user.id).first()
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


@app.route("/profile/delete")
@login_required
def deleteprofile():
    deletedUser = User.query.filter_by(id=current_user.id).first()
    logout_user()
    db.session.delete(deletedUser)
    db.session.commit()
    return redirect(url_for("index"))


@app.route("/admin")
@login_required
def admin():
    return render_template("admin.html", current_user=current_user, users=User.query.order_by(User.id).all(), products=Product.query.order_by(Product.productid).all())


@app.route("/admin/create/user", methods=["GET", "POST"])
@login_required
def staffsignup():
    form = forms.AdminCreateForm(request.form)
    if request.method == "POST" and form.validate():
        hashedPassword = generate_password_hash(form.password.data, method="sha256")
        newUser = User(username=form.username.data, email=form.email.data, password=hashedPassword)
        customer = Role.query.filter_by(name="Customer").first()
        customer.users.append(newUser)
        staff = Role.query.filter_by(name="Staff").first()
        staff.users.append(newUser)
        db.session.add(newUser)
        db.session.commit()
        return redirect(url_for("admin"))
    return render_template("signup.html", form=form)


@app.route("/admin/delete/<int:user_id>")
@login_required
def adminDelete(user_id):
    deletedUser = User.query.filter_by(id=user_id).first()
    db.session.delete(deletedUser)
    db.session.commit()
    return redirect(url_for("admin"))


@app.route("/product/<int:product_id>")
def product(product_id):
    form = forms.ReviewForm(request.form)
    product = Product.query.filter_by(productid=product_id).first_or_404()
    reviews = Review.query.filter_by(product_id=product_id).order_by(Review.rating).all()
    sort_by = request.args.get("sort-by")
    if sort_by != "lowest-rating":
        reviews.reverse()

    if current_user.is_authenticated:
        user_review = Review.query.filter_by(user_id=current_user.id, product_id=product_id).first()
        if user_review is not None:
            form.review_rating.data = str(user_review.rating)
            form.review_contents.data = user_review.contents
    else:
        user_review = None

    return render_template("product.html", product=product, form=form, reviews=reviews, user_review=user_review)


@app.route("/add_review/<int:user_id>/<int:product_id>", methods=["POST"])
@login_required
def add_review(user_id, product_id):
    form = forms.ReviewForm(request.form)
    if form.validate():
        user = User.query.filter_by(id=user_id).first()
        product = Product.query.filter_by(productid=product_id).first()
        if None in [user, product]:
            print("No such user and/or product.")
            return redirect(url_for("product", product_id=product_id))

        review = Review(rating=form.review_rating.data, contents=form.review_contents.data)
        review.product = product
        user.reviews.append(review)
        db.session.add(review)
        db.session.commit()
    else:
        print("Review is invalid.")

    return redirect(url_for('product', product_id=product_id))


@app.route("/edit_review/<int:user_id>/<int:product_id>", methods=["POST"])
@login_required
def edit_review(user_id, product_id):
    form = forms.ReviewForm(request.form)
    if form.validate():
        review = Review.query.filter_by(user_id=user_id, product_id=product_id).first()
        if review is None:
            print("No such user and/or product, or user haven't submitted a review for this product.")
            return redirect(url_for("product", product_id=product_id))

        review.rating = form.review_rating.data
        review.contents = form.review_contents.data
        db.session.commit()
    else:
        print("Review is invalid.")

    return redirect(url_for('product', product_id=product_id))


@app.route("/delete_review/<int:user_id>/<int:product_id>", methods=["POST"])
@login_required
def delete_review(user_id, product_id):
    review = Review.query.filter_by(user_id=user_id, product_id=product_id).first()
    if review is None:
        print("No such user and/or product, or user haven't submitted a review for this product.")
        return redirect(url_for("product", product_id=product_id))

    db.session.delete(review)
    db.session.commit()
    return redirect(url_for('product', product_id=product_id))

@app.route("/cart")
def cart():
    for i in cart:
        name = cart[i].get_productName
    return render_template("product.html")

@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    checkoutForm = forms.Checkout(request.form)
    if request.method == "POST":
        name = checkoutForm.name.data
        cardNum = checkoutForm.cardNum.data
        CVV = checkoutForm.CVV.data
        expiry_month = checkoutForm.expiry_month.data
        expiry_year = checkoutForm.expiry_year.data
        billing_address = checkoutForm.billing_address.data
        postal_code = checkoutForm.postal_code.data
        return redirect(url_for("index"))
    return render_template("checkout.html", form=checkoutForm)

@app.route('/products', methods=['GET'])
def getProducts():
    return redirect('admin')


@app.route('/products/new', methods=['GET', 'POST'])
def addProduct():
    form = forms.addProductForm(request.form)
    if request.method == "POST" and form.validate():
        product = Product(product_name=form.productName.data, description=form.productDescription.data, price=form.productPrice.data, quantity=form.productQuantity.data)
        db.session.add(product)
        db.session.commit()
        flash(f'Product {{ form.productName }} added successfully', 'success')
        return redirect(url_for("product", product_id=product.productid))
    return render_template('addProduct.html', form=form)


@app.route('/products/<int:product_id>/update', methods=['GET', 'POST'])
def update_product(product_id):
    products = Product.query.get(product_id)
    form = forms.addProductForm(request.form)
    if form.validate():
        products.product_name = form.productName.data
        products.description = form.productDescription.data
        products.price = form.productPrice.data
        products.quantity = form.productQuantity.data
        db.session.commit()
        flash('This product has been updated!', 'success')
        return redirect((url_for('getProducts')))
    elif request.method == 'GET':
        form.productName.data = products.product_name
        form.productDescription.data = products.description
        form.productPrice.data = products.price
        form.productQuantity.data = products.quantity
    return render_template('addProduct.html', legend='Update Product', form=form)


@app.route('/products/<int:product_id>/delete', methods=["GET", "POST"])
def delete_product(product_id):
    products = Product.query.filter_by(productid=product_id).first()
    db.session.delete(products)
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


if __name__ == "__main__":
    app.run(debug=True)
