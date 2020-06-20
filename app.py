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
from classes.models import db, User, Role, Product, ProductSchema
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
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = forms.LoginForm(request.form)
    if request.method == "POST" and form.validate():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for("profile"))
        return redirect(url_for("login"))
    return render_template("login.html", form=form)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = forms.RegisterForm(request.form)
    if request.method == "POST" and form.validate():
        hashedPassword = generate_password_hash(form.password.data, method="sha256")
        newUser = User(username=form.username.data, email=form.email.data, password=hashedPassword)
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
    return render_template("admin.html", current_user=current_user, users=User.query.order_by(User.id).all())


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
    return render_template("product.html")


@app.route('/products', methods=['GET'])
def products():
    get_products = Product.query.all()
    product_schema = ProductSchema(many=True)
    products = product_schema.dump(get_products)
    return make_response(jsonify({"product": products}))


@app.route('/products', methods=['POST'])
def create_product():
    data = request.get_json()
    product_schema = ProductSchema()
    product = product_schema.load(data)
    result = product_schema.dump(product.create())
    return make_response(jsonify(({"product": result})), 200)


@app.route('/products/<id>', methods=['GET'])
def get_product_by_id(id):
    get_product = Product.query.get(id)
    product_schema = ProductSchema()
    product = product_schema.dump(get_product)
    return make_response(jsonify({"product": product}))


@app.route('/products/<id>', methods=['PUT'])
def update_product_by_id(id):
    data = request.get_json()
    get_product = Product.query.get(id)
    if data.get('title'):
        get_product.title = data['title']
    if data.get('productDescription'):
        get_product.productDescription = data['productDescription']
    if data.get('productBrand'):
        get_product.productBrand = data['productBrand']
    if data.get('price'):
        get_product.price = data['price']
    db.session.add(get_product)
    db.session.commit()
    product_schema = ProductSchema(only=['id', 'title', 'productDescription', 'productBrand', 'price'])
    product = product_schema.dump(get_product)
    return make_response(jsonify({"product": product}))


@app.route('/products/<id>', methods=['DELETE'])
def delete_product_by_id(id):
    get_product = Product.query.get(id)
    db.session.delete(get_product)
    db.session.commit()
    return make_response("", 204)


@app.route("/search")
def search():
    query = request.args.get("q")
    return render_template("search.html", query=query)


if __name__ == "__main__":
    app.run(debug=True)
