from datetime import datetime
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

roles_users = db.Table(
    "roles_users",
    db.Column("user_id", db.Integer(), db.ForeignKey('user.id')),
    db.Column("role_id", db.Integer(), db.ForeignKey('role.id'))
)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.now)
    roles = db.relationship(
        "Role",
        secondary=roles_users,
        backref=db.backref("users", lazy='dynamic')
    )
    reviews = db.relationship("Review", backref=db.backref("user"))
    orders = db.relationship("Orders", backref=db.backref("user"))

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))


class Product(db.Model):
    __tablename__ = 'products'
    __table_args__ = {'extend_existing': True}
    productid = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(100))
    description = db.Column(db.String(100))
    price = db.Column(db.Numeric(10,2))
    quantity = db.Column(db.Integer)

    def __repr__(self):
        return f"Product('{self.productid}', '{self.product_name}', '{self.description}', '{self.price}', '{self.quantity}')"

'''
    def create(self):
        db.session.add(self)
        db.session.commit()
        return self

    def __init__(self, product_name, description, brand, price, quantity):
        self.product_name = product_name
        self.description = description
        self.brand = brand
        self.price = price
        self.quantity = quantity

'''


class Review(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.productid"), primary_key=True)
    rating = db.Column(db.Integer, nullable=False)
    contents = db.Column(db.String(255), nullable=False)
    product = db.relationship("Product")

class Orders(db.Model):
    orderid = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    order_product = db.relationship("Orderproduct", backref=db.backref("orders"))

class Orderproduct(db.Model):
    order_id = db.Column("order_id", db.Integer(), db.ForeignKey('orders.orderid'), primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.productid"), primary_key=True)
    quantity = db.Column(db.Integer, nullable=False)
    product = db.relationship("Product")


