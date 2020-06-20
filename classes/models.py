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


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class Product(db.Model):
    __tablename__ = "products"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    productDescription = db.Column(db.String(100))
    productBrand = db.Column(db.String(20))
    price = db.Column(db.Decimal)
    quantity = db.Column(db.Integer)

    def create(self):
        db.session.add(self)
        db.session.commit()
        return self

    def __init__(self, name, productDescription, productBrand, price, quantity):
        self.name = name
        self.productDescription = productDescription
        self.productBrand = productBrand
        self.price = price
        self.quantity = quantity

    def __repr__(self):
        return f"Product('{self.id}', '{self.name}', '{self.productDescription}', '{self.productBrand}', '{self.price}', '{self.quantity}')"
