from datetime import datetime

from flask import url_for
from flask_login import UserMixin
from flask_sqlalchemy import BaseQuery, SQLAlchemy

db = SQLAlchemy()

roles_users = db.Table(
    "roles_users",
    db.Column("user_id", db.Integer(), db.ForeignKey("user.id")),
    db.Column("role_id", db.Integer(), db.ForeignKey("role.id")),
)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.now)
    status = db.Column(db.Boolean(), nullable=False, default=True)
    roles = db.relationship(
        "Role",
        secondary=roles_users,
        backref=db.backref("users", lazy="dynamic"),
    )
    reviews = db.relationship("Review", backref=db.backref("user"))
    orders = db.relationship("Orders", backref=db.backref("user"))
    credit_cards = db.relationship(
        "CreditCard",
        backref=db.backref("user"),
        cascade="all, delete, delete-orphan",
    )
    addresses = db.relationship(
        "Address",
        backref=db.backref("user"),
        cascade="all, delete, delete-orphan",
    )


class CreditCard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    card_number = db.Column(db.String, nullable=False)
    expiry = db.Column(db.Date, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    iv = db.Column(db.String, nullable=False)


class Address(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(120), nullable=False)
    zip_code = db.Column(db.Integer, nullable=False)
    city = db.Column(db.String(120), nullable=False)
    state = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))


class QueryWithSoftDelete(BaseQuery):
    _with_deleted = False

    def __new__(cls, *args, **kwargs):
        obj = super(QueryWithSoftDelete, cls).__new__(cls)
        obj._with_deleted = kwargs.pop("_with_deleted", False)
        if len(args) > 0:
            super(QueryWithSoftDelete, obj).__init__(*args, **kwargs)
            return (
                obj.filter_by(deleted=False) if not obj._with_deleted else obj
            )
        return obj

    def __init__(self, *args, **kwargs):
        pass

    def with_deleted(self):
        return self.__class__(
            db.class_mapper(self._mapper_zero().class_),
            session=db.session(),
            _with_deleted=True,
        )

    def _get(self, *args, **kwargs):
        # this calls the original query.get function from the base class
        return super().get(*args, **kwargs)

    def get(self, *args, **kwargs):
        # the query.get method does not like it if there is a filter clause
        # pre-loaded, so we need to implement it using a workaround
        obj = self.with_deleted()._get(*args, **kwargs)
        return (
            obj
            if obj is None or self._with_deleted or not obj.deleted
            else None
        )


class Product(db.Model):
    __tablename__ = "product"
    __table_args__ = {"extend_existing": True}
    product_id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    deleted = db.Column(db.Boolean(), default=False)

    query_class = QueryWithSoftDelete

    def __repr__(self):
        product_id = self.product_id
        product_name = self.product_name
        description = self.description
        image = self.image
        price = self.price
        quantity = self.quantity
        url = url_for(
            "get_products", id=self.product_id if not self.deleted else None
        )
        return (
            f"Product('{product_id}', '{product_name}', '{description}', "
            f"'{image}', '{price}', '{quantity}', '{url}'"
        )


class Review(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True)
    product_id = db.Column(
        db.Integer, db.ForeignKey("product.product_id"), primary_key=True
    )
    rating = db.Column(db.Integer, nullable=False)
    contents = db.Column(db.String(255), nullable=False)
    product = db.relationship("Product")


class Orders(db.Model):
    order_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    order_product = db.relationship(
        "OrderProduct", backref=db.backref("orders")
    )


class OrderProduct(db.Model):
    order_id = db.Column(
        "order_id",
        db.Integer(),
        db.ForeignKey("orders.order_id"),
        primary_key=True,
    )
    product_id = db.Column(
        db.Integer, db.ForeignKey("product.product_id"), primary_key=True
    )
    quantity = db.Column(db.Integer, nullable=False)
    product = db.relationship("Product")
