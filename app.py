from datetime import datetime
from flask import (
    flash,
    Flask,
    make_response,
    redirect,
    render_template,
    request,
    url_for
)
from flask_login import (
    current_user,
    login_required,
    login_user,
    LoginManager,
    logout_user
)
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)

app.secret_key = os.urandom(16)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(32), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.now)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run()
