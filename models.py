from app import db
from flask_login import UserMixin


class Store(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    inventories = db.relationship('Inventory', backref='store', lazy=True)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True) 
    password = db.Column(db.String(80), nullable=False)
    first_name = db.Column(db.String(20), nullable=True)
    last_name = db.Column(db.String(20), nullable=True)
    role = db.Column(db.String(20), nullable=False)
    reset_code = db.Column(db.String(5))
    reset_expiration = db.Column(db.DateTime)
    store_id = db.Column(db.Integer, db.ForeignKey('store.id'), nullable=True)
    verified = db.Column(db.Boolean, default=False)

class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(50), nullable=False)
    material = db.Column(db.String(50), nullable=True)
    weight = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    value_per_item = db.Column(db.DECIMAL(10, 2), nullable=False)
    barcode = db.Column(db.String(50), nullable=True)
    store_id = db.Column(db.Integer, db.ForeignKey('store.id'), nullable=False)
    type = db.Column(db.String(20))
