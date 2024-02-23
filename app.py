from flask import Flask, render_template, url_for, redirect, request, jsonify,send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField, SubmitField, ValidationError, SelectField, FloatField, IntegerField, DateField
from wtforms.validators import InputRequired, Length, Email, NumberRange
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message 
from flask_migrate import Migrate
from datetime import datetime, timedelta
import random
import string
from sqlalchemy import func
from barcode import generate
from barcode.writer import ImageWriter
from io import BytesIO
import base64
import os

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'csc400'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'OwlGoSCSU@gmail.com'
app.config['MAIL_PASSWORD'] = 'rbjb dwxk lqly smlz'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    from app import User
    return User.query.get(int(user_id))


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
    profile_picture = db.Column(db.String(20), nullable=True, default='default.jpg')


class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(50), nullable=False)
    material = db.Column(db.String(50), nullable=True)
    weight = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    value_per_item = db.Column(db.DECIMAL(10, 2), nullable=False)
    barcode = db.Column(db.String(50), nullable=True)
    store_id = db.Column(db.Integer, db.ForeignKey('store.id'), nullable=True)
    type = db.Column(db.String(20))  

# Create the database table for swapshop
    #class SwapShopInvetory(db.Model):


# Set the app context (this is necessary for Flask-SQLAlchemy)
app.app_context().push()
# Create all tables
db.create_all()


class RegisterForm(FlaskForm):
    email = StringField(validators=[
             InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Email"})
    
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    first_name = StringField(validators=[
                            InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "First Name"})
    last_name = StringField(validators=[
                            InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "Last Name"})
    picture = FileField('Upload Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    
    role = SelectField('Role', choices=[('student', 'Student'), ('staff', 'Staff')], default='student')

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')

    def validate_email(self, email):
        if not email.data.lower().endswith('@southernct.edu'):
            raise ValidationError('Please use a Southern Connecticut State University email address.')

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

class ForgotPasswordForm(FlaskForm):
    email = StringField(validators=[
             InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Email"})

    submit = SubmitField('Submit')

class ResetPasswordForm(FlaskForm):
    code = StringField(validators=[
             InputRequired(), Length(min=5, max=5)], render_kw={"placeholder": "Code"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Submit')

class ItemForm(FlaskForm):
    item_name = StringField('Item Name', validators=[InputRequired(), Length(min=1, max=50)])
    material = StringField('Material', validators=[Length(max=50)])
    weight = FloatField('Weight (kg)', validators=[InputRequired(), NumberRange(min=0)])
    stock = IntegerField('Stock', validators=[InputRequired(), NumberRange(min=0)])
    value_per_item = FloatField('Value Per Item', validators=[InputRequired(), NumberRange(min=0)])
    submit = SubmitField('Add Item')

#create swapshop item form
        

@app.route('/')
def home():
    return render_template('home.html')


from flask_login import current_user

@app.route('/add_item', methods=['GET', 'POST'])
@login_required
def add_item():
    form = ItemForm()
    if request.method == 'POST' and form.validate_on_submit():
        item_name = form.item_name.data
        material = form.material.data
        weight = form.weight.data
        stock = form.stock.data
        value_per_item = form.value_per_item.data

        try:
            # Generate barcode data
            barcode_data = generate_barcode()

            # Create a new Inventory object with the generated barcode data
            new_item = Inventory(item_name=item_name, material=material, weight=weight, stock=stock, value_per_item=value_per_item, barcode=barcode_data)
            # Add the new item to the database session
            db.session.add(new_item)
            # Commit the changes to the database
            db.session.commit()
            print("New item added successfully")
        except Exception as e:
            # If an error occurs, rollback the database session
            db.session.rollback()
            print("Error adding item:", e)

        return redirect(url_for('dashboard'))
    return render_template('add_item.html', form=form)


@app.route('/delete_item', methods=['POST'])
def delete_item():
    data = request.json
    item_id = data['id']
    
    # Retrieve the inventory item from the database
    inventory_item = Inventory.query.get(item_id)
    if inventory_item:
        # Delete the inventory item
        db.session.delete(inventory_item)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Item deleted successfully'})
    else:
        return jsonify({'success': False, 'message': 'Item not found'})

from barcode import generate
from barcode.writer import ImageWriter

def generate_barcode():
    barcode_data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    try:
        barcode = generate('code128', barcode_data, writer=ImageWriter())
        # Save the barcode image to a BytesIO object
        barcode_image_bytes = BytesIO()
        barcode.write(barcode_image_bytes)
        barcode_image_bytes.seek(0)  # Move the file pointer to the beginning
        return barcode_data
    except Exception as e:
        print(f"Error generating barcode: {e}")
        return None  

@app.route('/scan_barcode', methods=['POST'])
def scan_barcode():
    data = request.json
    barcode = data['barcode']
    
    # Process scanned barcode data
    # Query database for inventory item with matching barcode (case-insensitive comparison)
    inventory_item = Inventory.query.filter(func.lower(Inventory.barcode) == func.lower(barcode)).first()

    if inventory_item:
        # Increment the stock quantity for the scanned item
        inventory_item.stock += 1
        db.session.commit()
        return jsonify({'success': True, 'message': 'Item quantity increased successfully', 'item': {'id': inventory_item.id}})
    else:
        return jsonify({'success': False, 'message': 'Item not found'})


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('home'))
            else:
                error_message = 'Invalid username or password. Please try again'
                return render_template('login.html', form=form, error_message=error_message)
        else:
            error_message = 'Invalid username or password. Please try again'
            return render_template('login.html', form=form, error_message=error_message)
    return render_template('login.html', form=form)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            # Generate a random reset code
            user.reset_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))

            # Set the expiration date to 10 minutes from now
            user.reset_expiration = datetime.now() + timedelta(minutes=10)

            db.session.commit()

            # Send reset email
            msg = Message('Password Reset', sender='SustainableSouthern@gmail.com', recipients=[user.email])
            msg.body = 'Your reset code is: {}'.format(user.reset_code)
            mail.send(msg)

            # Redirect to the enter code page
            return redirect(url_for('enter_code'))

    return render_template('forgot_password.html', form=form)

@app.route('/reset_password', methods=['GET', 'POST'])
def enter_code():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(reset_code=form.code.data).first()
        if user:
            if datetime.now() > user.reset_expiration:
                print('Reset code has expired.')
                return redirect(url_for('forgot_password'))
            
            if user.reset_expiration > datetime.now():
                user.password = bcrypt.generate_password_hash(form.password.data)
                user.reset_code = None
                user.reset_expiration = None
                db.session.commit()
                return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

@app.route('/verify_code', methods=['POST'])
def verify_code():
    code = request.form.get('code')
    user = User.query.filter_by(reset_code=code).first()
    if user and datetime.now() <= user.reset_expiration:
        return jsonify(code_valid=True)
    else:
        return jsonify(code_valid=False)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    # Fetch inventory items for the current user's store
    inventory_items = Inventory.query.all()
    return render_template('dashboard.html', inventory_items=inventory_items)

@app.route('/swapshopbase')
@login_required
def swapshopbase():
    # Code here
    return render_template('swapshopbase.html')

@app.route('/print_barcode/<barcode>', methods=['GET'])
def print_barcode(barcode):
    # Generate barcode image
    barcode_img = generate_barcode_image(barcode)

    # Save the barcode image to a temporary file
    temp_file_path = f'/tmp/{barcode}.png'
    barcode_img.save(temp_file_path)

    # Send the barcode image file to the client
    return send_file(temp_file_path, mimetype='image/png')

def generate_barcode_image(barcode):
    # Generate barcode image using the barcode library
    from barcode import Code128
    from barcode.writer import ImageWriter

    code128 = Code128(barcode, writer=ImageWriter())
    return code128.render()


@app.route('/get_inventory', methods=['GET'])
def get_inventory():
    # Fetch inventory items
    inventory_items = Inventory.query.all()
    serialized_items = [{
        'id': item.id,
        'item_name': item.item_name,
        'material': item.material,
        'weight': item.weight,
        'stock': item.stock,
        'value_per_item': item.value_per_item,
        'barcode': item.barcode,  # Ensure barcode information is included
        'store_name': item.store.name if item.store else '',  # Get store name or empty string if store is None
        'type': item.type
    } for item in inventory_items]

    return jsonify({'inventory': serialized_items})

@app.route('/update_quantity', methods=['POST'])
def update_quantity():
    try:
        data = request.get_json()
        item_id = data['id']
        new_quantity = data.get('new_quantity')  # Use get() method to handle missing field gracefully
        
        # Retrieve the inventory item from the database
        inventory_item = Inventory.query.get(item_id)
        if inventory_item:
            # Update the stock quantity for the inventory item
            inventory_item.stock = new_quantity
            db.session.commit()
            return jsonify({'success': True, 'message': 'Quantity updated successfully'})
        else:
            return jsonify({'success': False, 'message': 'Item not found'}), 404
    except KeyError as e:
        return jsonify({'success': False, 'message': f'Missing field: {str(e)}'}), 400

####END Test
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        if form.picture.data:
            picture_file = secure_filename(form.picture.data.filename)
            picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_file)
            form.picture.data.save(picture_path)
            picture_file = 'profile_pics/' + picture_file
        else:
            picture_file = 'default.jpg'

        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password,
                        first_name=form.first_name.data, last_name=form.last_name.data, role=form.role.data, profile_picture=picture_file)
        
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/profile')
@login_required
def profile():
    
    user_store = Store.query.get(current_user.store_id)
    return render_template('profile.html', user=current_user, store=user_store)

if __name__ == "__main__":
    app.run(debug=True)