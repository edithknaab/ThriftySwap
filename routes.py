from flask import Blueprint, render_template, redirect, url_for, request, jsonify, send_file, flash
from flask_login import current_user, login_user, login_required, logout_user
from datetime import datetime, timedelta
from forms import RegisterForm, LoginForm, ForgotPasswordForm, ResetPasswordForm, ItemForm
from models import User, Inventory, Store
from app import app, db, mail
from flask_bcrypt import Bcrypt
from barcode import generate as generate_barcode
from barcode.writer import ImageWriter
from io import BytesIO
import random
import string
from sqlalchemy import func

bp = Blueprint('routes', __name__)

bcrypt = Bcrypt()

@bp.route('/')
def home():
    logout_user()
    return render_template('home.html')

@app.route('/add_item', methods=['GET', 'POST'])
@login_required
def add_item():
    form = ItemForm()
    if form.validate_on_submit():
        item_name = form.item_name.data
        material = form.material.data
        weight = form.weight.data
        stock = form.stock.data
        value_per_item = form.value_per_item.data
        
        try:
            # Generate a random barcode number
            barcode = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
            
            # Adjusted to include store_id=1
            new_item = Inventory(item_name=item_name, material=material, weight=weight, stock=stock, 
                                 value_per_item=value_per_item, barcode=barcode, store_id=1)
            
            db.session.add(new_item)
            db.session.commit()
            flash('Item added successfully', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding item: {str(e)}', 'error')
            return redirect(url_for('add_item'))

    return render_template('add_item.html', form=form)



@app.route('/delete_item', methods=['POST'])
def delete_item():
    data = request.json
    item_id = data['id']
    
    inventory_item = Inventory.query.get(item_id)
    if inventory_item:
        db.session.delete(inventory_item)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Item deleted successfully'})
    else:
        return jsonify({'success': False, 'message': 'Item not found'})

@app.route('/scan_barcode', methods=['POST'])
def scan_barcode():
    data = request.json
    barcode = data['barcode']
    
    inventory_item = Inventory.query.filter(func.lower(Inventory.barcode) == func.lower(barcode)).first()

    if inventory_item:
        inventory_item.stock += 1
        db.session.commit()
        return jsonify({'success': True, 'message': 'Item quantity increased successfully', 'item': {'id': inventory_item.id}})
    else:
        return jsonify({'success': False, 'message': 'Item not found'})

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password,
                        first_name=form.first_name.data, last_name=form.last_name.data, role=form.role.data)
        
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))  # Redirect to home page
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
            user.reset_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
            user.reset_expiration = datetime.now() + timedelta(minutes=10)
            db.session.commit()

            msg = Message('Password Reset', sender='SustainableSouthern@gmail.com', recipients=[user.email])
            msg.body = 'Your reset code is: {}'.format(user.reset_code)
            mail.send(msg)

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
    # Filter inventory items by store_id = 1
    inventory_items = Inventory.query.filter_by(store_id=1).all()
    return render_template('dashboard.html', inventory_items=inventory_items)


@app.route('/print_barcode/<barcode>', methods=['GET'])
def print_barcode(barcode):
    barcode_img = generate_barcode_image(barcode)
    temp_file_path = f'/tmp/{barcode}.png'
    barcode_img.save(temp_file_path)
    return send_file(temp_file_path, mimetype='image/png')

def generate_barcode_image(barcode):
    from barcode import Code128
    from barcode.writer import ImageWriter

    code128 = Code128(barcode, writer=ImageWriter())
    return code128.render

@app.route('/profile')
@login_required
def profile():
    user_store = Store.query.get(current_user.store_id)
    return render_template('profile.html', user=current_user, store=user_store)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/update_quantity', methods=['POST'])
def update_quantity():
    try:
        data = request.get_json()
        item_id = data['id']
        new_quantity = data.get('new_quantity')
        
        inventory_item = Inventory.query.get(item_id)
        if inventory_item:
            inventory_item.stock = new_quantity
            db.session.commit()
            return jsonify({'success': True, 'message': 'Quantity updated successfully'})
        else:
            return jsonify({'success': False, 'message': 'Item not found'}), 404
    except KeyError as e:
        return jsonify({'success': False, 'message': f'Missing field: {str(e)}'}), 400


def get_inventory():
    # Filter inventory items by store_id = 1
    inventory_items = Inventory.query.filter_by(store_id=1).all()
    serialized_items = [{
        'id': item.id,
        'item_name': item.item_name,
        'material': item.material,
        'weight': item.weight,
        'stock': item.stock,
        'value_per_item': item.value_per_item,
        'barcode': item.barcode,
        'store_name': item.store.name if item.store else '',
        'type': item.type
    } for item in inventory_items]

    return jsonify({'inventory': serialized_items})


####swap shop routes

@app.route('/dashboard_ss', methods=['GET', 'POST'])
@login_required
def dashboard_ss():
    # Filter inventory items by store_id
    inventory_items = Inventory.query.filter_by(store_id=2).all()
    return render_template('dashboard_ss.html', inventory_items=inventory_items)

def get_inventory_ss():
    # Filter inventory items by store_id = 2
    inventory_items = Inventory.query.filter_by(store_id=2).all()
    serialized_items = [{
        'id': item.id,
        'item_name': item.item_name,
        'material': item.material,
        'weight': item.weight,
        'stock': item.stock,
        'value_per_item': item.value_per_item,
        'barcode': item.barcode,
        'store_name': item.store.name if item.store else '',
        'type': item.type
    } for item in inventory_items]

    return jsonify({'inventory': serialized_items})

@app.route('/add_item_ss', methods=['GET', 'POST'])
@login_required
def add_item_ss():
    form = ItemForm()
    if form.validate_on_submit():
        item_name = form.item_name.data
        material = form.material.data
        weight = form.weight.data
        stock = form.stock.data
        value_per_item = form.value_per_item.data
        
        try:
            # Generate a random barcode number (keep this logic for the swap shop items)
            barcode = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
            
            # Create a new Inventory object for the swap shop with the generated barcode and store_id set to 2
            new_item = Inventory(item_name=item_name, material=material, weight=weight, stock=stock, 
                                 value_per_item=value_per_item, barcode=barcode, store_id=2)
            
            db.session.add(new_item)
            db.session.commit()
            flash('Item added successfully to the swap shop', 'success')
            return redirect(url_for('dashboard_ss'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding item to the swap shop: {str(e)}', 'error')
            return redirect(url_for('add_item_ss'))

    return render_template('add_item_ss.html', form=form)