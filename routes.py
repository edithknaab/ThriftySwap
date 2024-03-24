import os 
from flask import Blueprint, render_template, redirect, url_for, request, jsonify, send_file, flash
from flask_login import current_user, login_user, login_required, logout_user
from datetime import datetime, timedelta
from forms import RegisterForm, LoginForm, ForgotPasswordForm, ResetPasswordForm, ItemForm, ConfirmForm, SSItemForm
from flask_mail import Message
from werkzeug.utils import secure_filename
from models import User, Inventory, Store, IntakeTransaction, OuttakeTransaction, SwapShopInventory, SwapShopIntakeTransaction, SwapShopOuttakeTransaction
from app import app, db, mail
from flask_bcrypt import Bcrypt
from barcode import generate as generate_barcode
from barcode.writer import ImageWriter
from io import BytesIO
import random
import string
from sqlalchemy import func, extract


bp = Blueprint('routes', __name__)

bcrypt = Bcrypt()


@bp.route('/')
def home():
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
            # Generate a random barcode number (replace this with your barcode generation logic)
            barcode = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
            
            # Create a new Inventory object with the generated barcode
            new_item = Inventory(item_name=item_name, material=material, weight=weight, stock=stock, 
                                 value_per_item=value_per_item, barcode=barcode)
            
            db.session.add(new_item)
            db.session.commit()
            flash('Item added successfully', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding item: {str(e)}', 'error')
            return redirect(url_for('add_item'))

    return render_template('add_item.html', form=form)

@bp.route('/scan_barcode', methods=['POST'])
@login_required
def scan_barcode():
    data = request.json
    scanned_barcode = data['barcode']
    
    inventory_item = Inventory.query.filter_by(barcode=scanned_barcode).first()

    if inventory_item:
        
        return jsonify({'success': True, 'message': 'Item found', 'itemId': inventory_item.id})
    else:
        return jsonify({'success': False, 'message': 'Item not found'})

    
@app.route('/scan_barcode_swap_shop', methods=['POST'])
@login_required
def scan_barcode_swap_shop():
    data = request.json
    barcode = data.get('barcode')
    print('Received barcode:', barcode)  

    item = SwapShopInventory.query.filter_by(barcode=barcode).first()
    print('Query result:', item)  

    if item:
        return jsonify({'success': True, 'itemId': item.id, 'item_name': item.item_name, 'material': item.material, 'weight': item.weight, 'stock': item.stock, 'value_per_item': str(item.value_per_item), 'barcode': item.barcode})
    else:
        return jsonify({'success': False, 'message': 'Item not found'})


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

        new_user.verification_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))

        db.session.add(new_user)
        db.session.commit()

        msg = Message('Confirm Your Email', recipients=[new_user.email])
        msg.body = 'Your verification code is: {}'.format(new_user.verification_code)
        mail.send(msg)
        return redirect(url_for('confirm_email')) 

    return render_template('register.html', form=form)


@app.route('/user_verify', methods=['GET', 'POST'])
def confirm_email():
    form = ConfirmForm()  

    if form.validate_on_submit():
        user = User.query.filter_by(verification_code=form.code.data).first()
        if user:
            if not user.verified:
                user.verified = True
                user.verification_code = None
                db.session.add(user)
                db.session.commit()
            return redirect(url_for('login'))

    return render_template('user_verify.html', form=form)  


@app.route('/user_unverified')
def user_unverified():
    if current_user.is_anonymous or current_user.verified:
        return redirect(url_for('routes.home'))
    return render_template('user_unverified.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('routes.home'))
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
            user.reset_expiration = datetime.now() + timedelta(minutes=5)
            db.session.commit()

            msg = Message('Password Reset', recipients=[user.email])
            msg.body = 'Your reset code is: {}. This code will expire in 5 minutes.'.format(user.reset_code)
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


from collections import defaultdict

@app.route('/dashboard')
@login_required
def dashboard():
    inventory_items = Inventory.query.all() 
    return render_template('dashboard.html', inventory_items=inventory_items)


@app.route('/swapshopbase')
@login_required
def swapshopbase():
    
    return render_template('swapshopbase.html')


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


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        if 'picture' in request.files:
            picture = request.files['picture']
            filename = secure_filename(picture.filename)
            picture.save(os.path.join('static/profile_pics', filename))
            current_user.profile_picture = 'profile_pics/' + filename
            db.session.commit()
            return redirect(url_for('profile'))

    user_store = Store.query.get(current_user.store_id)
    return render_template('profile.html', user=current_user, store=user_store)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/update_quantity', methods=['POST'])
@login_required
def update_quantity():
    try:
        data = request.get_json()
        item_id = data['id']
        quantity_to_add = int(data.get('new_quantity'))
        donor_info = data.get('donor_info')

        inventory_item = Inventory.query.get(item_id)
        if inventory_item:
            intake_transaction = IntakeTransaction(
                inventory_id=item_id,
                item_name=inventory_item.item_name,  # Corrected attribute
                quantity=quantity_to_add,
                user=current_user.username,  # Assuming the user model has a username field
                donor_info=donor_info,
                timestamp=datetime.utcnow()
            )
            db.session.add(intake_transaction)

            inventory_item.stock += quantity_to_add  # Add the quantity to the existing stock
            db.session.commit()
            return jsonify({'success': True, 'message': 'Quantity updated successfully'})
        else:
            return jsonify({'success': False, 'message': 'Item not found'}), 404
    except KeyError as e:
        return jsonify({'success': False, 'message': f'Missing field: {str(e)}'}), 400
    
@app.route('/get_inventory', methods=['GET'])
def get_inventory():
    inventory_items = Inventory.query.all()
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


@app.route('/release_item', methods=['POST'])
@login_required
def release_item():
    data = request.json
    item_id = data['item_id']
    quantity = data['quantity']
    donor_info = data['donor_info']

    # Get the item name from the inventory
    inventory_item = Inventory.query.get(item_id)
    if inventory_item:
        if inventory_item.stock >= quantity:
            # Subtract released quantity from stock
            inventory_item.stock -= quantity

            # Create a new outtake transaction record with donor information
            outtake_transaction = OuttakeTransaction(
                inventory_id=item_id,
                quantity=quantity,
                donor_info=donor_info,  
                timestamp=datetime.utcnow()
            )
            db.session.add(outtake_transaction)
            db.session.commit()

            return jsonify({'success': True, 'message': 'Item released successfully'})
        else:
            return jsonify({'success': False, 'message': 'Insufficient stock'})
    else:
        return jsonify({'success': False, 'message': 'Item not found'})
   
def get_item_name(item_id, transaction_type):
    
    transaction = None
    if transaction_type == 'intake':
        transaction = IntakeTransaction.query.get(item_id)
    elif transaction_type == 'outtake':
        transaction = OuttakeTransaction.query.get(item_id)

    if transaction:
        return transaction.item_name  
    else:
        return None 

@app.route('/get_item_details/<int:id>', methods=['GET'])
def get_item_details(id):
    
    item = Inventory.query.get(id)

    
    if item is None:
        return jsonify({'error': 'Item not found'}), 404


    item_data = {
        'id': item.id,
        'item_name': item.item_name,
        'material': item.material,
        'weight': item.weight,
        'stock': item.stock,
        'value_per_item': str(item.value_per_item),
        'barcode': item.barcode,
        'store_id': item.store_id,
        'type': item.type
    }

    
    return jsonify(item_data)

@app.route('/get_ssitem_details/<int:item_id>', methods=['GET'])
@login_required
def get_ssitem_details(item_id):
    item = SwapShopInventory.query.get(item_id)
    if item:
        return jsonify({
            'success': True,
            'item_id': item.id,
            'item_name': item.item_name,
            'material': item.material,
            'weight': item.weight,
            'stock': item.stock,
            'value_per_item': str(item.value_per_item),
            'barcode': item.barcode
        })
    else:
        return jsonify({'success': False, 'message': 'Item not found'})

@app.route('/filter_inventory')
def filter_inventory():
    date = request.args.get('date')

    
    
    inventory_items = Inventory.query.all()
    
    
    inventory_data = [
        {
            'id': item.id,
            'item_name': item.item_name,
            'material': item.material,
            'weight': item.weight,
            'stock': item.stock,
            'value_per_item': str(item.value_per_item),
            'barcode': item.barcode,
            'store_id': item.store_id,
            'type': item.type
        }
        for item in inventory_items
    ]

    
    return jsonify(inventory_data)


@app.route('/thriftyowlrecords')
def thriftyowlrecords():
    
    intake_transactions = IntakeTransaction.query.all()
    
    outtake_transactions = OuttakeTransaction.query.all()
    
    intake_info = collect_intake_info(intake_transactions)

    return render_template('thriftyowlrecords.html', intake_info=intake_info, outtake_transactions=outtake_transactions)


def collect_intake_info(intake_transactions):
    intake_info = {}
    for transaction in intake_transactions:
        if transaction.inventory is not None:
            item_name = transaction.inventory.item_name
            if item_name in intake_info:
                intake_info[item_name].append(transaction)
            else:
                intake_info[item_name] = [transaction]
    return intake_info


@app.route('/create_intake_transaction', methods=['POST'])
def create_intake_transaction():
    data = request.json  

    
    inventory_id = data.get('inventory_id')
    item_name = data.get('item_name')
    quantity = data.get('quantity')
    donor_info = data.get('donor_info')

    
    intake_transaction = IntakeTransaction(
        inventory_id=inventory_id,
        item_name=item_name,
        quantity=quantity,
        user="User",  
        donor_info=donor_info,
        timestamp=datetime.now()  
    )

    
    db.session.add(intake_transaction)

    try:
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Intake transaction created successfully'})
    except Exception as e:
        
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


# SWAP SHOP ROUTES

@app.route('/swap_shop_dashboard')
@login_required
def swap_shop_dashboard():
    
    items = SwapShopInventory.query.all()
    donor_info = SwapShopIntakeTransaction.query.all()
    return render_template('dashboard_swap_shop.html', items=items, donor_info=donor_info)

@app.route('/add_item_swap_shop', methods=['GET', 'POST'])
@login_required
def add_item_swap_shop():
    form = SSItemForm()
    if form.validate_on_submit():
        item_name = form.item_name.data
        material = form.material.data
        weight = form.weight.data
        stock = form.stock.data
        value_per_item = form.value_per_item.data
        
        try:
            # Generate a random barcode number (replace this with your barcode generation logic)
            barcode = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
            
            # Create a new Swap Shop Inventory object with the submitted data
            new_item = SwapShopInventory(item_name=item_name, material=material, weight=weight, 
                                         stock=stock, value_per_item=value_per_item, barcode=barcode)
            
            db.session.add(new_item)
            db.session.commit()
            flash('Item added successfully', 'success')
            return redirect(url_for('swap_shop_dashboard'))  
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding item: {str(e)}', 'error')
            return redirect(url_for('add_item_swap_shop'))
    return render_template('add_item_swap_shop.html', form=form)


@app.route('/get_swap_shop_inventory', methods=['GET'])
def get_swap_shop_inventory():
    inventory_items = SwapShopInventory.query.all()
    serialized_items = [{
        'id': item.id,
        'item_name': item.item_name,
        'material': item.material,
        'weight': item.weight,
        'stock': item.stock,
        'value_per_item': item.value_per_item,
        'barcode': item.barcode,
        
    } for item in inventory_items]

    return jsonify({'inventory': serialized_items})


@app.route('/swapshoprecords')
def swapshoprecords():
    
    intake_transactions = SwapShopIntakeTransaction.query.all()
    outtake_transactions = SwapShopOuttakeTransaction.query.all()
<<<<<<< HEAD
    
    intake_info = collect_intake_info(intake_transactions)
=======

    # Collect intake information into a dictionary
    intake_info = collect_swap_shop_intake_info(intake_transactions)
>>>>>>> 237283fca0e7a40121e3091c44c3ab5ee8c020a4
    donor_info = SwapShopIntakeTransaction.query.all()
    donor_info = SwapShopOuttakeTransaction.query.all()

    return render_template('swapshoprecords.html', intake_info=intake_info, outtake_transactions=outtake_transactions,donor_info=donor_info)


@app.route('/create_swapshop_intake_transaction', methods=['POST'])
def create_swapshop_intake_transaction():
    data = request.json  

    inventory_id = data.get('inventory_id')
    quantity = data.get('quantity')
    donor_info = data.get('donor_info')

    intake_transaction = SwapShopIntakeTransaction(
        swap_shop_inventory_id=inventory_id,
        quantity=quantity,
        donor_info=donor_info,
        timestamp=datetime.now()  
    )

    db.session.add(intake_transaction)

    try:
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Intake transaction for Swap Shop Inventory created successfully'})
    except Exception as e:
        
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/create_swapshop_outtake_transaction', methods=['POST'])
def create_swapshop_outtake_transaction():
    data = request.json  

    inventory_id = data.get('inventory_id')
    quantity = data.get('quantity')
    donor_info = data.get('donor_info')

    
    outtake_transaction = SwapShopOuttakeTransaction(
        swap_shop_inventory_id=inventory_id,
        quantity=quantity,
        donor_info=donor_info,
        timestamp=datetime.now()  
    )

    
    db.session.add(outtake_transaction)

    try:
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Outtake transaction for Swap Shop Inventory created successfully'})
    except Exception as e:
        
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

<<<<<<< HEAD

def collect_intake_info(intake_transactions):
=======
def collect_swap_shop_intake_info(intake_transactions):
>>>>>>> 237283fca0e7a40121e3091c44c3ab5ee8c020a4
    intake_info = {}
    for transaction in intake_transactions:
        
        if isinstance(transaction, SwapShopIntakeTransaction):
            item_name = transaction.swap_shop_inventory.item_name  
            if item_name in intake_info:
                intake_info[item_name].append(transaction)
            else:
                intake_info[item_name] = [transaction]
    return intake_info


@app.route('/release_item_ss', methods=['POST'])
@login_required
def release_item_ss():
    data = request.json
    item_id = data.get('item_id')
    quantity = int(data.get('quantity'))
    donor_info = data.get('donor_info')

    if not item_id:
        return jsonify({'success': False, 'message': 'Item ID is required'})

    swapshop_item = SwapShopInventory.query.get(item_id)
    if swapshop_item:
        if swapshop_item.stock >= quantity:
            swapshop_item.stock -= quantity

            outtake_transaction = SwapShopOuttakeTransaction(
                swap_shop_inventory_id=item_id,
                quantity=quantity,
                donor_info=donor_info,
                timestamp=datetime.utcnow()
            )
            db.session.add(outtake_transaction)

            db.session.commit()

            return jsonify({'success': True, 'message': 'Item released successfully'})
        else:
            return jsonify({'success': False, 'message': 'Insufficient stock'})
    else:
        return jsonify({'success': False, 'message': 'Item not found'})


@app.route('/update_quantity_ss', methods=['POST'])
@login_required
def update_quantity_ss():
    try:
        data = request.json
        item_id = data.get('item_id')
<<<<<<< HEAD
        quantity_to_add = int(data.get('quantity_to_add'))  
=======
        quantity_to_add = int(data.get('quantity_to_add'))  # Change 'new_quantity' to 'quantity_to_add'
        donor_info = data.get('donor_info')
>>>>>>> 237283fca0e7a40121e3091c44c3ab5ee8c020a4

        inventory_item = SwapShopInventory.query.get(item_id)
        if inventory_item:
            intake_transaction = SwapShopIntakeTransaction(
                swap_shop_inventory_id=item_id,
<<<<<<< HEAD
                quantity=quantity_to_add,  
=======
                quantity=quantity_to_add,  # Use the quantity to add directly
                user=current_user.username,
                donor_info=donor_info,
>>>>>>> 237283fca0e7a40121e3091c44c3ab5ee8c020a4
                timestamp=datetime.utcnow()
            )
            db.session.add(intake_transaction)

            inventory_item.stock += quantity_to_add  
            db.session.commit()
            return jsonify({'success': True, 'message': 'Quantity updated successfully'})
        else:
            return jsonify({'success': False, 'message': 'Item not found'}), 404
    except KeyError as e:
        return jsonify({'success': False, 'message': f'Missing field: {str(e)}'}), 400


@app.route('/profile_swap_shop', methods=['GET', 'POST'])
@login_required
def profile_swap_shop():
    if request.method == 'POST':
        if 'picture' in request.files:
            picture = request.files['picture']
            filename = secure_filename(picture.filename)
            picture.save(os.path.join('static/profile_pics', filename))
            current_user.profile_picture = 'profile_pics/' + filename
            db.session.commit()
            return redirect(url_for('profile'))

    user_store = Store.query.get(current_user.store_id)
    return render_template('profile_swap_shop.html', user=current_user, store=user_store)
