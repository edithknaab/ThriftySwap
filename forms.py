from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, ValidationError, SelectField, FloatField, IntegerField, FileField
from wtforms.validators import InputRequired, Length, Email, NumberRange, DataRequired
from flask_wtf.file import FileAllowed
from models import User  

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

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')
        
class ConfirmForm(FlaskForm):
    code = StringField('Code', validators=[DataRequired(), Length(min=5, max=5)])
    submit = SubmitField('Confirm')

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
    weight = FloatField('Weight (lb)', validators=[InputRequired(), NumberRange(min=0)])
    stock = IntegerField('Stock', validators=[InputRequired(), NumberRange(min=0)])
    value_per_item = FloatField('Value Per Item', validators=[InputRequired(), NumberRange(min=0)])
    type = StringField('Category', validators=[InputRequired(), Length(min=1, max=50)])
    barcode = StringField('Barcode', validators=[Length(max=50)])
    submit = SubmitField('Add Item')

class SSItemForm(FlaskForm):
    item_name = StringField('Item Name', validators=[InputRequired(), Length(min=1, max=50)])
    material = StringField('Material', validators=[Length(max=50)])
    weight = FloatField('Weight (lb)', validators=[InputRequired(), NumberRange(min=0)])
    stock = IntegerField('Stock', validators=[InputRequired(), NumberRange(min=0)])
    value_per_item = FloatField('Value Per Item', validators=[InputRequired(), NumberRange(min=0)])
    type = StringField('Category', validators=[InputRequired(), Length(min=1, max=50)]) 
    barcode = StringField('Barcode', validators=[Length(max=50)])
    submit = SubmitField('Add Item')