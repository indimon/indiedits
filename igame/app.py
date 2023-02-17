from flask import Flask, flash, redirect, render_template, request, url_for
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from datetime import datetime
from flask_login import UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, DateField, EmailField, SubmitField
from wtforms.validators import InputRequired, Email, length, EqualTo, Regexp
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = 'TheSecretKeyForTeam9'
app.config['SQLALCHEMY_DATABASE_URI'] = \
    'postgresql://postgres:password@igame-instance.cj3l9swcgrzl.us-east-1.rds.amazonaws.com/igame_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
bcrypt = Bcrypt(app)
login_manager.login_view = 'login'
login_manager.login_message_category = "danger"


def hash_pass(password: str = "password"):
    hashPass = password
    # *adds salt*
    salt = "igame"
    hashPass += salt
    hashed = hashlib.md5(hashPass.encode())
    return hashed.hexdigest()


class User(UserMixin, db.Model):
    __tablename__ = "user_details"
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(50), nullable=False)
    user_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(150), nullable=False, unique=True)
    birth_date = db.Column(db.DateTime, nullable=False)
    zip_code = db.Column(db.Integer, nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    user_password = db.Column(db.String(40), nullable=False)

    def __init__(self, name: str, username: str, email: str, bday: datetime,
                 zipcode: int, phone: str, password: str):
        self.full_name = name
        self.user_name = username
        self.email = email
        self.birth_date = bday
        self.zip_code = zipcode
        self.phone_number = phone
        self.user_password = bcrypt.generate_password_hash(password)

    def __repr__(self):
        return f'<email {self.email}'


# Create the Login Form Class
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), length(3, 50)])
    password = PasswordField("Password", validators=[InputRequired(), length(8, 50)])
    remember = BooleanField('remember me')
    submit = SubmitField("LOGIN")


# Create the Registration Form Class
class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), length(3, 50)])
    email = EmailField("Email", validators=[InputRequired(), length(5, 50), Email()])
    password = PasswordField("Password", validators=[InputRequired(), length(8, 50),
                                                     EqualTo('password_confirm', message='Passwords must match')])
    password_confirm = PasswordField("Confirm Password", validators=[InputRequired(),
                                                                     EqualTo('password',
                                                                             message='Passwords must match')])
    name = StringField("Full Name", validators=[InputRequired(), length(1, 50)])
    bday = DateField("Birthdate", format='%m-%d-%Y', validators=[InputRequired()])
    zipcode = StringField("Zip Code", validators=[InputRequired(),
                                                  Regexp('^[0-9]*$')])
    phone = StringField("Phone Number",
                        validators=[InputRequired(),
                                    Regexp('^(\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}$')])
    submit = SubmitField("REGISTER")

    def validate(self, extra_validators=None):
        initial_validation = super(RegisterForm, self).validate(extra_validators)
        if not initial_validation:
            return False
        user = User.query.filter_by(username=self.username.data).first()
        if user:
            self.username.errors.append("This username has already been taken!")
            return False
        user = User.query.filter_by(email=self.email.data).first()
        if user:
            self.email.errors.append("This email is already in use.")
            return False
        if self.password.data != self.confirm.data:
            self.password.errors.append("Passwords must match!")
            return False
        return True


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        flash('You are already registered! Please login.', 'info')
        return redirect(url_for('accounts/login.html'))
    form = RegisterForm(request.form)
    if form.validate_on_submit():
        password_hash = hash_pass(request.form.get('password', type=str)).decode('utf8')
        user = User(username=form.username.data, email=form.email.data,
                    password=password_hash, name=form.name.data,
                    bday=form.bday.data, zipcode=form.zipcode.data,
                    phone=form.phone.data)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        flash('SUCCESS! Welcome to iGame, you are now logged in.', 'success')
        return redirect(url_for('core.home'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('core.home'))
    form = LoginForm(request.form)
    if form.validate_on_submit():
        user = User.query.filter_by(user_name=form.username.data).first()
        if user and bcrypt.check_password_hash(user.user_password, request.form['password']):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Your username or password are invalid. Try again!', 'danger')
            return render_template('login.html', form=form)
    return render_template('login.html', form=form)


@app.route('/home')
@login_required
def dashboard():
    return render_template('home.html', name=current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You were logged out.', 'success')
    return redirect(url_for('login'))


# Error handlers
@app.errorhandler(401)
def unauthorized_page(error):
    return render_template("401.html"), 401


@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error_page(error):
    return render_template("500.html"), 500


if __name__ == '__main__':
    app.run(debug=True)
