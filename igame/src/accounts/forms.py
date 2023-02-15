from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, DateField, EmailField, SubmitField
from wtforms import InputRequired, Email, length, EqualTo, Regexp

from igame.src.accounts.models import User


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
    password = PasswordField("Password", validators=[InputRequired(), length(8, 50)])
    password_confirm = PasswordField("Confirm Password", validators=[InputRequired(), length(8, 50),
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

    def validate(self):
        initial_validation = super(RegisterForm, self).validate()
        if not initial_validation:
            return False
        user = User.query.filter_by(username=self.username.data).first()
        if user:
            self.username.errors.append("This username has already been taken!")
            return False
        user = User.query.filter_by(email=self.email.data).first()
        if user:
            self.email.errors.append("This email is already linked to a registered user!")
            return False
        if self.password.data != self.confirm.data:
            self.password.errors.append("The passwords must match!")
            return False
        return True
