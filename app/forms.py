from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length


class LoginForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[
            DataRequired(message='Username is required'),
            Length(max=64, message='Username is too long'),
        ],
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired(message='Password is required')],
    )
    remember = BooleanField('Keep me signed in')
    submit = SubmitField('Log In')
