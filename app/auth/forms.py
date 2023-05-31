from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User

class LoginForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField(label='password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Inicia sesión')

class RegistrationForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField(label='Nombre de Usuario', validators=[DataRequired(), Length(1, 64), 
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'los nombres de usuarios deben de tener solo letras,'
            'numeros, puntos o guiones bajos')])
    password = PasswordField('password', validators=[DataRequired(), EqualTo('password2', message='Las contraseñas deben coincidir')])
    password2 = PasswordField('password2', validators=[DataRequired()])
    submit = SubmitField('Crear Cuenta')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Nombre de usuario ya está en uso')

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField(label='Contraseña antigua', validators=[DataRequired()])
    password = PasswordField(label='Nueva contraseña', validators=[DataRequired(), EqualTo('password2', message='Las contraseñas deben coincidir')])
    password2 = PasswordField(label='Confirmar nueva contraseña', validators=[DataRequired()])
    submit = SubmitField('Actualizar contraseña')

class PasswordResetRequestForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired(), Length(1, 64), Email()])
    submit = SubmitField('Reiniciar contraseña')

class PasswordResetForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField(label='Nueva contraseña', validators=[DataRequired(), EqualTo('password2', message='Las contraseñas no coinciden')])
    password2 = PasswordField(label='Confirmar contraseña', validators=[DataRequired()])
    submit = SubmitField('Reiniciar contraseña')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first() is None:
            raise ValidationError('Dirección de correo electrónico desconocida.')

class ChangeEmailForm(FlaskForm):
    email = StringField(label='Nuevo Email', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField(label='Contraseña', validators=[DataRequired()])
    submit = SubmitField('Actualización de la dirección de correo electrónico')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Correo electrónico ya registrado')
