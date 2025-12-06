from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp

class LoginForm(FlaskForm):
    username = StringField('اسم المستخدم', validators=[
        DataRequired(message="هذا الحقل مطلوب"),
        Length(min=4, max=25, message="يجب أن يكون الاسم بين 4 و 25 حرفاً"),
        Regexp(r'^[\w.@+-]+$', message="يجب أن يحتوي الاسم على أحرف وأرقام فقط")
    ])
    password = PasswordField('كلمة المرور', validators=[
        DataRequired(message="هذا الحقل مطلوب")
    ])
    # Honeypot field - should be left empty by humans
    honeypot = StringField('Middle Name', validators=[Length(max=0, message="Bot detected")])
    submit = SubmitField('تسجيل الدخول')

class TwoFactorForm(FlaskForm):
    token = StringField('رمز التحقق (2FA)', validators=[
        DataRequired(),
        Length(min=6, max=6, message="الرمز يجب أن يكون 6 أرقام"),
        Regexp(r'^\d+$', message="أرقام فقط")
    ])
    submit = SubmitField('تحقق')
