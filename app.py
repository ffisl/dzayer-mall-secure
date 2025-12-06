from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from models import db, User, Product
from forms import LoginForm, TwoFactorForm
import os
import logging
import pyotp
import qrcode
from io import BytesIO
import base64

# Load environment variables
load_dotenv()

app = Flask(__name__)

# --- Advanced Security Configuration ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback_secret_key_CHANGE_THIS')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Secure Cookies
app.config['SESSION_COOKIE_SECURE'] = True # Always True for "Unhackable" (requires HTTPS)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True

# Initialize Extensions
db.init_app(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.session_protection = 'strong' # Protect against session hijacking

# Content Security Policy (CSP)
csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\'', '\'unsafe-inline\''], # unsafe-inline needed for current JS structure
    'style-src': ['\'self\'', '\'unsafe-inline\'', 'https://fonts.googleapis.com'],
    'font-src': ['\'self\'', 'https://fonts.gstatic.com'],
    'img-src': ['\'self\'', 'data:', 'https://images.unsplash.com', 'https://via.placeholder.com']
}

# Talisman for HTTP Headers (HSTS, XSS, Frame Options)
talisman = Talisman(
    app,
    content_security_policy=csp,
    force_https=False, # Set to True in production
    strict_transport_security=True,
    session_cookie_secure=True,
    frame_options='DENY' # Prevent Clickjacking
)

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Logging
logging.basicConfig(filename='security.log', level=logging.INFO)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    form = LoginForm()
    if form.validate_on_submit():
        # Honeypot check
        if form.honeypot.data:
            logging.warning(f"Bot detected via honeypot from {request.remote_addr}")
            return redirect(url_for('index')) # Silent fail for bots

        user = User.query.filter_by(username=form.username.data).first()
        
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            # 2FA Check
            session['pre_2fa_user_id'] = user.id
            if user.totp_secret:
                return redirect(url_for('verify_2fa'))
            else:
                return redirect(url_for('setup_2fa'))
        else:
            logging.warning(f"Failed login attempt for user: {form.username.data} from {request.remote_addr}")
            flash('خطأ في اسم المستخدم أو كلمة المرور', 'danger')
            
    return render_template('login.html', form=form)

@app.route('/login/2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pre_2fa_user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['pre_2fa_user_id'])
    form = TwoFactorForm()
    
    if form.validate_on_submit():
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(form.token.data):
            login_user(user)
            session.pop('pre_2fa_user_id', None)
            flash('تم تسجيل الدخول بنجاح!', 'success')
            logging.info(f"Successful 2FA login for user: {user.username}")
            
            if user.role == 'admin': return redirect(url_for('admin'))
            elif user.role == 'merchant': return redirect(url_for('merchant'))
            else: return redirect(url_for('index'))
        else:
            flash('رمز التحقق غير صحيح', 'danger')
            
    return render_template('verify_2fa.html', form=form)

@app.route('/setup-2fa', methods=['GET', 'POST'])
def setup_2fa():
    if 'pre_2fa_user_id' not in session:
        return redirect(url_for('login'))
        
    user = User.query.get(session['pre_2fa_user_id'])
    # Only allow setup if not already set (or add logic to reset)
    if user.totp_secret:
        return redirect(url_for('verify_2fa'))

    # Generate secret if not exists (in session for temp storage)
    if 'temp_totp_secret' not in session:
        session['temp_totp_secret'] = pyotp.random_base32()
    
    secret = session['temp_totp_secret']
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user.username, issuer_name="DzayerMall")
    
    # Generate QR Code
    img = qrcode.make(uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_code = base64.b64encode(buffered.getvalue()).decode("utf-8")
    
    form = TwoFactorForm()
    if form.validate_on_submit():
        if totp.verify(form.token.data):
            user.totp_secret = secret
            db.session.commit()
            session.pop('temp_totp_secret', None)
            login_user(user)
            session.pop('pre_2fa_user_id', None)
            flash('تم تفعيل المصادقة الثنائية بنجاح!', 'success')
            
            if user.role == 'admin': return redirect(url_for('admin'))
            elif user.role == 'merchant': return redirect(url_for('merchant'))
            else: return redirect(url_for('index'))
        else:
            flash('الرمز غير صحيح، حاول مرة أخرى', 'danger')

    return render_template('setup_2fa.html', form=form, qr_code=qr_code, secret=secret)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        abort(403) # Forbidden
    return render_template('admin.html')

@app.route('/merchant')
@login_required
def merchant():
    if current_user.role != 'merchant':
        abort(403)
    return render_template('merchant.html')

# --- API for Products ---
@app.route('/api/products')
def get_products():
    products = Product.query.all()
    product_list = []
    for p in products:
        product_list.append({
            'id': p.id,
            'title': p.name,
            'price': f"{p.price} د.ج",
            'category': p.category,
            'image': p.image_url
        })
    return jsonify(product_list)

# --- Error Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return "<h1>403 - Forbidden: You don't have permission to access this resource.</h1>", 403

@app.errorhandler(500)
def internal_server_error(e):
    return "<h1>500 - Internal Server Error</h1>", 500

# --- Database Setup ---
def create_db():
    with app.app_context():
        db.create_all()
        if not Product.query.first():
            dummy_products = [
                Product(name="ساعة ذكية برو", price=5500, category="إلكترونيات", image_url="https://images.unsplash.com/photo-1523275335684-37898b6baf30?auto=format&fit=crop&w=500&q=80", merchant_id=1),
                Product(name="سماعات بلوتوث", price=3200, category="صوتيات", image_url="https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=500&q=80", merchant_id=1),
                Product(name="حقيبة ظهر عصرية", price=4800, category="موضة", image_url="https://images.unsplash.com/photo-1553062407-98eeb64c6a62?auto=format&fit=crop&w=500&q=80", merchant_id=1),
            ]
            if not User.query.filter_by(username='merchant').first():
                hashed_pw = bcrypt.generate_password_hash('password').decode('utf-8')
                merchant = User(username='merchant', email='merchant@example.com', password=hashed_pw, role='merchant')
                db.session.add(merchant)
                db.session.commit()
                for p in dummy_products:
                    p.merchant_id = merchant.id
                    db.session.add(p)
                db.session.commit()

            if not User.query.filter_by(username='admin').first():
                hashed_pw = bcrypt.generate_password_hash('password').decode('utf-8')
                admin = User(username='admin', email='admin@example.com', password=hashed_pw, role='admin')
                db.session.add(admin)
                db.session.commit()

if __name__ == '__main__':
    if not os.path.exists('database.db'):
        create_db()
    # In production, debug must be False
    app.run(debug=False, ssl_context='adhoc') # Enable adhoc SSL for local dev to test Secure cookies
