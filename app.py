from flask import Flask, request, redirect, render_template_string, url_for, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User
from encryption import encrypt_data, decrypt_data
import pyotp
from flask_sqlalchemy import SQLAlchemy
import qrcode
from io import BytesIO
import base64
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev_secret_key_123456"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

# Google OAuth configuration (put your client credentials here)
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='1048673187883-8es91sf060h98o4tjfsqqti8u970mhq8.apps.googleusercontent.com',
    client_secret='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',
   server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

 
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        otp_secret = pyotp.random_base32()
        encrypted = encrypt_data('Sensitive Info Here')

        user = User(
            email=email,
            password_hash=password, 
            otp_secret=otp_secret,
            encrypted_data=encrypted
        )
        db.session.add(user)
        db.session.commit()

      
        otp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=email, issuer_name="Internee.pk")
        qr = qrcode.make(otp_uri)
        buffer = BytesIO()
        qr.save(buffer, format="PNG")
        qr_data = base64.b64encode(buffer.getvalue()).decode()

        return render_template_string("""
        <h3>Scan this QR code in Google Authenticator</h3>
        <img src="data:image/png;base64,{{ qr_data }}">
        <br><a href='/login'>Go to Login</a>
        """, qr_data=qr_data)

    return '''
    <form method="post">
        Email: <input name="email"><br>
        Password: <input name="password" type="password"><br>
        <button type="submit">Register</button>
    </form>
    '''
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        otp = request.form['otp']

        user = User.query.filter_by(email=email).first()
        if user and user.password_hash == password:
            totp = pyotp.TOTP(user.otp_secret)
            if totp.verify(otp):
                login_user(user)
                return redirect('/dashboard')
            else:
                return "Invalid 2FA code"

        return "Invalid credentials"

    return '''
    <form method="post">
        Email: <input name="email"><br>
        Password: <input name="password" type="password"><br>
        2FA Code: <input name="otp"><br>
        <button type="submit">Login</button>
    </form>
    '''

@app.route('/dashboard')
@login_required
def dashboard():
    decrypted = decrypt_data(current_user.encrypted_data)
    return f"""
    <h3>Welcome, {current_user.email}</h3>
    <p>Decrypted Data: {decrypted}</p>
    <a href='/logout'>Logout</a>
    """

@app.route('/session')
def session_debug():
    return dict(session)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')


@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize/google')
def authorize_google():
    token = google.authorize_access_token()
    user_info = token.get('userinfo')
    if user_info is None:
        # If not in token, fetch manually
        resp = google.get('https://openidconnect.googleapis.com/v1/userinfo')
        user_info = resp.json()
    print("DEBUG: user_info =", user_info)

    email = user_info["email"]

    user = User.query.filter_by(email=email).first()
    if not user:
        # Create new user
        user = User(
            email=email,
            password="",
            otp_secret=pyotp.random_base32(),
            encrypted_data=encrypt_data("OAuth User")
        )
        db.session.add(user)
        db.session.commit()
        print("DEBUG: Created new user with id =", user.id)
    else:
        print("DEBUG: Found existing user with id =", user.id)

    # ✅ THIS IS THE FIX
    login_user(user)

    return redirect(url_for("dashboard"))


