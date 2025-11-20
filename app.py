from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import numpy as np
import traceback
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from datetime import datetime
from werkzeug.utils import secure_filename
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
import os, io, shutil
from functools import wraps
from google.oauth2.service_account import Credentials
import tempfile
from sqlalchemy import create_engine
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import hashlib

app = Flask(__name__)
app.secret_key = 'vasanth'

# # === Database Configuration ===
# DATABASE_TYPE = 'mysql'
# DB_DRIVER = 'pymysql'
# USERNAME = 'appsadmin'
# PASSWORD = 'appsadmin2025'
# HOST = '34.93.75.171'
# PORT = '3306'
# DATABASE_NAME = 'mc'

# engine = create_engine(f"{DATABASE_TYPE}+{DB_DRIVER}://{USERNAME}:{PASSWORD}@{HOST}:{PORT}/{DATABASE_NAME}")

# ---------- DB CONFIG (LOCAL + APP ENGINE) ----------
DATABASE_TYPE = "mysql"
DB_DRIVER = "pymysql"

DB_USER = os.environ.get("DB_USER", "appsadmin")
DB_PASS = os.environ.get("DB_PASS", "appsadmin2025")
DB_NAME = os.environ.get("DB_NAME", "mc")

# For local dev you can still use PUBLIC IP:
DB_HOST = os.environ.get("DB_HOST", "34.93.75.171")
DB_PORT = os.environ.get("DB_PORT", "3306")

# On App Engine we’ll use Unix socket: /cloudsql/<INSTANCE_CONNECTION_NAME>
INSTANCE_UNIX_SOCKET = os.environ.get("INSTANCE_UNIX_SOCKET")

if INSTANCE_UNIX_SOCKET:
    # 👉 Running on App Engine (or anywhere with Cloud SQL Unix socket)
    SQLALCHEMY_DATABASE_URI = (
        f"{DATABASE_TYPE}+{DB_DRIVER}://{DB_USER}:{DB_PASS}@/{DB_NAME}"
        f"?unix_socket={INSTANCE_UNIX_SOCKET}"
    )
else:
    # 👉 Local / VM using host + port (public IP or private IP)
    SQLALCHEMY_DATABASE_URI = (
        f"{DATABASE_TYPE}+{DB_DRIVER}://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )

app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy()
db.init_app(app)

engine = create_engine(SQLALCHEMY_DATABASE_URI)


SMTP_SERVER = "smtp.datasolve-analytics.com"
SMTP_PORT = 587
WEBMAIL_USER = "apps.admin@datasolve-analytics.com"
WEBMAIL_PASSWORD = "datasolve@2025"
# === Google Drive Configuration ===
SERVICE_ACCOUNT_FILE = 'service.json'
SCOPES = ['https://www.googleapis.com/auth/drive']

credentials = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES)
service = build('drive', 'v3', credentials=credentials)

# === Shared Drive Configuration ===
# "Test" Shared Drive as parent
PARENT_FOLDER_ID = '0AE_1ban4Ri_5Uk9PVA'  # Your "Test" Shared Drive ID

# Folder map - ONLY include folders that actually exist in your Shared Drive
FOLDER_MAP = {
    'Analytics_Team': {'id': '1HUpcs_hTxvrODlIOzkbtdJXhaQmO5JtX'},
    'IP_Analytics': {'id': '133tBYeuvrS_P-_sJXo9JJofB5567h4nH'},
    'IP_Team': {'id': '1WJWS4qDPwnWR2tIUecFB3i_SNZrRrYEZ'},
    'MC_AI': {'id': '1ecmDn3BVAOH1dsxD6WdDItQh6wmnQBep'},
    'MC_Analytics': {'id': '1oISNViuUqHTvqxXtC1vTqt8HQFQZVLHE'},
    'MC_Profiling': {'id': '1GSrVRuYnlBahGpCtwQXxuM4utuJ9CaZO'},
    'MC_QC': {'id': '1DsrtjxyT8mdOdi-8hkFAPy9_HABAZGsW'},
    'MC_Team': {'id': '1iP3pit7W8iu1ue4oQOmO-i4FDnk8lERQ'},
    'MR_Team': {'id': '14OEj4bfniCqcK-ETjlhYnxmHtIGwfCAy'},
    'MC_PM': {'id': '1H-_FoP11gSTivCsGWGWv9wcEqHJYhdq6'},
    'MC_Others': {'id': '1_ZCNlpIEAZ1xMspSEul2u4Gu4am5rAw7'},
    'IP_Others': {'id': '13071DZq9c1XbdIm2YcusPSbX_lPAXTVI'},
    'Mindmap': {'id': '1Vu0m0nbbW1zaGrTr1cy0AgEnEstKgqW7'},
    'MC_Personnel_Mapping': {'id': '15I4ECz11i2WSJ-WVvRAqEZGG_kX0kuZa'},
    'IP_PPT_Reports':{'id':'1lbICvKGiN6UWMZZ5M20wuN1FZ948fml7'},
    'Bruntha Codes File':{'id':'130Lbk6gFzUv3eCQJ6MrvIvv1-w0X15pj'}
}

# === Database Models ===
class User(db.Model):
    __tablename__ = 'desktop_userstable'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    verified = db.Column(db.Boolean, default=True)
    verification_code = db.Column(db.String(255), nullable=True)
    role = db.Column('Role', db.String(50), nullable=False, default='user')
    folders = db.Column('Folders', db.Text, nullable=True)

class UserProfile(db.Model):
    __tablename__ = "User_Profiles"
    __table_args__ = {"extend_existing": True, "schema": "mainapp"}

    Email_ID = db.Column(db.String(255), primary_key=True)
    Image_URL = db.Column(db.Text)
    Designation = db.Column(db.String(200))
    Team = db.Column(db.String(100))

# === Helper Functions ===
@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    return response

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Please log in first.")
            return redirect('/')
        return f(*args, **kwargs)
    return decorated_function

def send_otp_email(email, otp):
    try:
        otp_str = str(otp)
        subject = "Email Verification OTP"
        plain_text = f"Your OTP is: {otp_str}"
        html_content = f"""
        <html>
            <body>
                <h1>Email Verification</h1>
                <p>Your OTP is: <strong>{otp_str}</strong></p>
            </body>
        </html>
        """
        msg = MIMEMultipart("alternative")
        msg["From"] = f"Your App <{WEBMAIL_USER}>"
        msg["To"] = email
        msg["Subject"] = subject
        msg.attach(MIMEText(plain_text, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(WEBMAIL_USER, WEBMAIL_PASSWORD)
            server.sendmail(WEBMAIL_USER, email, msg.as_string())

    except Exception as error:
        print("Error sending OTP email:", error)

def get_profile_for_email(email: str):
    if not email:
        return None, None, None
    rec = (db.session.query(UserProfile.Designation, UserProfile.Team, UserProfile.Image_URL)
           .filter(UserProfile.Email_ID == email)
           .first())
    if not rec:
        return None, None, None
    return rec[0], rec[1], rec[2]

def gravatar_url(email: str, size=64, default="identicon"):
    if not email:
        return ""
    h = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    return f"https://www.gravatar.com/avatar/{h}?s={size}&d={default}&r=g"

def create_drive_folder(folder_name, parent_id=PARENT_FOLDER_ID):
    """Create a folder inside the specified parent folder (Shared Drive) - ADMIN ONLY"""
    folder_metadata = {
        'name': folder_name,
        'mimeType': 'application/vnd.google-apps.folder',
        'parents': [parent_id]
    }
    try:
        folder = service.files().create(
            body=folder_metadata,
            fields='id',
            supportsAllDrives=True
        ).execute()
        return folder.get('id')
    except Exception as e:
        print(f"❌ Error creating folder '{folder_name}': {e}")
        return None

def log_action(activity_type, filename, folder_name, username):
    try:
        ExecutionEndTime = datetime.now()
        log_data = {
            'Username': username,
            'Activity': activity_type,
            'Filename': filename,
            'Folder_Name': folder_name,
            'Start_Date': ExecutionEndTime.strftime('%Y-%m-%d'),
            'Time': ExecutionEndTime
        }
        log_df = pd.DataFrame([log_data])
        log_df.to_sql('desktop_user_ip', con=engine, if_exists='append', index=False)
        print(f"✅ Logged {activity_type} for {filename}")
    except Exception as e:
        print("❌ Log insert failed:", e)
        traceback.print_exc()

# === Context Processors ===
@app.context_processor
def inject_gravatar():
    return dict(gravatar_url=gravatar_url)

@app.context_processor
def inject_profile_image():
    img_url = None
    display_name = session.get("username")
    email = session.get("email")

    try:
        if not email and display_name:
            u = User.query.filter_by(username=display_name).first()
            email = u.email if u else None

        if email:
            rec = (db.session.query(UserProfile.Image_URL)
                   .filter(UserProfile.Email_ID == email)
                   .first())
            if rec and rec[0]:
                img_url = rec[0]
    except Exception as e:
        app.logger.exception("Profile inject failed: %s", e)

    return {
        "user_email": email,
        "profile_image_url": img_url,
        "profile_name": display_name,
    }

# === Routes ===
# @app.route('/')
# def home():
#     return redirect('/login')

@app.route('/welcome')
@login_required
def welcome():
    username = session.get('username', 'User')
    role = session.get('role', 'user')
    dashboard_url = '/admin' if role == 'admin' else '/fileshare'
    return render_template('welcome.html', username=username, dashboard_url=dashboard_url)

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        otp = request.form['otp']

        if 'verification_code' in session and str(session['verification_code']) == otp:
            email = session.get('email')
            user = db.session.query(User).filter_by(email=email).first()
            if user:
                user.verified = True
                user.verification_code = None
                db.session.commit()

                session.pop('email', None)
                session.pop('verification_code', None)

                return render_template('login.html', success="Your account has been verified successfully!")
            return render_template('verify.html', error="User not found or verification error.")

    return render_template('verify.html')

@app.route('/signup', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        allowed_domain = "datasolve-analytics.com"
        if not email.endswith(f"@{allowed_domain}"):
            return render_template('register.html', error="Only datasolve-analytics.com emails are allowed.")

        hashed_password = generate_password_hash(password)
        verification_code = random.randint(100000, 999999)

        existing_user = db.session.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            return render_template('register.html', error="Username or email already exists.")

        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            verification_code=verification_code,
            verified=False
        )

        db.session.add(new_user)
        db.session.commit()

        send_otp_email(email, verification_code)

        session['email'] = email
        session['verification_code'] = verification_code

        return redirect(url_for('verify'))

    return render_template('register.html', error="Only datasolve-analytics.com emails are allowed.")

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Frontend form: <input name="email"> nu irukkanum
        email = request.form.get('email', '').strip()
        pwd   = request.form.get('password', '')

        # DB la email + verified=True vachi user edukkiren
        user = User.query.filter_by(email=email, verified=True).first()

        if user and check_password_hash(user.password, pwd):
            session['username'] = user.username
            session['role'] = user.role
            session['email'] = user.email
            return redirect('/welcome')  # Driver App main page
        else:
            flash("❌ Invalid email/password or account not verified.")
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = db.session.query(User).filter_by(email=email, verified=True).first()

        if user:
            reset_code = random.randint(100000, 999999)
            user.verification_code = reset_code
            db.session.commit()

            send_otp_email(email, reset_code)
            session['reset_email'] = email

            flash("An OTP has been sent to your email to reset your password.", "info")
            return redirect(url_for('reset_password'))
        else:
            return render_template('forgot_password.html', error="No verified account found with this email.")

    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        otp = request.form['otp']
        new_password = request.form['new_password']

        if 'reset_email' in session:
            email = session['reset_email']
            user = db.session.query(User).filter_by(email=email).first()

            if user and str(user.verification_code) == otp:
                user.password = generate_password_hash(new_password)
                user.verification_code = None
                db.session.commit()

                session.pop('reset_email', None)
                flash("Your password has been reset. Please log in.", "success")
                return redirect(url_for('login'))
            else:
                return render_template('reset_password.html', error="Invalid OTP or email.")
    
    return render_template('reset_password.html')

@app.route('/fileshare', methods=['GET', 'POST'])
@login_required
def portal():
    username = session.get('username', 'Anonymous')
    try:
        user = User.query.filter_by(username=username).first()
        allowed_folders = {}

        # Build user folder access map - ONLY from predefined FOLDER_MAP
        if user.folders:
            for folder in user.folders.split(','):
                folder = folder.strip()
                # Only allow folders that exist in FOLDER_MAP and have valid IDs
                if folder in FOLDER_MAP and FOLDER_MAP[folder]['id'] and FOLDER_MAP[folder]['id'] != 'YOUR_ACTUAL_FOLDER_ID_HERE':
                    allowed_folders[folder] = FOLDER_MAP[folder]
                else:
                    # Silent warning - don't show flash messages for every missing folder
                    pass

        files = []
        selected_folder = request.form.get('folder') if request.method == 'POST' else request.args.get('folder')

        if selected_folder:
            if selected_folder not in allowed_folders:
                flash("❌ You do not have permission to access this folder or it doesn't exist.")
                return redirect(url_for('portal'))
            folder_id = allowed_folders[selected_folder]['id']

        if request.method == 'POST':
            action = request.form.get('action')
            
            if action == 'upload':
                uploaded_files = request.files.getlist('files')
                if uploaded_files:
                    successful_uploads = 0
                    
                    for file in uploaded_files:
                        if file and file.filename:
                            temp_file_path = None
                            try:
                                # Create temporary file with delete=False to prevent access conflicts
                                with tempfile.NamedTemporaryFile(delete=False, suffix='_' + secure_filename(file.filename)) as temp_file:
                                    file.save(temp_file.name)
                                    temp_file_path = temp_file.name

                                filename = secure_filename(file.filename)
                                
                                # Upload to Google Drive
                                metadata = {
                                    'name': filename, 
                                    'parents': [folder_id]
                                }
                                media = MediaFileUpload(temp_file_path)
                                
                                service.files().create(
                                    body=metadata, 
                                    media_body=media, 
                                    fields='id',
                                    supportsAllDrives=True
                                ).execute()

                                successful_uploads += 1
                                log_action('Upload', filename, selected_folder, username)

                            except Exception as e:
                                error_msg = str(e)
                                if "WinError 32" in error_msg:
                                    flash(f"❌ File access error for '{filename}'. Please try again.")
                                else:
                                    flash(f"❌ Failed to upload '{filename}': {error_msg}")
                            finally:
                                # Always clean up temporary file
                                if temp_file_path and os.path.exists(temp_file_path):
                                    try:
                                        os.unlink(temp_file_path)
                                    except:
                                        pass  # Ignore cleanup errors
                    
                    # Show summary
                    if successful_uploads > 0:
                        flash(f"✅ Successfully uploaded {successful_uploads} file(s) to '{selected_folder}'.")
                        
                else:
                    flash("⚠️ No files selected.")
                return redirect(url_for('portal', folder=selected_folder))

            elif action == 'download':
                file_id = request.form.get('file_id')
                filename = request.form.get('filename')

                request_drive = service.files().get_media(
                    fileId=file_id,
                    supportsAllDrives=True
                )
                file_stream = io.BytesIO()
                downloader = MediaIoBaseDownload(file_stream, request_drive)

                done = False
                while not done:
                    _, done = downloader.next_chunk()

                file_stream.seek(0)
                log_action('Download', filename, selected_folder, username)

                response = make_response(send_file(file_stream, as_attachment=True, download_name=filename))
                response.set_cookie("fileDownload", "true", max_age=5, path='/')
                return response

        # File listing
        if selected_folder and (request.method == 'GET' or request.form.get('action') == 'browse'):
            folder_id = allowed_folders[selected_folder]['id']
            query = f"'{folder_id}' in parents and trashed=false"
            
            files = service.files().list(
                q=query, 
                fields="files(id, name)",
                supportsAllDrives=True,
                includeItemsFromAllDrives=True
            ).execute().get('files', [])

        return render_template('index.html', folders=allowed_folders.keys(), files=files, selected_folder=selected_folder)

    except Exception as e:
        flash(f"❌ Error: {str(e)}")
        return redirect(url_for('portal'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if session.get('role') != 'admin':
        flash("❌ Unauthorized access.")
        return redirect('/')

    global FOLDER_MAP
    users = User.query.all()

    folder_access_user = None
    folder_access_list = []

    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('username')
        folder_name = request.form.get('folder')
        selected_folders = request.form.getlist('folders')
        new_folder_name = request.form.get('folder_name')
        check_user = request.form.get('check_user')

        if action == 'grant':
            user = User.query.filter_by(username=username).first()
            if user:
                current_access = [f.strip() for f in (user.folders.split(',') if user.folders else [])]
                # Only grant access to folders that exist in FOLDER_MAP
                valid_folders = []
                for folder in selected_folders:
                    if folder in FOLDER_MAP and FOLDER_MAP[folder]['id'] and FOLDER_MAP[folder]['id'] != 'YOUR_ACTUAL_FOLDER_ID_HERE':
                        if folder not in current_access:
                            current_access.append(folder)
                            valid_folders.append(folder)
                    else:
                        flash(f"⚠️ Folder '{folder}' is not available in the system and was skipped.", "warning")
                
                user.folders = ','.join(current_access)
                db.session.commit()
                if valid_folders:
                    flash(f"✅ Access granted to {username} for {', '.join(valid_folders)}.")

        elif action == 'remove':
            user = User.query.filter_by(username=username).first()
            if user:
                current_access = [f.strip() for f in (user.folders.split(',') if user.folders else [])]
                if folder_name in current_access:
                    current_access.remove(folder_name)
                    user.folders = ','.join(current_access)
                    db.session.commit()
                    flash(f"✅ Access removed from {username} for {folder_name}.")
                else:
                    flash(f"⚠️ {folder_name} was not in {username}'s access list.")

        elif action == 'make_admin':
            user = User.query.filter_by(username=username).first()
            if user:
                user.role = 'admin'
                db.session.commit()
                flash(f"✅ {username} promoted to Admin.")

        elif action == 'create_folder':
            if new_folder_name:
                folder_id = create_drive_folder(new_folder_name)
                if folder_id:
                    FOLDER_MAP[new_folder_name] = {'id': folder_id}
                    flash(f"✅ New Folder created: {new_folder_name} (ID: {folder_id})")
                else:
                    flash("❌ Failed to create folder.")
            else:
                flash("⚠️ Folder name cannot be empty.")

        elif action == 'check_access':
            folder_access_user = check_user
            user = User.query.filter_by(username=check_user).first()
            if user:
                folder_access_list = [f.strip() for f in (user.folders.split(',') if user.folders else [])]
            else:
                flash("⚠️ User not found.")

    # Only show folders that have valid IDs
    valid_folders = [folder for folder in FOLDER_MAP.keys() 
                    if FOLDER_MAP[folder]['id'] and FOLDER_MAP[folder]['id'] != 'YOUR_ACTUAL_FOLDER_ID_HERE']

    emails = [u.email for u in users if u.email]
    pic_rows = (
        db.session.query(UserProfile.Email_ID, UserProfile.Image_URL)
        .filter(UserProfile.Email_ID.in_(emails))
        .all()
    )
    pics = {row.Email_ID: row.Image_URL for row in pic_rows}

    user_data = []
    for u in users:
        folder_list = [f.strip() for f in (u.folders.split(',') if u.folders else [])]
        user_data.append({
            'username': u.username,
            'email': u.email,
            'role': u.role,
            'folders': folder_list,
            'image_url': pics.get(u.email)
        })

    user_folder_map = {
        u.username: [f.strip() for f in (u.folders.split(',') if u.folders else [])]
        for u in users
    }

    return render_template(
        'admin_dashboard.html',
        users=user_data,
        folders=valid_folders,
        folder_access_user=folder_access_user,
        folder_access_list=folder_access_list,
        user_folder_map=user_folder_map
    )

@app.route('/get-folder-id/<folder_name>')
@login_required
def get_folder_id(folder_name):
    """Get the ID of a folder by name in the Shared Drive"""
    try:
        query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and '{PARENT_FOLDER_ID}' in parents and trashed=false"
        
        results = service.files().list(
            q=query,
            fields="files(id, name)",
            supportsAllDrives=True,
            includeItemsFromAllDrives=True
        ).execute()
        
        folders = results.get('files', [])
        
        if folders:
            return jsonify({
                'status': 'success',
                'folder_name': folder_name,
                'folder_id': folders[0]['id']
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f"Folder '{folder_name}' not found in Shared Drive"
            })
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/diagnose-drives')
@login_required
def diagnose_drives():
    """Diagnose which Shared Drives are accessible"""
    try:
        results = service.drives().list(pageSize=20).execute()
        drives = results.get('drives', [])
        
        drive_info = []
        for drive in drives:
            drive_info.append({
                'name': drive['name'],
                'id': drive['id']
            })
        
        return jsonify({
            'status': 'success',
            'drives': drive_info
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/log', methods=['GET'])
@login_required
def log_page_with_data():
    if session.get('role') != 'admin':
        flash("❌ Unauthorized access. Admins only.")
        return redirect('/')

    if 'fetch_data' in request.args:
        query = """
            SELECT 
                id AS ID,
                username AS Username,
                activity AS Activity,
                filename AS Filename,
                folder_name AS Folder,
                start_date AS Tool_Start_Date,
                `Time` AS Time
            FROM mc.desktop_user_ip
            ORDER BY id DESC
        """
        try:
            with engine.connect() as connection:
                result = pd.read_sql(query, connection)

                for col in result.columns:
                    if pd.api.types.is_timedelta64_dtype(result[col]):
                        result[col] = result[col].astype(str)
                    elif pd.api.types.is_datetime64_any_dtype(result[col]):
                        result[col] = result[col].astype(str)
                    elif result[col].dtype == object:
                        result[col] = result[col].apply(lambda x: str(x) if isinstance(x, (np.timedelta64, pd.Timedelta)) else x)

                return jsonify(result.to_dict(orient='records'))
        except Exception as e:
            error_message = traceback.format_exc()
            return jsonify({"error": str(e), "trace": error_message}), 500

    return '''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>File Sharing Logs</title>

  <link rel="icon" href="https://storage.googleapis.com/my-react-image-bucket-123/DS_Logos/Logo_Favicon/DSFileshare_Favicon.png" type="image/x-icon">

  <!-- Bootstrap CSS -->
  <link
    href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
    rel="stylesheet"
  >

  <!-- Bootstrap Icons -->
  <link
    rel="stylesheet"
    href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css"
  >

  <!-- DataTables CSS -->
  <link
    href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css"
    rel="stylesheet"
  >

  <!-- jQuery & DataTables JS -->
  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
  <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>

  <style>
    body {
      font-family: "Segoe UI", system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      background: radial-gradient(circle at top, #2563eb 0, #020617 55%, #020617 100%);
      min-height: 100vh;
      padding: 30px 15px;
      color: #e5e7eb;
    }

    .page-wrapper {
      max-width: 1250px;
      margin: 0 auto;
    }

    .card-logs {
      background: rgba(15, 23, 42, 0.9);
      border-radius: 20px;
      box-shadow: 0 20px 45px rgba(37, 99, 235, 0.4);
      padding: 24px 24px 18px;
      border: 1px solid rgba(148, 163, 184, 0.4);
      backdrop-filter: blur(14px);
    }

    .btn-back {
      background: linear-gradient(to right, #38bdf8, #0ea5e9);
      border: none;
      border-radius: 999px;
      padding: 8px 16px;
      font-size: 0.9rem;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      color: #0b1220;
      text-decoration: none;
      box-shadow: 0 8px 18px rgba(56, 189, 248, 0.35);
      margin-bottom: 15px;
    }

    .btn-back:hover {
      background: linear-gradient(to right, #0ea5e9, #2563eb);
    }

    .page-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      gap: 12px;
      margin-bottom: 14px;
      flex-wrap: wrap;
    }

    .page-title {
      font-size: 1.7rem;
      font-weight: 700;
      color: #ffffff;
      margin-bottom: 2px;
    }

    .page-subtitle {
      font-size: 0.9rem;
      color: #cbd5e1;
      margin: 0;
    }

    .btn-reset {
      border-radius: 999px;
      font-size: 0.85rem;
      padding: 6px 14px;
      border: 1px solid #60a5fa;
      color: #e5f2ff;
      background: rgba(15, 23, 42, 0.8);
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .btn-reset:hover {
      background: rgba(37, 99, 235, 0.9);
      color: #ffffff;
    }

    .table-responsive {
      border-radius: 14px;
      overflow: hidden;
      border: 1px solid rgba(148, 163, 184, 0.3);
      background: rgba(15, 23, 42, 0.95);
    }

    /* TABLE BASE */
    #log-table {
      width: 100% !important;
      table-layout: fixed; /* standard column width, no x-scroll */
    }

    /* Header */
    table.dataTable thead th {
      background: linear-gradient(to right, #1d4ed8, #3b82f6);
      color: #ffffff !important;
      text-transform: uppercase;
      font-weight: 600;
      border-bottom: none !important;
      padding: 9px 10px;
      font-size: 0.78rem;
    }

    /* Column width hints */
    th:nth-child(1) { width: 6%; }   /* ID */
    th:nth-child(2) { width: 14%; }  /* Name */
    th:nth-child(3) { width: 12%; }  /* Activity */
    th:nth-child(4) { width: 34%; }  /* Filename */
    th:nth-child(5) { width: 14%; }  /* Folder */
    th:nth-child(6) { width: 10%; }  /* Date */
    th:nth-child(7) { width: 10%; }  /* Time */

    /* Body rows */
    table.dataTable tbody td {
      color: #ffffff !important;
      background-color: rgba(15, 23, 42, 0.92) !important;
      padding: 7px 10px;
      border-color: rgba(51, 65, 85, 0.85) !important;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;  /* text cut with ... */
      font-size: 0.88rem;
    }

    table.dataTable tbody tr:nth-child(even) td {
      background-color: rgba(21, 32, 72, 0.96) !important;
    }

    /* Hover: light blue */
    table.dataTable tbody tr:hover td {
      background-color: rgba(96, 165, 250, 0.28) !important;
      cursor: pointer;
    }

    /* Date/Time center aligned */
    td.col-date,
    td.col-time {
      text-align: center !important;
    }
    th.col-date,
    th.col-time {
      text-align: center !important;
    }

    /* Column filter dropdown */
    .column-filter {
      margin-top: 6px;
      font-size: 0.75rem;
      background-color: rgba(15, 23, 42, 0.95) !important;
      color: #ffffff !important;
      border: 1px solid #60a5fa !important;
      border-radius: 4px;
      padding: 2px 4px;
    }

    .column-filter option {
      background-color: #020617;
      color: #ffffff;
    }

    /* Search bar */
    #log-table_filter label {
      color: #ffffff !important;
      font-size: 0.9rem;
    }

    #log-table_filter input[type="search"] {
      background-color: rgba(15, 23, 42, 0.95);
      border: 1px solid #60a5fa;
      color: #ffffff !important;
      border-radius: 999px;
      padding: 5px 32px 5px 12px;
      min-width: 240px;
      font-size: 0.9rem;
    }

    #log-table_filter input[type="search"]::placeholder {
      color: #9ca3af;
    }

    /* Remove browser default X */
    #log-table_filter input[type="search"]::-webkit-search-cancel-button {
      appearance: none;
      display: none;
    }

    .search-wrapper {
      position: relative;
      display: inline-flex;
      align-items: center;
    }

    .clear-search-btn {
      position: absolute;
      right: 8px;
      border: none;
      background: transparent;
      padding: 0;
      cursor: pointer;
    }

    .clear-search-btn i {
      color: #60a5fa;
      font-size: 1rem;
    }

    .clear-search-btn:hover i {
      color: #f97373;
    }

    /* Pagination */
    .dataTables_info {
      color: #e5e7eb !important;
      font-size: 0.8rem;
    }

    .dataTables_paginate .paginate_button {
      color: #e5e7eb !important;
      font-size: 0.8rem;
    }

    .dataTables_paginate .paginate_button.current {
      background: #2563eb !important;
      color: #ffffff !important;
      border: none !important;
    }

    .dataTables_paginate .paginate_button:hover {
      background: #1d4ed8 !important;
      color: #ffffff !important;
      border: none !important;
    }
  </style>
</head>
<body>

  <div class="page-wrapper">
    <div class="card-logs">

      <a href="/admin" class="btn-back">
        <i class="bi bi-arrow-left"></i> Back to Admin Dashboard
      </a>

      <div class="page-header">
        <div>
          <h1 class="page-title">File Sharing Logs</h1>
          <p class="page-subtitle">Monitor all file sharing activities with filters and search.</p>
        </div>
        <button id="reset-filters" class="btn-reset">
          <i class="bi bi-arrow-counterclockwise"></i>
          Reset Filters
        </button>
      </div>

      <div class="table-responsive">
        <table id="log-table" class="display table table-bordered align-middle">
          <thead><tr id="table-head"></tr></thead>
          <tbody id="table-body"></tbody>
        </table>
      </div>

    </div>
  </div>

<script>
async function fetchData() {
  try {
    const response = await $.get('/log?fetch_data=true');
    populateTable(response || []);
  } catch (error) {
    console.error(error);
    alert("Failed to load logs.");
  }
}

function populateTable(data) {
  const tableHead = $('#table-head');
  const tableBody = $('#table-body');
  const columnOrder = ["ID", "Name", "Activity", "Filename", "Folder", "Date", "Time"];

  tableHead.empty();
  tableBody.empty();

  if (!data || data.length === 0) {
    tableBody.append('<tr><td colspan="7" class="text-center text-white">No data available</td></tr>');
    return;
  }

  // Build header
  columnOrder.forEach(col => {
    let cls = "";
    if (col === "Date") cls = "col-date";
    if (col === "Time") cls = "col-time";

    tableHead.append(`
      <th class="${cls}">
        ${col}
        <br>
        <select class="column-filter" data-column="${col}">
          <option value="">All</option>
        </select>
      </th>
    `);
  });

  const displayRows = [];

  // Build rows
  data.forEach(row => {
    const tr = $('<tr></tr>');
    const displayRow = {};

    columnOrder.forEach(col => {
      let value = "";

      if (col === "ID") {
        value = row["ID"];
      } else if (col === "Name") {
        value = row["Username"];
      } else if (col === "Activity") {
        value = row["Activity"];
      } else if (col === "Filename") {
        value = row["Filename"];
      } else if (col === "Folder") {
        value = row["Folder"];
      } else if (col === "Date") {
        const d = new Date(row["Tool_Start_Date"]);
        if (!isNaN(d)) {
          value = d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
        }
      } else if (col === "Time") {
        let t = row["Time"] || "";
        if (typeof t === "string" && t.includes("days")) {
          const parts = t.split(" ");
          t = parts[2] || t;
        }
        value = t;
      }

      if (value === undefined || value === null) value = "";

      displayRow[col] = String(value);

      const safeTitle = String(value).replace(/"/g, '&quot;');
      let tdClass = "";
      if (col === "Date") tdClass = "col-date";
      if (col === "Time") tdClass = "col-time";

      tr.append(`<td class="${tdClass}" title="${safeTitle}">${value}</td>`);
    });

    displayRows.push(displayRow);
    tableBody.append(tr);
  });

  const table = $('#log-table').DataTable({
    destroy: true,
    pageLength: 10,
    ordering: true,
    order: [[0, "desc"]],
    searching: true
  });

  // Column filters from display values
  columnOrder.forEach((header, index) => {
    const select = $(`select[data-column="${header}"]`);
    const uniqueValues = [...new Set(displayRows.map(r => r[header]).filter(v => v))].sort();

    uniqueValues.forEach(v => {
      select.append(`<option value="${v}">${v}</option>`);
    });

    select.on("change", function () {
      const val = $(this).val();
      table.column(index).search(val).draw();
    });
  });

  // Search wrapper + X button
  const filterInput = $('#log-table_filter input[type="search"]');
  filterInput.wrap('<span class="search-wrapper"></span>');
  const wrapper = $('.search-wrapper');

  wrapper.append(`
    <button type="button" class="clear-search-btn" id="clear-search-btn">
      <i class="bi bi-x-circle-fill"></i>
    </button>
  `);

  $('#clear-search-btn').on('click', function () {
    filterInput.val('');
    table.search('').draw();
  });

  // Reset Filters button – clears all filters + search
  $('#reset-filters').off('click').on('click', function () {
    $('.column-filter').val('');
    filterInput.val('');
    table.search('');
    table.columns().search('');
    table.draw();
  });
}

fetchData();
</script>

</body>
</html>


    '''

# === Main Application ===
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)