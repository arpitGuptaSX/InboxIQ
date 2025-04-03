from flask import Flask, redirect, url_for, session, request, render_template
from flask_session import Session
import requests
import os
import json
import base64
import mimetypes
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from werkzeug.utils import secure_filename
import datetime
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)  # Enables CORS for all routes

# Configuration
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your-secret-key")
app.config["SESSION_TYPE"] = os.getenv("SESSION_TYPE", "filesystem")
app.config["UPLOAD_FOLDER"] = "uploads"
Session(app)

# Create uploads folder if it doesn't exist
if not os.path.exists(app.config["UPLOAD_FOLDER"]):
    os.makedirs(app.config["UPLOAD_FOLDER"])

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "https://inboxiq-kuey.onrender.com/auth/callback")

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'jpeg', 'png'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login")
def login():
    google_auth_url = (
        "https://accounts.google.com/o/oauth2/auth"
        "?response_type=code"
        f"&client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        "&scope=openid%20email%20profile%20https://mail.google.com/"
        "&access_type=offline"
        "&prompt=consent"
    )
    return redirect(google_auth_url)

@app.route("/auth/callback")
def auth_callback():
    code = request.args.get("code")
    if not code:
        return "Authorization code not received", 400

    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    
    token_response = requests.post(token_url, data=token_data)
    token_json = token_response.json()
    
    access_token = token_json.get("access_token")
    refresh_token = token_json.get("refresh_token")
    expires_in = token_json.get("expires_in")
    
    if not access_token:
        return "Authentication failed. Please try again.", 400

    # Get user info
    user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    user_info_response = requests.get(
        user_info_url, 
        headers={"Authorization": f"Bearer {access_token}"}
    )
    
    user_info = user_info_response.json()
    email = user_info.get("email")

    if not email:
        return "Failed to retrieve user email.", 400
    
    # Store in session
    session["email"] = email
    session["access_token"] = access_token
    session["refresh_token"] = refresh_token
    session["token_expiry"] = datetime.datetime.now().timestamp() + expires_in

    return redirect(url_for("dashboard"))

@app.route("/dashboard")
def dashboard():
    if "email" not in session:
        return redirect(url_for("login"))
    
    email = session.get("email")
    return render_template("index2.html", email=email)

@app.route("/upload", methods=["POST"])
def upload_file():
    if "email" not in session or "access_token" not in session:
        return redirect(url_for("login"))
    
    access_token = session["access_token"]
    email = session["email"]
    
    recipient = request.form.get("recipient", "")
    subject = request.form.get("subject", "")
    body = request.form.get("body", "")
    action = request.form.get("action", "draft")  # Either 'draft' or 'send'
    
    # Check if file part exists
    if 'file' not in request.files:
        return "No file part", 400
    
    file = request.files['file']
    
    # If user doesn't select a file
    if file.filename == '':
        return "No selected file", 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Create email with attachment
        result = create_email(access_token, recipient, subject, body, filepath, action)
        
        # Remove the temporary file
        os.remove(filepath)
        
        if result:
            action_msg = "created and saved as draft" if action == "draft" else "sent"
            return f"Email successfully {action_msg}", 200
        else:
            return "Error processing your request", 500
    
    return "File type not allowed", 400

def create_email(access_token, to, subject, body, file_path, action="draft"):
    """Create an email with attachment and either save as draft or send it"""
    try:
        # Create message container
        message = MIMEMultipart()
        message['to'] = to
        message['subject'] = subject
        
        # Add body to email
        message.attach(MIMEText(body))
        
        # Add attachment to email
        with open(file_path, 'rb') as file:
            attachment = MIMEApplication(file.read())
            filename = os.path.basename(file_path)
            attachment.add_header('Content-Disposition', 'attachment', filename=filename)
            message.attach(attachment)
        
        # Encode the message
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
        
        # Create the draft or send the email using Gmail API
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        if action == "draft":
            # Create a draft
            url = "https://gmail.googleapis.com/gmail/v1/users/me/drafts"
            data = json.dumps({"message": {"raw": raw_message}})
        else:
            # Send the email
            url = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
            data = json.dumps({"raw": raw_message})
        
        response = requests.post(url, headers=headers, data=data)
        return response.status_code == 200
        
    except Exception as e:
        print(f"Error creating email: {str(e)}")
        return False

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)
