import os
import logging
import urllib.parse
from flask import Flask, request, jsonify, session, redirect, url_for, render_template, Response
from werkzeug.utils import secure_filename
import pandas as pd
import gspread
from google.oauth2.credentials import Credentials as UserCredentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import json
from datetime import datetime
from googleapiclient.errors import HttpError
import time
import base64
from io import BytesIO
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s: %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Flask app configuration
app = Flask(__name__, template_folder='templates')
app.secret_key = 'your-secret-key-here-change-in-production'

# Upload configuration
UPLOAD_FOLDER = 'tmp'
ALLOWED_EXTENSIONS = {'xlsx', 'xls', 'csv', 'xlsm', 'xltx', 'xltm'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Google API scopes
SCOPES = [
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/spreadsheets'
]

def get_credentials_file():
    """Get the path to the credentials file"""
    possible_paths = [
        'credentials.json',
        os.path.join(os.path.dirname(__file__), 'credentials.json'),
        '/home/tongtongtong/mysite/credentials.json'
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    
    return None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def read_excel_file(file_path):
    """Read Excel file and return data"""
    try:
        if file_path.endswith('.csv'):
            try:
                df = pd.read_csv(file_path, encoding='utf-8')
            except UnicodeDecodeError:
                df = pd.read_csv(file_path, encoding='latin-1')
        else:
            df = pd.read_excel(file_path)
        
        return {
            'success': True,
            'data': df.to_dict('records'),
            'columns': df.columns.tolist()
        }
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return {
            'success': False,
            'error': str(e)
        }

# Routes
@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/login')
def login():
    """Start OAuth2 flow"""
    try:
        credentials_file = get_credentials_file()
        if not credentials_file:
            return jsonify({
                'success': False,
                'error': 'Credentials file not found'
            }), 500
        
        flow = Flow.from_client_secrets_file(
            credentials_file,
            scopes=SCOPES,
            redirect_uri=url_for('oauth2callback', _external=True)
        )
        
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        
        session['state'] = state
        return redirect(authorization_url)
        
    except Exception as e:
        logger.error(f"Error in login: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/oauth2callback')
def oauth2callback():
    """Handle OAuth2 callback"""
    try:
        state = session.get('state')
        if not state:
            return jsonify({'error': 'State not found in session'}), 400
        
        credentials_file = get_credentials_file()
        if not credentials_file:
            return jsonify({'error': 'Credentials file not found'}), 500
        
        flow = Flow.from_client_secrets_file(
            credentials_file,
            scopes=SCOPES,
            state=state,
            redirect_uri=url_for('oauth2callback', _external=True)
        )
        
        flow.fetch_token(authorization_response=request.url)
        
        credentials = flow.credentials
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
        
        return redirect(url_for('index'))
        
    except Exception as e:
        logger.error(f"Error in oauth2callback: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/logout')
def logout():
    """Clear session"""
    session.clear()
    return redirect(url_for('index'))

@app.route('/force_reauth')
def force_reauth():
    """Force re-authentication"""
    session.clear()
    return redirect(url_for('login'))

@app.route('/clear_session')
def clear_session():
    """Clear session endpoint"""
    session.clear()
    return jsonify({'success': True, 'message': 'Session cleared'})

@app.route('/session/status', methods=['GET'])
def session_status():
    """Check session status"""
    credentials = get_user_credentials_from_session()
    if credentials:
        try:
            # Test credentials by making a simple API call
            drive = build('drive', 'v3', credentials=credentials)
            drive.about().get(fields="user").execute()
            return jsonify({'authenticated': True})
        except Exception as e:
            logger.error(f"Credentials test failed: {e}")
            return jsonify({'authenticated': False})
    else:
        return jsonify({'authenticated': False})

def get_user_credentials_from_session():
    """Get user credentials from session"""
    if 'credentials' not in session:
        return None
    
    try:
        credentials = UserCredentials(
            token=session['credentials']['token'],
            refresh_token=session['credentials']['refresh_token'],
            token_uri=session['credentials']['token_uri'],
            client_id=session['credentials']['client_id'],
            client_secret=session['credentials']['client_secret'],
            scopes=session['credentials']['scopes']
        )
        
        if credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            session['credentials']['token'] = credentials.token
        
        return credentials
        
    except Exception as e:
        logger.error(f"Error getting credentials: {e}")
        return None

def get_drive_service():
    """Get Google Drive service"""
    credentials = get_user_credentials_from_session()
    if not credentials:
        return None
    return build('drive', 'v3', credentials=credentials)

def ensure_anyone_reader_permission(drive, file_id):
    """Ensure file has anyone with link can view permission"""
    try:
        permission = {
            'role': 'reader',
            'type': 'anyone'
        }
        drive.permissions().create(fileId=file_id, body=permission).execute()
        logger.info(f"Added anyone reader permission to {file_id}")
    except Exception as e:
        logger.warning(f"Could not add anyone permission to {file_id}: {e}")

def build_file_link(item_id: str, mime_type: str) -> str:
    """Build appropriate link for file based on mime type"""
    if 'spreadsheet' in mime_type:
        return f"https://docs.google.com/spreadsheets/d/{item_id}/edit"
    elif 'document' in mime_type:
        return f"https://docs.google.com/document/d/{item_id}/edit"
    elif 'presentation' in mime_type:
        return f"https://docs.google.com/presentation/d/{item_id}/edit"
    else:
        return f"https://drive.google.com/file/d/{item_id}/view"

def extract_drive_id(value: str) -> str:
    """Extract Google Drive ID from various URL formats"""
    if not value:
        return value
    
    v = str(value).strip()
    
    if all(c.isalnum() or c in ['-', '_'] for c in v) and len(v) >= 10 and 'http' not in v and '/' not in v:
        return v
    
    import re
    patterns = [
        r'https?://drive\.google\.com/file/d/([A-Za-z0-9_-]+)',
        r'https?://drive\.google\.com/drive/folders/([A-Za-z0-9_-]+)',
        r'https?://drive\.google\.com/open\?[^#]*[?&]id=([A-Za-z0-9_-]+)',
        r'https?://drive\.google\.com/uc\?[^#]*[?&]id=([A-Za-z0-9_-]+)',
        r'https?://docs\.google\.com/[^/]+/d/([A-Za-z0-9_-]+)'
    ]
    
    for pat in patterns:
        m = re.search(pat, v)
        if m:
            return m.group(1)
    
    m = re.search(r'[?&]id=([A-Za-z0-9_-]{10,})', v)
    if m:
        return m.group(1)
    
    return v

def get_item_metadata(drive, file_id):
    """Get metadata for a Drive item"""
    try:
        return drive.files().get(fileId=file_id, fields='id,name,mimeType,parents').execute()
    except Exception as e:
        logger.error(f"Error getting metadata for {file_id}: {e}")
        return None

def copy_single_file(drive, source_meta, target_folder_id=None, new_name=None):
    """Copy a single file"""
    try:
        body = {'name': new_name or source_meta['name']}
        if target_folder_id:
            body['parents'] = [target_folder_id]
        
        copied_file = drive.files().copy(fileId=source_meta['id'], body=body).execute()
        ensure_anyone_reader_permission(drive, copied_file['id'])
        
        return copied_file
    except Exception as e:
        logger.error(f"Error copying file {source_meta['name']}: {e}")
        return None

def create_folder(drive, name, parent_id=None):
    """Create a new folder"""
    body = {
        'name': name,
        'mimeType': 'application/vnd.google-apps.folder'
    }
    if parent_id:
        body['parents'] = [parent_id]
    
    try:
        folder = drive.files().create(body=body).execute()
        ensure_anyone_reader_permission(drive, folder['id'])
        return folder
    except Exception as e:
        logger.error(f"Error creating folder {name}: {e}")
        return None

def list_children(drive, folder_id):
    """List children of a folder"""
    try:
        results = drive.files().list(
            q=f"'{folder_id}' in parents and trashed=false",
            fields="files(id,name,mimeType)"
        ).execute()
        return results.get('files', [])
    except Exception as e:
        logger.error(f"Error listing children of {folder_id}: {e}")
        return []

def copy_folder_recursive(drive, source_meta, target_folder_id=None, new_name=None):
    """Recursively copy a folder and its contents"""
    try:
        new_folder = create_folder(drive, new_name or source_meta['name'], target_folder_id)
        if not new_folder:
            return None
        
        children = list_children(drive, source_meta['id'])
        for child in children:
            if child['mimeType'] == 'application/vnd.google-apps.folder':
                copy_folder_recursive(drive, child, new_folder['id'])
            else:
                copy_single_file(drive, child, new_folder['id'])
        
        return new_folder
    except Exception as e:
        logger.error(f"Error copying folder {source_meta['name']}: {e}")
        return None

@app.route('/copy', methods=['GET', 'POST'])
def copy_drive():
    """Copy Google Drive files/folders"""
    if request.method == 'GET':
        return render_template('copy.html')
    
    try:
        drive = get_drive_service()
        if not drive:
            return jsonify({
                'success': False,
                'error': 'Not authenticated. Please login first.'
            }), 401
        
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        source_id = extract_drive_id(data.get('source_id', ''))
        target_folder_id = extract_drive_id(data.get('target_folder_id', '')) or None
        new_name = data.get('new_name', '').strip() or None
        
        if not source_id:
            return jsonify({
                'success': False,
                'error': 'Source ID is required'
            }), 400
        
        source_meta = get_item_metadata(drive, source_id)
        if not source_meta:
            return jsonify({
                'success': False,
                'error': 'Source file/folder not found or not accessible'
            }), 404
        
        if source_meta['mimeType'] == 'application/vnd.google-apps.folder':
            result = copy_folder_recursive(drive, source_meta, target_folder_id, new_name)
        else:
            result = copy_single_file(drive, source_meta, target_folder_id, new_name)
        
        if result:
            link = build_file_link(result['id'], result.get('mimeType', ''))
            return jsonify({
                'success': True,
                'result': {
                    'id': result['id'],
                    'name': result['name'],
                    'link': link,
                    'mimeType': result.get('mimeType', '')
                }
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to copy item'
            }), 500
            
    except Exception as e:
        logger.error(f"Error in copy_drive: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Webhook endpoint for automatic deployment
@app.route('/update_server', methods=['POST'])
def update_server():
    """
    Webhook endpoint để tự động cập nhật server khi có push từ GitHub
    """
    import hmac
    import hashlib
    import subprocess
    import requests
    
    try:
        # Lấy secret từ environment variable
        webhook_secret = os.environ.get('WEBHOOK_SECRET')
        if not webhook_secret:
            logger.error("WEBHOOK_SECRET not found in environment variables")
            return jsonify({'error': 'Webhook secret not configured'}), 500
        
        # Xác thực webhook từ GitHub
        signature = request.headers.get('X-Hub-Signature-256')
        if not signature:
            logger.error("No signature found in webhook request")
            return jsonify({'error': 'No signature'}), 401
        
        # Tính toán signature
        payload = request.get_data()
        expected_signature = 'sha256=' + hmac.new(
            webhook_secret.encode('utf-8'),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        # So sánh signature
        if not hmac.compare_digest(signature, expected_signature):
            logger.error("Invalid webhook signature")
            return jsonify({'error': 'Invalid signature'}), 401
        
        # Parse JSON payload
        payload_data = request.get_json()
        if not payload_data:
            logger.error("No JSON payload found")
            return jsonify({'error': 'No payload'}), 400
        
        # Chỉ xử lý push events đến main branch
        if payload_data.get('ref') != 'refs/heads/main':
            logger.info(f"Ignoring push to branch: {payload_data.get('ref')}")
            return jsonify({'message': 'Ignored - not main branch'}), 200
        
        logger.info("Valid webhook received, starting update process...")
        
        # Chạy script update.sh
        script_path = '/home/tongtongtong/mysite/update.sh'
        result = subprocess.run(['bash', script_path], 
                              capture_output=True, 
                              text=True, 
                              timeout=300)  # 5 minutes timeout
        
        if result.returncode != 0:
            logger.error(f"Update script failed: {result.stderr}")
            return jsonify({
                'error': 'Update script failed',
                'stderr': result.stderr,
                'stdout': result.stdout
            }), 500
        
        logger.info("Update script completed successfully")
        
        # Reload web app bằng PythonAnywhere API
        api_token = os.environ.get('PA_API_TOKEN')
        username = os.environ.get('PA_USERNAME', 'tongtongtong')
        
        if api_token:
            reload_url = f'https://www.pythonanywhere.com/api/v0/user/{username}/webapps/{username}.pythonanywhere.com/reload/'
            headers = {'Authorization': f'Token {api_token}'}
            
            try:
                reload_response = requests.post(reload_url, headers=headers, timeout=30)
                if reload_response.status_code == 200:
                    logger.info("Web app reloaded successfully")
                else:
                    logger.warning(f"Failed to reload web app: {reload_response.status_code}")
            except Exception as e:
                logger.warning(f"Failed to reload web app: {e}")
        
        return jsonify({
            'success': True,
            'message': 'Server updated successfully',
            'stdout': result.stdout
        }), 200
        
    except subprocess.TimeoutExpired:
        logger.error("Update script timed out")
        return jsonify({'error': 'Update script timed out'}), 500
    except Exception as e:
        logger.error(f"Error in webhook handler: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)