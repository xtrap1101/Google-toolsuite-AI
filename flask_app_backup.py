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

# Imports for chart generation
import base64
from io import BytesIO
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s: %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Khởi tạo Flask app
app = Flask(__name__, template_folder='templates')
app.secret_key = 'your-secret-key-here-change-in-production'

# Cấu hình upload
UPLOAD_FOLDER = 'tmp'
ALLOWED_EXTENSIONS = {'xlsx', 'xls', 'csv', 'xlsm', 'xltx', 'xltm'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Tạo thư mục upload nếu chưa có
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Google OAuth configuration
SCOPES = [
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/spreadsheets'
]

def get_credentials_file():
    """Tìm file credentials phù hợp - CHỈ dùng OAuth cho web app"""
    # Ưu tiên OAuth credentials cho web app
    oauth_files = [
        'credentials_oauth.json',
        'credentials_local.json'
    ]
    
    # Kiểm tra OAuth files trước
    for filename in oauth_files:
        if os.path.exists(filename):
            logger.info(f"Using OAuth credentials file: {filename}")
            return filename
    
    logger.error("No OAuth credentials file found")
    return None

def allowed_file(filename):
    """Kiểm tra file extension có được phép không"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def read_excel_file(file_path):
    """Đọc file Excel và trả về DataFrame"""
    try:
        ext = os.path.splitext(file_path)[1].lower()
        if ext == '.csv':
            # Ưu tiên đọc với UTF-8 có BOM để tránh lỗi tên cột lạ
            try:
                df = pd.read_csv(file_path, encoding='utf-8-sig')
            except UnicodeDecodeError:
                df = pd.read_csv(file_path)
        elif ext in ('.xlsx', '.xlsm', '.xltx', '.xltm'):
            # Chỉ định engine openpyxl cho các định dạng Excel hiện đại
            df = pd.read_excel(file_path, engine='openpyxl')
        elif ext in ('.xls',):
            # Chỉ định engine xlrd cho định dạng Excel cũ
            df = pd.read_excel(file_path, engine='xlrd')
        else:
            return {
                'success': False,
                'error': 'Định dạng file không được hỗ trợ'
            }
        
        return {
            'success': True,
            'data': df
        }
    except ImportError as e:
        logger.error(f"Missing Excel dependency: {e}")
        return {
            'success': False,
            'error': 'Thiếu thư viện đọc Excel. Vui lòng cài openpyxl (cho .xlsx) hoặc xlrd (cho .xls).'
        }
    except Exception as e:
        logger.error(f"Error reading Excel file: {e}")
        return {
            'success': False,
            'error': str(e)
        }

# ==================== ROUTES ====================

@app.route('/')
def index():
    """Trang chủ với menu điều hướng"""
    logged_in = 'credentials' in session
    return render_template('index.html', logged_in=logged_in)

@app.route('/login')
def login():
    """Bắt đầu quá trình OAuth với Google"""
    try:
        # Cho phép HTTP trong môi trường local dev để vượt qua yêu cầu HTTPS của oauthlib
        if not request.is_secure:
            os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
        credentials_file = get_credentials_file()
        if not credentials_file:
            return jsonify({
                'success': False,
                'error': 'Không tìm thấy file credentials'
            }), 500
        
        # Kiểm tra loại credentials file
        with open(credentials_file, 'r') as f:
            creds_data = json.load(f)
        
        # Nếu là service account, không thể dùng OAuth flow
        if creds_data.get('type') == 'service_account':
            return jsonify({
                'success': False,
                'error': 'Cần OAuth credentials cho web app, không phải service account. Vui lòng tạo OAuth 2.0 Client ID trong Google Cloud Console.'
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
            'error': f'Lỗi đăng nhập: {str(e)}'
        }), 500

@app.route('/oauth2callback')
def oauth2callback():
    """Xử lý callback từ Google OAuth"""
    try:
        # Cho phép HTTP trong môi trường local dev khi xử lý callback
        if not request.is_secure:
            os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
        state = session.get('state')
        if not state or state != request.args.get('state'):
            return jsonify({
                'success': False,
                'error': 'Invalid state parameter'
            }), 400
        
        credentials_file = get_credentials_file()
        if not credentials_file:
            return jsonify({
                'success': False,
                'error': 'Không tìm thấy file credentials'
            }), 500
        
        flow = Flow.from_client_secrets_file(
            credentials_file,
            scopes=SCOPES,
            state=state,
            redirect_uri=url_for('oauth2callback', _external=True)
        )
        
        flow.fetch_token(authorization_response=request.url)
        
        # Lưu credentials vào session
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
            'error': f'Lỗi xác thực: {str(e)}'
        }), 400

@app.route('/logout')
def logout():
    """Đăng xuất"""
    session.clear()
    return redirect(url_for('index'))

@app.route('/force_reauth')
def force_reauth():
    """Buộc xác thực lại - clear session và redirect về login"""
    session.clear()
    logger.info("Session cleared - forcing re-authentication")
    return jsonify({
        'success': True,
        'message': 'Session đã được clear. Vui lòng đăng nhập lại.',
        'redirect_url': url_for('login')
    })

@app.route('/clear_session')
def clear_session():
    """API endpoint để clear OAuth session"""
    session.clear()
    logger.info("OAuth session cleared via API")
    return jsonify({
        'success': True,
        'message': 'OAuth session đã được clear thành công'
    })

# New: session status endpoint for frontend auth check
@app.route('/session/status', methods=['GET'])
def session_status():
    try:
        creds = get_user_credentials_from_session()
        logged_in = creds is not None
        user = None
        if logged_in:
            try:
                drive = build('drive', 'v3', credentials=creds)
                about = drive.about().get(fields='user(displayName, emailAddress)').execute()
                user = about.get('user', {})
            except Exception:
                user = None
        return jsonify({
            'success': True,
            'logged_in': logged_in,
            'user': user,
            'login_url': url_for('login')
        })
    except Exception as e:
        return jsonify({'success': False, 'logged_in': False, 'error': str(e)}), 500

# Helpers for Google Drive service

def get_user_credentials_from_session():
    creds_data = session.get('credentials')
    if not creds_data:
        return None
    creds = UserCredentials(
        token=creds_data.get('token'),
        refresh_token=creds_data.get('refresh_token'),
        token_uri=creds_data.get('token_uri'),
        client_id=creds_data.get('client_id'),
        client_secret=creds_data.get('client_secret'),
        scopes=creds_data.get('scopes'),
    )
    # Refresh token if needed
    try:
        if not creds.valid and creds.refresh_token:
            creds.refresh(Request())
            # Persist refreshed token back to session
            session['credentials'] = {
                'token': creds.token,
                'refresh_token': creds.refresh_token,
                'token_uri': creds.token_uri,
                'client_id': creds.client_id,
                'client_secret': creds.client_secret,
                'scopes': creds.scopes,
            }
    except Exception as _:
        logger.exception("Failed to refresh OAuth token")
    return creds


def get_drive_service():
    creds = get_user_credentials_from_session()
    if not creds:
        return None
    service = build('drive', 'v3', credentials=creds)
    return service


def ensure_anyone_reader_permission(drive, file_id):
    try:
        drive.permissions().create(
            fileId=file_id,
            body={'type': 'anyone', 'role': 'reader'},
            fields='id',
            supportsAllDrives=True,
        ).execute()
    except HttpError as e:
        # Ignore if permission already exists or not allowed
        logger.warning(f"Set permission warning for {file_id}: {e}")


def build_file_link(item_id: str, mime_type: str) -> str:
    if mime_type == 'application/vnd.google-apps.folder':
        return f"https://drive.google.com/drive/folders/{item_id}?usp=sharing"
    return f"https://drive.google.com/file/d/{item_id}/view?usp=sharing"

# Helper: Extract Google Drive file/folder ID from raw ID or various URL formats
# Accepts raw ID or URLs like:
# - https://drive.google.com/file/d/{ID}/view
# - https://drive.google.com/drive/folders/{ID}
# - https://drive.google.com/open?id={ID}
# - https://drive.google.com/uc?id={ID}&export=download
# - https://docs.google.com/spreadsheets/d/{ID}/edit
# If no pattern matches, returns the original string.
def extract_drive_id(value: str) -> str
    if not value:
        return value
    v = str(value).strip()
    # Already looks like a plain ID
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
    # Fallback: id= query param
    m = re.search(r'[?&]id=([A-Za-z0-9_-]{10,})', v)
    if m:
        return m.group(1)
    return v


def get_item_metadata(drive, file_id):
    return drive.files().get(
        fileId=file_id,
        fields='id, name, mimeType, parents',
        supportsAllDrives=True,
    ).execute()


def copy_single_file(drive, source_meta, target_folder_id=None, new_name=None):
    body = {'name': new_name or source_meta['name']}
    # If target_folder_id provided, place copy there, else keep same parents or root
    if target_folder_id:
        body['parents'] = [target_folder_id]
    elif source_meta.get('parents'):
        body['parents'] = source_meta.get('parents')
    else:
        body['parents'] = ['root']
    copied = drive.files().copy(
        fileId=source_meta['id'],
        body=body,
        fields='id, name, mimeType, parents',
        supportsAllDrives=True,
    ).execute()
    return copied


def create_folder(drive, name, parent_id=None):
    metadata = {
        'name': name,
        'mimeType': 'application/vnd.google-apps.folder',
    }
    if parent_id:
        metadata['parents'] = [parent_id]
    else:
        metadata['parents'] = ['root']
    folder = drive.files().create(
        body=metadata,
        fields='id, name, mimeType, parents',
        supportsAllDrives=True,
    ).execute()
    return folder


def list_children(drive, folder_id):
    page_token = None
    items = []
    query = f"'{folder_id}' in parents and trashed=false"
    while True:
        resp = drive.files().list(
            q=query,
            spaces='drive',
            fields='nextPageToken, files(id, name, mimeType)',
            includeItemsFromAllDrives=True,
            supportsAllDrives=True,
            pageToken=page_token,
        ).execute()
        items.extend(resp.get('files', []))
        page_token = resp.get('nextPageToken')
        if not page_token:
            break
    return items


def copy_folder_recursive(drive, source_meta, target_folder_id=None, new_name=None):
    # Create destination folder
    dest_folder = create_folder(drive, new_name or source_meta['name'], parent_id=target_folder_id)
    # Copy children
    for child in list_children(drive, source_meta['id']):
        if child['mimeType'] == 'application/vnd.google-apps.folder':
            copy_folder_recursive(drive, child, target_folder_id=dest_folder['id'], new_name=None)
        else:
            src_child_meta = get_item_metadata(drive, child['id'])
            copy_single_file(drive, src_child_meta, target_folder_id=dest_folder['id'])
    return dest_folder

@app.route('/copy', methods=['GET', 'POST'])
def copy_drive():
    """Google Drive Copy Manager"""
    if request.method == 'GET':
        return render_template('copy.html')
    # Require login for POST actions
    if 'credentials' not in session:
        return jsonify({'success': False, 'error': 'Chưa đăng nhập Google hoặc hết hạn token'}), 401
    
    # Xử lý POST request cho copy files
    try:
        data = request.get_json()
        raw_source = data.get('source_id')
        raw_target = data.get('target_folder_id')
        source_id = extract_drive_id(raw_source) if raw_source else None
        target_folder_id = extract_drive_id(raw_target) if raw_target else 'root'
        new_name = data.get('new_name')
        
        if not source_id:
            return jsonify({
                'success': False,
                'error': 'Thiếu source_id'
            }), 400
        
        drive = get_drive_service()
        if not drive:
            return jsonify({'success': False, 'error': 'Chưa đăng nhập Google hoặc hết hạn token'}), 401
        
        src_meta = get_item_metadata(drive, source_id)
        if not src_meta:
            return jsonify({'success': False, 'error': 'Không tìm thấy file/folder nguồn'}), 404

        # Validate and resolve target folder if provided
        if target_folder_id and target_folder_id != 'root':
            try:
                tmeta = drive.files().get(
                    fileId=target_folder_id,
                    fields='id, name, mimeType, shortcutDetails, capabilities',
                    supportsAllDrives=True,
                ).execute()
                # Resolve shortcut to actual target
                if tmeta.get('mimeType') == 'application/vnd.google-apps.shortcut':
                    sd = tmeta.get('shortcutDetails', {}) or {}
                    resolved_id = sd.get('targetId')
                    if resolved_id:
                        tmeta = drive.files().get(
                            fileId=resolved_id,
                            fields='id, name, mimeType, capabilities',
                            supportsAllDrives=True,
                        ).execute()
                        target_folder_id = resolved_id
                # Ensure it's a folder
                if tmeta.get('mimeType') != 'application/vnd.google-apps.folder':
                    return jsonify({'success': False, 'error': 'Thư mục đích không hợp lệ: không phải là thư mục'}), 400
                # Check write permission
                caps = tmeta.get('capabilities', {}) or {}
                if caps.get('canAddChildren') is False:
                    return jsonify({'success': False, 'error': 'Bạn không có quyền ghi vào thư mục đích'}), 403
            except HttpError as e:
                logger.error(f'Error validating target folder {target_folder_id}: {e}')
                return jsonify({'success': False, 'error': 'Thư mục đích không hợp lệ hoặc không truy cập được'}), 400
        
        if src_meta['mimeType'] == 'application/vnd.google-apps.folder':
            dest = copy_folder_recursive(drive, src_meta, target_folder_id=target_folder_id, new_name=new_name)
        else:
            dest = copy_single_file(drive, src_meta, target_folder_id=target_folder_id, new_name=new_name)
        
        # Make shareable and build link
        try:
            ensure_anyone_reader_permission(drive, dest['id'])
        except Exception:
            pass
        result_url = build_file_link(dest['id'], dest['mimeType'])
        
        # Optionally lookup target folder name
        target_name = None
        try:
            if target_folder_id and target_folder_id != 'root':
                tmeta = get_item_metadata(drive, target_folder_id)
                target_name = tmeta.get('name')
            else:
                target_name = 'Root'
        except Exception:
            target_name = None
        
        return jsonify({
            'success': True,
            'message': 'Copy thành công',
            'data': {
                'source_id': source_id,
                'source_name': src_meta.get('name'),
                'target_folder_id': None if target_folder_id == 'root' else target_folder_id,
                'target_folder_name': target_name,
                'new_name': new_name or dest.get('name'),
                'result_url': result_url,
                'message': 'Sao chép thành công'
            }
        })
        
    except HttpError as e:
        logger.error(f"Google API error in copy_drive: {e}")
        return jsonify({'success': False, 'error': f'Lỗi Google API: {e}'}), 500
    except Exception as e:
        logger.error(f"Error in copy_drive: {e}")
        return jsonify({
            'success': False,
            'error': f'Lỗi copy: {str(e)}'
        }), 500



# ==================== GOOGLE TRENDS FUNCTIONS ====================

def process_google_trends_simple(keywords, timeframe='today 12-m'):
    """Process Google Trends data simply and save to Trends_Data sheet"""
    try:
        from pytrends.request import TrendReq
        import pandas as pd
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import base64
        from io import BytesIO
        from datetime import datetime
        import gspread
        # Đọc NID cookie từ file để tránh bị spam
        nid_cookie = None
        nid_file_path = os.path.join(os.path.dirname(__file__), 'NID_KEY.txt')
        if os.path.exists(nid_file_path):
            try:
                with open(nid_file_path, 'r', encoding='utf-8') as f:
                    nid_cookie = f.read().strip()
                logger.info("Loaded NID cookie from NID_KEY.txt")
            except Exception as e:
                logger.warning(f"Could not read NID_KEY.txt: {e}")
        
        # Initialize pytrends với cải thiện chống spam
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Khởi tạo pytrends với các tham số cải thiện
        pytrends = TrendReq(
            hl='vi-VN', 
            tz=420,
            timeout=(10, 25),
            retries=2,
            backoff_factor=0.1,
            requests_args={'headers': headers}
        )
        
        # Thêm NID cookie nếu có (sau khi khởi tạo)
        if nid_cookie:
            try:
                import requests
                pytrends.session.cookies.set('NID', nid_cookie, domain='.google.com')
                logger.info("Applied NID cookie to session")
            except Exception as e:
                logger.warning(f"Could not apply NID cookie: {e}")
        
        # Handle keywords input
        if isinstance(keywords, str):
            keywords_list = [k.strip() for k in keywords.split(',') if k.strip()]
        elif isinstance(keywords, list):
            keywords_list = keywords
        else:
            return {
                'success': False,
                'error': 'Định dạng từ khóa không hợp lệ'
            }
        
        if not keywords_list or len(keywords_list) == 0:
            return {
                'success': False,
                'error': 'Không có từ khóa hợp lệ'
            }
        
        # Xử lý từng batch 5 từ khóa (giới hạn của Google Trends API)
        all_data = {}
        chart_data = {}
        
        for i in range(0, len(keywords_list), 5):
            batch_keywords = keywords_list[i:i+5]
            
            try:
                # Thêm delay để tránh spam
                if i > 0:
                    time.sleep(2)  # Delay 2 giây giữa các batch
                
                # Build payload với timeframe được chọn
                pytrends.build_payload(
                    batch_keywords, 
                    cat=0, 
                    timeframe=timeframe, 
                    geo='VN', 
                    gprop=''
                )
                
                # Get interest over time data
                interest_over_time_df = pytrends.interest_over_time()
                
                if not interest_over_time_df.empty:
                    # Remove 'isPartial' column if exists
                    if 'isPartial' in interest_over_time_df.columns:
                        interest_over_time_df = interest_over_time_df.drop('isPartial', axis=1)
                    
                    # Store data for each keyword
                    for keyword in batch_keywords:
                        if keyword in interest_over_time_df.columns:
                            all_data[keyword] = interest_over_time_df[keyword].to_dict()
                            chart_data[keyword] = {
                                'dates': interest_over_time_df.index.strftime('%Y-%m-%d').tolist(),
                                'values': interest_over_time_df[keyword].tolist()
                            }
                
            except Exception as e:
                logger.error(f"Error processing batch {batch_keywords}: {e}")
                continue
        
        return {
            'success': True,
            'data': all_data,
            'chart_data': chart_data,
            'keywords': keywords_list
        }
        
    except Exception as e:
        logger.error(f"Error in process_google_trends_simple: {e}")
        return {
            'success': False,
            'error': str(e)
        }


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
                
                if not interest_over_time_df.empty:
                    # Remove 'isPartial' column if it exists
                    if 'isPartial' in interest_over_time_df.columns:
                        interest_over_time_df = interest_over_time_df.drop('isPartial', axis=1)
                    
                    # Lưu dữ liệu cho từng từ khóa
                    for keyword in batch_keywords:
                        if keyword in interest_over_time_df.columns:
                            all_data[keyword] = interest_over_time_df[keyword].to_dict()
                            chart_data[keyword] = {
                                'dates': [date.strftime('%Y-%m-%d') for date in interest_over_time_df.index],
                                'values': interest_over_time_df[keyword].tolist()
                            }
                        else:
                            # Từ khóa không có dữ liệu
                            all_data[keyword] = {}
                            chart_data[keyword] = {'dates': [], 'values': [], 'no_data': True}
                            
            except Exception as e:
                logger.warning(f"Error processing batch {batch_keywords}: {e}")
                # Đánh dấu các từ khóa trong batch này là không có dữ liệu
                for keyword in batch_keywords:
                    all_data[keyword] = {}
                    chart_data[keyword] = {'dates': [], 'values': [], 'no_data': True}
        
        # Lưu dữ liệu vào Google Sheets 'Trends_Data'
        sheet_result = save_to_trends_data_sheet(all_data, keywords_list)
        
        # Tạo biểu đồ theo mẫu đã gửi
        chart_base64 = create_trends_chart(chart_data, keywords_list)
        
        # Tính toán thống kê tổng hợp
        summary_stats = {}
        if keywords_list and all_data:
            for keyword in keywords_list:
                if keyword in all_data and all_data[keyword] and isinstance(all_data[keyword], dict):
                    values = [v for v in all_data[keyword].values() if isinstance(v, (int, float))]
                    if values:
                        summary_stats[keyword] = {
                            'avg': round(sum(values) / len(values), 2),
                            'max': max(values),
                            'min': min(values),
                            'total_points': len(values)
                        }
                    else:
                        summary_stats[keyword] = {
                            'avg': 0,
                            'max': 0,
                            'min': 0,
                            'total_points': 0,
                            'no_data': True
                        }
                else:
                    summary_stats[keyword] = {
                        'avg': 0,
                        'max': 0,
                        'min': 0,
                        'total_points': 0,
                        'no_data': True
                    }
        
        return {
            'success': True,
            'keywords': keywords_list,
            'data': all_data,
            'chart_data': chart_data,
            'chart_base64': chart_base64,
            'chart_url': f'data:image/png;base64,{chart_base64}' if chart_base64 else None,
            'sheet_result': sheet_result,
            'summary': summary_stats,
            'keywords_processed': len(keywords_list),
            'message': f'Đã xử lý thành công {len(keywords_list)} từ khóa',
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        import traceback
        logger.error(f"Error processing Google Trends data: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return {
            'success': False,
            'error': f'Lỗi xử lý dữ liệu Google Trends: {str(e)}'
        }
def create_trends_chart(chart_data, keywords_list):
    """Create a multi-panel trends chart from chart_data and return base64 PNG string."""
    try:
        if not keywords_list:
            return None

        total_keywords = len(keywords_list)
        # Vẽ dạng dọc để đơn giản hóa bố cục và tránh lỗi định dạng axes
        rows = total_keywords
        cols = 1
        fig, axes = plt.subplots(rows, cols, figsize=(8, max(3, rows * 2.8)), sharex=False)

        # Chuẩn hóa axes thành list
        if total_keywords == 1:
            axes_list = [axes]
        else:
            axes_list = list(axes)

        for i, keyword in enumerate(keywords_list):
            ax = axes_list[i]
            kdata = chart_data.get(keyword, {}) or {}

            # Trường hợp không có dữ liệu
            if not kdata or kdata.get('no_data'):
                ax.text(0.5, 0.5, 'Xu hướng dữ liệu\n\nKhông có dữ liệu',
                        ha='center', va='center', transform=ax.transAxes,
                        fontsize=10, color='red')
                ax.set_title(f'"{keyword}"', fontsize=10, fontweight='bold', pad=10, color='red')
                ax.set_facecolor('#ffebee')
                ax.set_xlabel('')
                ax.set_ylabel('')
                ax.tick_params(axis='both', which='major', labelsize=8)
                continue

            dates = kdata.get('dates') or []
            values = kdata.get('values') or []
            if dates and values and len(dates) == len(values):
                # Vẽ đường xu hướng
                ax.plot(dates, values, color='#1976d2', linewidth=1.5)
                # Tô nền dưới đường
                ax.fill_between(range(len(values)), values, color='#1976d2', alpha=0.15)
                # Giảm số lượng nhãn trục X để dễ đọc
                step = max(1, len(dates) // 6)
                ax.set_xticks(dates[::step])
                ax.set_xticklabels(dates[::step], rotation=45, ha='right', fontsize=8)
                # Tên biểu đồ
                ax.set_title(f'"{keyword}"', fontsize=10, fontweight='bold', pad=10)
            else:
                ax.text(0.5, 0.5, 'Xu hướng dữ liệu\n\nKhông có dữ liệu',
                        ha='center', va='center', transform=ax.transAxes,
                        fontsize=10, color='red')
                ax.set_title(f'"{keyword}"', fontsize=10, fontweight='bold', pad=10, color='red')
                ax.set_facecolor('#ffebee')

            # Ẩn nhãn trục dọc để gọn gàng
            ax.set_xlabel('')
            ax.set_ylabel('')
            ax.tick_params(axis='both', which='major', labelsize=8)

        plt.tight_layout()
        # Xuất ra base64 PNG
        buf = BytesIO()
        plt.savefig(buf, format='png', dpi=150, bbox_inches='tight', facecolor='white', edgecolor='none')
        buf.seek(0)
        img_b64 = base64.b64encode(buf.getvalue()).decode()
        plt.close(fig)
        return img_b64

    except Exception as e:
        logger.error(f"Error creating trends chart: {e}")
        return None


@app.route('/copy/template', methods=['GET'])
def download_copy_template():
    """Return a sample CSV template for batch copy.
    Columns: source_id, target_folder_id (optional), new_name (optional)
    """
    csv_content = (
        'source_id,target_folder_id,new_name\n'
        '1A2B3C4D5E6F,root,Sample Copied File\n'
        'https://drive.google.com/file/d/7G8H9I0J1K2L/view?usp=sharing,,\n'
    )
    return Response(
        csv_content,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=copy_template.csv'}
    )

@app.route('/trends', methods=['GET', 'POST'])
def trends():
    """Google Trends Analyzer"""
    if request.method == 'GET':
        return render_template('trends.html')
    
    try:
        data = request.get_json()
        keywords = data.get('keywords', '')
        timeframe = data.get('timeframe', 'today 12-m')
        
        if not keywords:
            return jsonify({
                'success': False,
                'error': 'Vui lòng nhập từ khóa'
            }), 400
        
        # Xử lý Google Trends
        result = process_google_trends_simple(keywords, timeframe)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in trends endpoint: {e}")
        return jsonify({
            'success': False,
            'error': f'Lỗi xử lý Google Trends: {str(e)}'
        }), 500

@app.route('/qr', methods=['GET', 'POST'])
def qr_generator():
    """QR Code Generator"""
    if request.method == 'GET':
        return render_template('qr.html')
    
    try:
        data = request.get_json(silent=True) or {}
        text_data = str(data.get('text', '')).strip()
        qr_size = int(data.get('qr_size', 200))
        
        if not text_data:
            return jsonify({
                'success': False,
                'error': 'Vui lòng nhập nội dung để tạo mã QR'
            }), 400
        
        # Generate QR code URL using quickchart.io
        encoded_text = urllib.parse.quote(text_data)
        qr_url = f"https://quickchart.io/qr?text={encoded_text}&size={qr_size}"
        
        return jsonify({
            'success': True,
            'qr_url': qr_url,
            'text': text_data,
            'size': qr_size
        })
        
    except Exception as e:
        logger.error(f"Error in QR generator: {e}")
        return jsonify({
            'success': False,
            'error': f'Lỗi server: {str(e)}'
        }), 500

@app.route('/qr/excel', methods=['POST'])
def qr_excel_upload():
    """Xử lý upload file Excel để tạo QR codes hàng loạt"""
    try:
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'Không có file được upload'
            }), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'Không có file được chọn'
            }), 400
        
        if not allowed_file(file.filename):
            return jsonify({
                'success': False,
                'error': 'Định dạng file không được hỗ trợ. Chỉ chấp nhận .xlsx, .xls, .csv'
            }), 400
        
        # Save uploaded file temporarily
        filename = secure_filename(file.filename)
        temp_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(temp_path)
        
        try:
            # Read Excel file
            excel_data = read_excel_file(temp_path)
            
            if not excel_data.get('success'):
                return jsonify({
                    'success': False,
                    'error': excel_data.get('error', 'Lỗi đọc file Excel')
                }), 400
            
            # Extract data from first column
            df = excel_data['data']
            if df.empty:
                return jsonify({
                    'success': False,
                    'error': 'File Excel không có dữ liệu'
                }), 400
            
            # Get first column data
            first_column = df.iloc[:, 0].dropna().astype(str).tolist()
            
            if not first_column:
                return jsonify({
                    'success': False,
                    'error': 'Cột đầu tiên không có dữ liệu'
                }), 400
            
            # Limit to 100 items to prevent overload
            if len(first_column) > 100:
                first_column = first_column[:100]
            
            # Generate QR codes for each item
            qr_results = []
            qr_size = request.form.get('qr_size', 200)
            
            for text in first_column:
                if text.strip():  # Skip empty cells
                    encoded_text = urllib.parse.quote(str(text).strip())
                    qr_url = f"https://quickchart.io/qr?text={encoded_text}&size={qr_size}"
                    
                    qr_results.append({
                        'success': True,
                        'qr_url': qr_url,
                        'text': str(text).strip(),
                        'size': int(qr_size)
                    })
            
            return jsonify({
                'success': True,
                'qr_codes': qr_results,
                'total': len(qr_results),
                'message': f'Đã tạo {len(qr_results)} mã QR từ file Excel'
            })
            
        finally:
            # Clean up temporary file
            if os.path.exists(temp_path):
                os.remove(temp_path)
                
    except Exception as e:
        logger.error(f"Error processing Excel file for QR codes: {e}")
        return jsonify({
            'success': False,
            'error': f'Lỗi xử lý file Excel: {str(e)}'
        }), 500

# ==================== GOOGLE TRENDS FUNCTIONS ====================

def process_google_trends_simple(keywords, timeframe='today 12-m'):
    """Process Google Trends data simply and save to Trends_Data sheet"""
    try:
        from pytrends.request import TrendReq
        import pandas as pd
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import base64
        from io import BytesIO
        from datetime import datetime
        import gspread
        # Đọc NID cookie từ file để tránh bị spam
        nid_cookie = None
        nid_file_path = os.path.join(os.path.dirname(__file__), 'NID_KEY.txt')
        if os.path.exists(nid_file_path):
            try:
                with open(nid_file_path, 'r', encoding='utf-8') as f:
                    nid_cookie = f.read().strip()
                logger.info("Loaded NID cookie from NID_KEY.txt")
            except Exception as e:
                logger.warning(f"Could not read NID_KEY.txt: {e}")
        
        # Initialize pytrends với cải thiện chống spam
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Khởi tạo pytrends với các tham số cải thiện
        pytrends = TrendReq(
            hl='vi-VN', 
            tz=420,
            timeout=(10, 25),
            retries=2,
            backoff_factor=0.1,
            requests_args={'headers': headers}
        )
        
        # Thêm NID cookie nếu có (sau khi khởi tạo)
        if nid_cookie:
            try:
                import requests
                pytrends.session.cookies.set('NID', nid_cookie, domain='.google.com')
                logger.info("Applied NID cookie to session")
            except Exception as e:
                logger.warning(f"Could not apply NID cookie: {e}")
        
        # Handle keywords input
        if isinstance(keywords, str):
            keywords_list = [k.strip() for k in keywords.split(',') if k.strip()]
        elif isinstance(keywords, list):
            keywords_list = keywords
        else:
            return {
                'success': False,
                'error': 'Định dạng từ khóa không hợp lệ'
            }
        
        if not keywords_list or len(keywords_list) == 0:
            return {
                'success': False,
                'error': 'Không có từ khóa hợp lệ'
            }
        
        # Xử lý từng batch 5 từ khóa (giới hạn của Google Trends API)
        all_data = {}
        chart_data = {}
        
        for i in range(0, len(keywords_list), 5):
            batch_keywords = keywords_list[i:i+5]
            
            try:
                # Thêm delay để tránh spam
                if i > 0:
                    time.sleep(2)  # Delay 2 giây giữa các batch
                
                # Build payload với timeframe được chọn
                pytrends.build_payload(
                    batch_keywords, 
                    cat=0, 
                    timeframe=timeframe, 
                    geo='VN', 
                    gprop=''
                )
                
                # Get interest over time data
                interest_over_time_df = pytrends.interest_over_time()
                
                if not interest_over_time_df.empty:
                    # Remove 'isPartial' column if it exists
                    if 'isPartial' in interest_over_time_df.columns:
                        interest_over_time_df = interest_over_time_df.drop('isPartial', axis=1)
                    
                    # Lưu dữ liệu cho từng từ khóa
                    for keyword in batch_keywords:
                        if keyword in interest_over_time_df.columns:
                            all_data[keyword] = interest_over_time_df[keyword].to_dict()
                            chart_data[keyword] = {
                                'dates': [date.strftime('%Y-%m-%d') for date in interest_over_time_df.index],
                                'values': interest_over_time_df[keyword].tolist()
                            }
                        else:
                            # Từ khóa không có dữ liệu
                            all_data[keyword] = {}
                            chart_data[keyword] = {'dates': [], 'values': [], 'no_data': True}
                            
            except Exception as e:
                logger.warning(f"Error processing batch {batch_keywords}: {e}")
                # Đánh dấu các từ khóa trong batch này là không có dữ liệu
                for keyword in batch_keywords:
                    all_data[keyword] = {}
                    chart_data[keyword] = {'dates': [], 'values': [], 'no_data': True}
        
        # Lưu dữ liệu vào Google Sheets 'Trends_Data'
        sheet_result = save_to_trends_data_sheet(all_data, keywords_list)
        
        # Tạo biểu đồ theo mẫu đã gửi
        chart_base64 = create_trends_chart(chart_data, keywords_list)
        
        # Tính toán thống kê tổng hợp
        summary_stats = {}
        if keywords_list and all_data:
            for keyword in keywords_list:
                if keyword in all_data and all_data[keyword] and isinstance(all_data[keyword], dict):
                    values = [v for v in all_data[keyword].values() if isinstance(v, (int, float))]
                    if values:
                        summary_stats[keyword] = {
                            'avg': round(sum(values) / len(values), 2),
                            'max': max(values),
                            'min': min(values),
                            'total_points': len(values)
                        }
                    else:
                        summary_stats[keyword] = {
                            'avg': 0,
                            'max': 0,
                            'min': 0,
                            'total_points': 0,
                            'no_data': True
                        }
                else:
                    summary_stats[keyword] = {
                        'avg': 0,
                        'max': 0,
                        'min': 0,
                        'total_points': 0,
                        'no_data': True
                    }
        
        return {
            'success': True,
            'keywords': keywords_list,
            'data': all_data,
            'chart_data': chart_data,
            'chart_base64': chart_base64,
            'chart_url': f'data:image/png;base64,{chart_base64}' if chart_base64 else None,
            'sheet_result': sheet_result,
            'summary': summary_stats,
            'keywords_processed': len(keywords_list),
            'message': f'Đã xử lý thành công {len(keywords_list)} từ khóa',
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        import traceback
        logger.error(f"Error processing Google Trends data: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return {
            'success': False,
            'error': f'Lỗi xử lý dữ liệu Google Trends: {str(e)}'
        }
def create_trends_chart(chart_data, keywords_list):
    """Create a multi-panel trends chart from chart_data and return base64 PNG string."""
    try:
        if not keywords_list:
            return None

        total_keywords = len(keywords_list)
        # Vẽ dạng dọc để đơn giản hóa bố cục và tránh lỗi định dạng axes
        rows = total_keywords
        cols = 1
        fig, axes = plt.subplots(rows, cols, figsize=(8, max(3, rows * 2.8)), sharex=False)

        # Chuẩn hóa axes thành list
        if total_keywords == 1:
            axes_list = [axes]
        else:
            axes_list = list(axes)

        for i, keyword in enumerate(keywords_list):
            ax = axes_list[i]
            kdata = chart_data.get(keyword, {}) or {}

            # Trường hợp không có dữ liệu
            if not kdata or kdata.get('no_data'):
                ax.text(0.5, 0.5, 'Xu hướng dữ liệu\n\nKhông có dữ liệu',
                        ha='center', va='center', transform=ax.transAxes,
                        fontsize=10, color='red')
                ax.set_title(f'"{keyword}"', fontsize=10, fontweight='bold', pad=10, color='red')
                ax.set_facecolor('#ffebee')
                ax.set_xlabel('')
                ax.set_ylabel('')
                ax.tick_params(axis='both', which='major', labelsize=8)
                continue

            dates = kdata.get('dates') or []
            values = kdata.get('values') or []
            if dates and values and len(dates) == len(values):
                # Vẽ đường xu hướng
                ax.plot(dates, values, color='#1976d2', linewidth=1.5)
                # Tô nền dưới đường
                ax.fill_between(range(len(values)), values, color='#1976d2', alpha=0.15)
                # Giảm số lượng nhãn trục X để dễ đọc
                step = max(1, len(dates) // 6)
                ax.set_xticks(dates[::step])
                ax.set_xticklabels(dates[::step], rotation=45, ha='right', fontsize=8)
                # Tên biểu đồ
                ax.set_title(f'"{keyword}"', fontsize=10, fontweight='bold', pad=10)
            else:
                ax.text(0.5, 0.5, 'Xu hướng dữ liệu\n\nKhông có dữ liệu',
                        ha='center', va='center', transform=ax.transAxes,
                        fontsize=10, color='red')
                ax.set_title(f'"{keyword}"', fontsize=10, fontweight='bold', pad=10, color='red')
                ax.set_facecolor('#ffebee')

            # Ẩn nhãn trục dọc để gọn gàng
            ax.set_xlabel('')
            ax.set_ylabel('')
            ax.tick_params(axis='both', which='major', labelsize=8)

        plt.tight_layout()
        # Xuất ra base64 PNG
        buf = BytesIO()
        plt.savefig(buf, format='png', dpi=150, bbox_inches='tight', facecolor='white', edgecolor='none')
        buf.seek(0)
        img_b64 = base64.b64encode(buf.getvalue()).decode()
        plt.close(fig)
        return img_b64

    except Exception as e:
        logger.error(f"Error creating trends chart: {e}")
        return None


@app.route('/copy/batch', methods=['POST'])
def copy_batch():
    """Batch copy files/folders from an uploaded Excel/CSV file.
    Expected columns: source_id, target_folder_id (optional), new_name (optional)
    """
    if 'credentials' not in session:
        return jsonify({'success': False, 'error': 'Chưa đăng nhập Google hoặc phiên đăng nhập đã hết hạn'}), 401

    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'Thiếu file upload'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'Chưa chọn file'}), 400

        filename = secure_filename(file.filename)
        if not allowed_file(filename):
            return jsonify({'success': False, 'error': 'Chỉ chấp nhận file .xlsx, .xls, .csv, .xlsm, .xltx, .xltm'}), 400

        # Save to temp
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(temp_path)

        # Read with helper
        read_result = read_excel_file(temp_path)
        if not read_result.get('success'):
            return jsonify({'success': False, 'error': f"Không đọc được file: {read_result.get('error')}"}), 400

        df = read_result['data']
        # Normalize column names
        df.columns = [str(c).strip().lower() for c in df.columns]
        
        # Fallback ánh xạ cột theo vị trí nếu thiếu header chuẩn
        # A: source_id, B: target_folder_id, C: new_name
        if 'source_id' not in df.columns and df.shape[1] >= 1:
            df['source_id'] = df.iloc[:, 0]
        if 'target_folder_id' not in df.columns and df.shape[1] >= 2:
            df['target_folder_id'] = df.iloc[:, 1]
        if 'new_name' not in df.columns and df.shape[1] >= 3:
            df['new_name'] = df.iloc[:, 2]
        
        # Validate bắt buộc phải có source_id sau khi fallback
        if 'source_id' not in df.columns:
            return jsonify({'success': False, 'error': 'Thiếu cột bắt buộc: source_id (hoặc không tìm thấy dữ liệu ở cột đầu tiên)'}), 400

        drive = get_drive_service()
        if not drive:
            return jsonify({'success': False, 'error': 'Không tạo được Drive service. Vui lòng đăng nhập lại.'}), 401

        results = []
        success_count = 0
        error_count = 0

        for idx, row in df.iterrows():
            try:
                src_val = row.get('source_id')
                if pd.isna(src_val) or str(src_val).strip() == '':
                    raise ValueError('Thiếu source_id')
                source_id = extract_drive_id(str(src_val).strip())

                tgt_val = row.get('target_folder_id') if 'target_folder_id' in df.columns else None
                target_folder_id = None
                if tgt_val is not None and not (isinstance(tgt_val, float) and pd.isna(tgt_val)) and str(tgt_val).strip() != '':
                    target_folder_id = extract_drive_id(str(tgt_val).strip())

                name_val = row.get('new_name') if 'new_name' in df.columns else None
                new_name = None if (name_val is None or (isinstance(name_val, float) and pd.isna(name_val)) or str(name_val).strip() == '') else str(name_val).strip()

                src_meta = get_item_metadata(drive, source_id)
                if src_meta['mimeType'] == 'application/vnd.google-apps.folder':
                    dest = copy_folder_recursive(drive, src_meta, target_folder_id=target_folder_id, new_name=new_name)
                else:
                    dest = copy_single_file(drive, src_meta, target_folder_id=target_folder_id, new_name=new_name)

                try:
                    ensure_anyone_reader_permission(drive, dest['id'])
                except Exception:
                    pass

                result_url = build_file_link(dest['id'], dest['mimeType'])
                target_name = None
                try:
                    if target_folder_id and target_folder_id != 'root':
                        tmeta = get_item_metadata(drive, target_folder_id)
                        target_name = tmeta.get('name')
                    else:
                        target_name = 'Root'
                except Exception:
                    target_name = None

                results.append({
                    'status': 'success',
                    'data': {
                        'source_id': source_id,
                        'source_name': src_meta.get('name'),
                        'target_folder_id': target_folder_id,
                        'target_folder_name': target_name,
                        'new_name': new_name or dest.get('name'),
                        'result_url': result_url,
                        'message': 'Sao chép thành công'
                    }
                })
                success_count += 1

            except HttpError as e:
                error_count += 1
                results.append({
                    'status': 'error',
                    'error': f'Google API error: {e}',
                    'data': {
                        'source_id': str(row.get('source_id')),
                        'target_folder_id': str(row.get('target_folder_id')) if 'target_folder_id' in df.columns else None,
                        'new_name': str(row.get('new_name')) if 'new_name' in df.columns else None
                    }
                })
            except Exception as e:
                error_count += 1
                results.append({
                    'status': 'error',
                    'error': str(e),
                    'data': {
                        'source_id': str(row.get('source_id')),
                        'target_folder_id': str(row.get('target_folder_id')) if 'target_folder_id' in df.columns else None,
                        'new_name': str(row.get('new_name')) if 'new_name' in df.columns else None
                    }
                })

        return jsonify({
            'success': True,
            'summary': {
                'total': int(len(df)),
                'success': int(success_count),
                'error': int(error_count)
            },
            'results': results
        })

    except Exception as e:
        logger.error(f"Error in copy_batch: {e}")
        return jsonify({'success': False, 'error': f'Lỗi xử lý batch: {str(e)}'}), 500



# ==================== GOOGLE TRENDS FUNCTIONS ====================

def process_google_trends_simple(keywords, timeframe='today 12-m'):
    """Process Google Trends data simply and save to Trends_Data sheet"""
    try:
        from pytrends.request import TrendReq
        import pandas as pd
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import base64
        from io import BytesIO
        from datetime import datetime
        import gspread
        # Đọc NID cookie từ file để tránh bị spam
        nid_cookie = None
        nid_file_path = os.path.join(os.path.dirname(__file__), 'NID_KEY.txt')
        if os.path.exists(nid_file_path):
            try:
                with open(nid_file_path, 'r', encoding='utf-8') as f:
                    nid_cookie = f.read().strip()
                logger.info("Loaded NID cookie from NID_KEY.txt")
            except Exception as e:
                logger.warning(f"Could not read NID_KEY.txt: {e}")
        
        # Initialize pytrends với cải thiện chống spam
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Khởi tạo pytrends với các tham số cải thiện
        pytrends = TrendReq(
            hl='vi-VN', 
            tz=420,
            timeout=(10, 25),
            retries=2,
            backoff_factor=0.1,
            requests_args={'headers': headers}
        )
        
        # Thêm NID cookie nếu có (sau khi khởi tạo)
        if nid_cookie:
            try:
                import requests
                pytrends.session.cookies.set('NID', nid_cookie, domain='.google.com')
                logger.info("Applied NID cookie to session")
            except Exception as e:
                logger.warning(f"Could not apply NID cookie: {e}")
        
        # Handle keywords input
        if isinstance(keywords, str):
            keywords_list = [k.strip() for k in keywords.split(',') if k.strip()]
        elif isinstance(keywords, list):
            keywords_list = keywords
        else:
            return {
                'success': False,
                'error': 'Định dạng từ khóa không hợp lệ'
            }
        
        if not keywords_list or len(keywords_list) == 0:
            return {
                'success': False,
                'error': 'Không có từ khóa hợp lệ'
            }
        
        # Xử lý từng batch 5 từ khóa (giới hạn của Google Trends API)
        all_data = {}
        chart_data = {}
        
        for i in range(0, len(keywords_list), 5):
            batch_keywords = keywords_list[i:i+5]
            
            try:
                # Thêm delay để tránh spam
                if i > 0:
                    time.sleep(2)  # Delay 2 giây giữa các batch
                
                # Build payload với timeframe được chọn
                pytrends.build_payload(
                    batch_keywords, 
                    cat=0, 
                    timeframe=timeframe, 
                    geo='VN', 
                    gprop=''
                )
                
                # Get interest over time data
                interest_over_time_df = pytrends.interest_over_time()