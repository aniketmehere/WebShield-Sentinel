from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
import json
import os
from datetime import datetime
import time
import threading
from scanner import VulnerabilityScanner
from auth import AuthManager
# import pdfkit
from io import BytesIO

app = Flask(__name__)
app.secret_key = 'your-super-secret-key-here-2024'
app.config['SESSION_TYPE'] = 'filesystem'

# Ensure directories exist
for directory in ['reports', 'payloads', 'static']:
    if not os.path.exists(directory):
        os.makedirs(directory)

# Initialize managers
auth_manager = AuthManager()
scanner = VulnerabilityScanner()

# Global scan status for real-time updates
scan_status = {
    'active': False,
    'progress': 0,
    'current_task': '',
    'vulnerabilities_found': 0,
    'current_url': '',
    'log_messages': []
}

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', username=session.get('username'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = auth_manager.authenticate_user(username, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        if auth_manager.register_user(username, password, email):
            return redirect(url_for('login'))
        else:
            return render_template('register.html', error='Username already exists')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get scan history
    scan_history = auth_manager.get_user_scans(session['user_id'])
    return render_template('dashboard.html', 
                         username=session.get('username'),
                         role=session.get('role'),
                         scan_history=scan_history[:5])

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        target_url = request.form.get('target_url')
        scan_type = request.form.get('scan_type', 'full')
        scan_depth = request.form.get('scan_depth', 'medium')
        
        session['scan_config'] = {
            'target_url': target_url,
            'scan_type': scan_type,
            'scan_depth': scan_depth
        }
        
        return render_template('scanning.html', 
                             target_url=target_url,
                             scan_type=scan_type)
    
    return render_template('scan.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Reset scan status
    global scan_status
    scan_status = {
        'active': True,
        'progress': 0,
        'current_task': 'Initializing scanner...',
        'vulnerabilities_found': 0,
        'current_url': '',
        'log_messages': ['🚀 Scan started at ' + datetime.now().strftime("%H:%M:%S")]
    }
    
    config = session.get('scan_config', {})
    
    # Start scan in background thread
    def run_scan():
        try:
            results = scanner.scan(
                config['target_url'], 
                config['scan_type'],
                progress_callback=update_scan_progress
            )
            
            # Save scan results
            scan_data = {
                'user_id': session['user_id'],
                'target_url': config['target_url'],
                'scan_type': config['scan_type'],
                'timestamp': datetime.now().isoformat(),
                'vulnerabilities_found': len(results),
                'results': results
            }
            
            auth_manager.save_scan(session['user_id'], scan_data)
            scan_status['active'] = False
            scan_status['progress'] = 100
            scan_status['current_task'] = 'Scan completed!'
            scan_status['log_messages'].append('✅ Scan completed successfully!')
            
        except Exception as e:
            scan_status['active'] = False
            scan_status['current_task'] = f'Scan failed: {str(e)}'
            scan_status['log_messages'].append(f'❌ Scan error: {str(e)}')
    
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'scan_started'})

def update_scan_progress(progress, task, vulnerabilities=0, current_url='', log_message=''):
    global scan_status
    scan_status['progress'] = progress
    scan_status['current_task'] = task
    scan_status['vulnerabilities_found'] = vulnerabilities
    scan_status['current_url'] = current_url
    
    if log_message:
        timestamp = datetime.now().strftime("%H:%M:%S")
        scan_status['log_messages'].append(f"[{timestamp}] {log_message}")

@app.route('/scan_status')
def get_scan_status():
    return jsonify(scan_status)

@app.route('/results')
def results():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get latest scan results
    user_scans = auth_manager.get_user_scans(session['user_id'])
    latest_scan = user_scans[0] if user_scans else None
    
    return render_template('results.html', 
                         scan_data=latest_scan,
                         username=session.get('username'))

@app.route('/api_dashboard')
def api_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('api_dashboard.html', username=session.get('username'))

@app.route('/admin')
def admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    
    users = auth_manager.get_all_users()
    all_scans = auth_manager.get_all_scans()
    
    return render_template('admin.html', 
                         users=users,
                         all_scans=all_scans,
                         username=session.get('username'))

@app.route('/export_pdf')
def export_pdf():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_scans = auth_manager.get_user_scans(session['user_id'])
    latest_scan = user_scans[0] if user_scans else None
    
    if not latest_scan:
        return "No scan data available"
    
    # Generate PDF report
    html = render_template('pdf_report.html', scan_data=latest_scan)
    
    try:
        pdf = pdfkit.from_string(html, False)
        return send_file(
            BytesIO(pdf),
            download_name=f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            as_attachment=True,
            mimetype='application/pdf'
        )
    except:
        # Fallback to HTML report if PDF generation fails
        return render_template('pdf_report.html', scan_data=latest_scan)

@app.route('/api/v1/scan', methods=['POST'])
def api_scan():
    api_key = request.headers.get('X-API-Key')
    if not auth_manager.validate_api_key(api_key):
        return jsonify({'error': 'Invalid API key'}), 401
    
    data = request.json
    target_url = data.get('target_url')
    scan_type = data.get('scan_type', 'full')
    
    try:
        results = scanner.scan(target_url, scan_type)
        return jsonify({
            'status': 'completed',
            'target_url': target_url,
            'vulnerabilities_found': len(results),
            'results': results,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🔥 Enhanced Vulnerability Scanner Starting...")
    print("📊 Features: Animated UI • Real-time Progress • Admin Dashboard • PDF Export • User Management")
    print("🌐 Access: http://127.0.0.1:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)