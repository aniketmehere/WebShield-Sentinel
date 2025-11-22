# import json
# import hashlib
# import secrets
# from datetime import datetime
# import os

# class AuthManager:
#     def __init__(self, users_file='users.json'):
#         self.users_file = users_file
#         self.users = self.load_users()
    
#     def load_users(self):
#         if os.path.exists(self.users_file):
#             with open(self.users_file, 'r') as f:
#                 return json.load(f)
#         return {
#             'users': [],
#             'scans': []
#         }
    
#     def save_users(self):
#         with open(self.users_file, 'w') as f:
#             json.dump(self.users, f, indent=2)
    
#     def hash_password(self, password):
#         return hashlib.sha256(password.encode()).hexdigest()
    
#     def generate_api_key(self):
#         return secrets.token_hex(32)
    
#     def register_user(self, username, password, email, role='user'):
#         # Check if user exists
#         for user in self.users['users']:
#             if user['username'] == username:
#                 return False
        
#         # Create new user
#         new_user = {
#             'id': len(self.users['users']) + 1,
#             'username': username,
#             'password': self.hash_password(password),
#             'email': email,
#             'role': role,
#             'api_key': self.generate_api_key(),
#             'created_at': datetime.now().isoformat(),
#             'last_login': None
#         }
        
#         self.users['users'].append(new_user)
#         self.save_users()
#         return True
    
#     def authenticate_user(self, username, password):
#         hashed_password = self.hash_password(password)
#         for user in self.users['users']:
#             if user['username'] == username and user['password'] == hashed_password:
#                 user['last_login'] = datetime.now().isoformat()
#                 self.save_users()
#                 return user
#         return None
    
#     def validate_api_key(self, api_key):
#         for user in self.users['users']:
#             if user.get('api_key') == api_key:
#                 return user
#         return None
    
#     def save_scan(self, user_id, scan_data):
#         scan_data['id'] = len(self.users['scans']) + 1
#         scan_data['user_id'] = user_id
#         self.users['scans'].append(scan_data)
#         self.save_users()
    
#     def get_user_scans(self, user_id):
#         return [scan for scan in self.users['scans'] if scan['user_id'] == user_id][::-1]
    
#     def get_all_users(self):
#         return self.users['users']
    
#     def get_all_scans(self):
#         return self.users['scans']

import json
import hashlib
import secrets
from datetime import datetime
import os

class AuthManager:
    def __init__(self, users_file='users.json'):
        self.users_file = users_file
        self.users = self.load_users()
    
    def load_users(self):
        """Safely load users from JSON file, create default structure if file doesn't exist or is invalid"""
        default_structure = {
            'users': [],
            'scans': []
        }
        
        try:
            # Check if file exists and has content
            if os.path.exists(self.users_file) and os.path.getsize(self.users_file) > 0:
                with open(self.users_file, 'r') as f:
                    data = json.load(f)
                    # Validate structure
                    if 'users' in data and 'scans' in data:
                        return data
                    else:
                        print("⚠️  Invalid users.json structure, creating new one...")
                        return default_structure
            else:
                # File doesn't exist or is empty
                print("📁 Creating new users.json file...")
                self.save_users(default_structure)
                return default_structure
                
        except (json.JSONDecodeError, Exception) as e:
            print(f"⚠️  Error loading users.json: {e}. Creating new file...")
            # Create backup of corrupted file
            if os.path.exists(self.users_file):
                backup_name = f"{self.users_file}.backup"
                os.rename(self.users_file, backup_name)
                print(f"📦 Backup created: {backup_name}")
            
            # Create new file with default structure
            self.save_users(default_structure)
            return default_structure
    
    def save_users(self, data=None):
        """Save users to JSON file"""
        if data is None:
            data = self.users
            
        try:
            with open(self.users_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"❌ Error saving users: {e}")
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def generate_api_key(self):
        return secrets.token_hex(32)
    
    def register_user(self, username, password, email, role='user'):
        # Check if user exists
        for user in self.users['users']:
            if user['username'] == username:
                return False
        
        # First user becomes admin
        if len(self.users['users']) == 0:
            role = 'admin'
        
        # Create new user
        new_user = {
            'id': len(self.users['users']) + 1,
            'username': username,
            'password': self.hash_password(password),
            'email': email,
            'role': role,
            'api_key': self.generate_api_key(),
            'created_at': datetime.now().isoformat(),
            'last_login': None
        }
        
        self.users['users'].append(new_user)
        self.save_users()
        print(f"✅ User '{username}' registered successfully as {role}")
        return True
    
    def authenticate_user(self, username, password):
        hashed_password = self.hash_password(password)
        for user in self.users['users']:
            if user['username'] == username and user['password'] == hashed_password:
                user['last_login'] = datetime.now().isoformat()
                self.save_users()
                return user
        return None
    
    def validate_api_key(self, api_key):
        for user in self.users['users']:
            if user.get('api_key') == api_key:
                return user
        return None
    
    def save_scan(self, user_id, scan_data):
        scan_data['id'] = len(self.users['scans']) + 1
        scan_data['user_id'] = user_id
        self.users['scans'].append(scan_data)
        self.save_users()
    
    def get_user_scans(self, user_id):
        return [scan for scan in self.users['scans'] if scan['user_id'] == user_id][::-1]
    
    def get_all_users(self):
        return self.users['users']
    
    def get_all_scans(self):
        return self.users['scans']