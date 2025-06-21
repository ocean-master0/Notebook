from flask import Flask, render_template, request, jsonify, send_file, abort
from flask_cors import CORS
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import re
import json
import math
import tempfile
from werkzeug.utils import secure_filename
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import io

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

class PasswordStrengthChecker:
    def __init__(self):
        self.min_length = 8
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        self.common_patterns = [
            'password', '123456', 'qwerty', 'abc123', 'admin', 'welcome',
            'login', 'master', 'hello', 'guest', 'test', 'user'
        ]

    def check_strength(self, password):
        """Comprehensive password strength checking"""
        if not password:
            return {
                'strength': 'Very Weak',
                'score': 0,
                'percentage': 0,
                'suggestions': ['Please enter a password'],
                'criteria': {
                    'length': False,
                    'uppercase': False,
                    'lowercase': False,
                    'numbers': False,
                    'special': False,
                    'no_common': False
                }
            }

        score = 0
        max_score = 10
        suggestions = []
        criteria = {}

        # Length check (0-3 points)
        length_score = 0
        if len(password) >= 12:
            length_score = 3
        elif len(password) >= 8:
            length_score = 2
        elif len(password) >= 6:
            length_score = 1

        score += length_score
        criteria['length'] = len(password) >= self.min_length

        if len(password) < self.min_length:
            suggestions.append(f'Use at least {self.min_length} characters')
        elif len(password) < 12:
            suggestions.append('Consider using 12+ characters for better security')

        # Character variety checks (1 point each)
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))

        criteria['uppercase'] = has_upper
        criteria['lowercase'] = has_lower
        criteria['numbers'] = has_digit
        criteria['special'] = has_special

        if has_upper:
            score += 1
        else:
            suggestions.append('Add uppercase letters (A-Z)')

        if has_lower:
            score += 1
        else:
            suggestions.append('Add lowercase letters (a-z)')

        if has_digit:
            score += 1
        else:
            suggestions.append('Add numbers (0-9)')

        if has_special:
            score += 1
        else:
            suggestions.append('Add special characters (!@#$%^&*)')

        # Pattern and complexity checks (2 points)
        pattern_score = 0

        # Check for common patterns
        password_lower = password.lower()
        has_common_pattern = any(pattern in password_lower for pattern in self.common_patterns)
        criteria['no_common'] = not has_common_pattern

        if not has_common_pattern:
            pattern_score += 1
        else:
            suggestions.append('Avoid common words and patterns')

        # Check for character diversity
        unique_chars = len(set(password))
        if unique_chars >= len(password) * 0.7:  # 70% unique characters
            pattern_score += 1
        else:
            suggestions.append('Use more diverse characters')

        score += pattern_score

        # Calculate percentage and determine strength
        percentage = min(100, (score / max_score) * 100)

        if score >= 9:
            strength = 'Very Strong'
        elif score >= 7:
            strength = 'Strong'
        elif score >= 5:
            strength = 'Medium'
        elif score >= 3:
            strength = 'Weak'
        else:
            strength = 'Very Weak'

        return {
            'strength': strength,
            'score': score,
            'max_score': max_score,
            'percentage': round(percentage),
            'suggestions': suggestions,
            'criteria': criteria
        }

class FileEncryption:
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derive encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    @staticmethod
    def encrypt_text(text: str, password: str) -> dict:
        """Encrypt text with password"""
        try:
            salt = os.urandom(16)
            key = FileEncryption.derive_key(password, salt)
            fernet = Fernet(key)
            encrypted_text = fernet.encrypt(text.encode())
            
            # Combine salt and encrypted data
            encrypted_data = salt + encrypted_text
            encoded_data = base64.b64encode(encrypted_data).decode()
            
            return {
                'success': True,
                'encrypted_data': encoded_data
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    @staticmethod
    def decrypt_text(encrypted_data: str, password: str) -> dict:
        """Decrypt text with password"""
        try:
            # Decode the base64 data
            data = base64.b64decode(encrypted_data.encode())
            
            # Extract salt and encrypted text
            salt = data[:16]
            encrypted_text = data[16:]
            
            # Derive key and decrypt
            key = FileEncryption.derive_key(password, salt)
            fernet = Fernet(key)
            decrypted_text = fernet.decrypt(encrypted_text).decode()
            
            return {
                'success': True,
                'decrypted_text': decrypted_text
            }
        except Exception as e:
            return {
                'success': False,
                'error': 'Invalid password or corrupted file'
            }

    @staticmethod
    def encrypt_file(file_data: bytes, password: str) -> dict:
        """Encrypt file data with password"""
        try:
            salt = os.urandom(16)
            key = FileEncryption.derive_key(password, salt)
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(file_data)
            
            # Combine salt and encrypted data
            final_data = salt + encrypted_data
            encoded_data = base64.b64encode(final_data).decode()
            
            return {
                'success': True,
                'encrypted_data': encoded_data
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    @staticmethod
    def decrypt_file(encrypted_data: str, password: str) -> dict:
        """Decrypt file data with password"""
        try:
            # Decode the base64 data
            data = base64.b64decode(encrypted_data.encode())
            
            # Extract salt and encrypted data
            salt = data[:16]
            encrypted_file_data = data[16:]
            
            # Derive key and decrypt
            key = FileEncryption.derive_key(password, salt)
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_file_data)
            
            return {
                'success': True,
                'decrypted_data': decrypted_data
            }
        except Exception as e:
            return {
                'success': False,
                'error': 'Invalid password or corrupted file'
            }

# Initialize components
password_checker = PasswordStrengthChecker()
file_encryption = FileEncryption()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check-password', methods=['POST'])
def check_password():
    try:
        data = request.get_json()
        password = data.get('password', '')
        result = password_checker.check_strength(password)
        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/generate-password', methods=['POST'])
def generate_password():
    try:
        import random
        import string

        data = request.get_json()
        length = min(max(data.get('length', 12), 8), 50)  # Between 8-50 chars

        # Ensure we have all character types
        password_chars = []

        # Add required character types
        password_chars.append(random.choice(string.ascii_uppercase))
        password_chars.append(random.choice(string.ascii_lowercase))
        password_chars.append(random.choice(string.digits))
        password_chars.append(random.choice("!@#$%^&*"))

        # Fill remaining length with random characters
        all_chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        for _ in range(length - 4):
            password_chars.append(random.choice(all_chars))

        # Shuffle the password
        random.shuffle(password_chars)
        generated_password = ''.join(password_chars)

        # Check the strength of generated password
        strength_result = password_checker.check_strength(generated_password)

        return jsonify({
            'success': True,
            'password': generated_password,
            'strength': strength_result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/download-note', methods=['POST'])
def download_note():
    try:
        data = request.get_json()
        content = data.get('content', '')
        title = data.get('title', 'Untitled Note')
        file_type = data.get('type', 'txt')
        
        if file_type == 'txt':
            # Create text file
            output = io.StringIO()
            output.write(f"# {title}\n\n{content}")
            
            # Create temporary file
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
            temp_file.write(output.getvalue())
            temp_file.close()
            
            return send_file(
                temp_file.name,
                as_attachment=True,
                download_name=f"{title}.txt",
                mimetype='text/plain'
            )
            
        elif file_type == 'pdf':
            # Create PDF file
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            styles = getSampleStyleSheet()
            
            story = []
            story.append(Paragraph(f"<b>{title}</b>", styles['Title']))
            story.append(Paragraph("<br/><br/>", styles['Normal']))
            
            # Split content into paragraphs
            paragraphs = content.split('\n')
            for para in paragraphs:
                if para.strip():
                    story.append(Paragraph(para, styles['Normal']))
                else:
                    story.append(Paragraph("<br/>", styles['Normal']))
            
            doc.build(story)
            buffer.seek(0)
            
            return send_file(
                buffer,
                as_attachment=True,
                download_name=f"{title}.pdf",
                mimetype='application/pdf'
            )
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/upload-file', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No file selected'
            }), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No file selected'
            }), 400

        # Check file type
        if not file.filename.lower().endswith('.txt'):
            return jsonify({
                'success': False,
                'error': 'Only .txt files are supported'
            }), 400

        # Read file content
        content = file.read().decode('utf-8')
        
        return jsonify({
            'success': True,
            'content': content,
            'filename': file.filename
        })

    except UnicodeDecodeError:
        return jsonify({
            'success': False,
            'error': 'File encoding not supported. Please use UTF-8 encoded text files.'
        }), 400
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/upload-encrypted-file', methods=['POST'])
def upload_encrypted_file():
    try:
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No file selected'
            }), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No file selected'
            }), 400

        # Check file extensions for encrypted files
        allowed_extensions = ['.encrypted', '.enc', '.txt']
        file_ext = os.path.splitext(file.filename.lower())[1]
        
        if file_ext not in allowed_extensions:
            return jsonify({
                'success': False,
                'error': 'Only .encrypted, .enc, or .txt files are supported for decryption'
            }), 400

        # Read file content
        content = file.read().decode('utf-8')
        
        return jsonify({
            'success': True,
            'content': content,
            'filename': file.filename,
            'file_type': 'encrypted'
        })

    except UnicodeDecodeError:
        return jsonify({
            'success': False,
            'error': 'File encoding not supported. Please use UTF-8 encoded files.'
        }), 400
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/upload-txt-for-encryption', methods=['POST'])
def upload_txt_for_encryption():
    try:
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No file selected'
            }), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No file selected'
            }), 400

        # Check file type - only txt files for encryption
        if not file.filename.lower().endswith('.txt'):
            return jsonify({
                'success': False,
                'error': 'Only .txt files can be uploaded for encryption'
            }), 400

        # Read file content
        content = file.read().decode('utf-8')
        
        return jsonify({
            'success': True,
            'content': content,
            'filename': file.filename,
            'file_type': 'txt_for_encryption'
        })

    except UnicodeDecodeError:
        return jsonify({
            'success': False,
            'error': 'File encoding not supported. Please use UTF-8 encoded text files.'
        }), 400
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/encrypt-text', methods=['POST'])
def encrypt_text():
    try:
        data = request.get_json()
        text = data.get('text', '')
        password = data.get('password', '')
        
        if not text or not password:
            return jsonify({
                'success': False,
                'error': 'Text and password are required'
            }), 400
            
        result = file_encryption.encrypt_text(text, password)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/decrypt-text', methods=['POST'])
def decrypt_text():
    try:
        data = request.get_json()
        encrypted_data = data.get('encrypted_data', '')
        password = data.get('password', '')
        
        if not encrypted_data or not password:
            return jsonify({
                'success': False,
                'error': 'Encrypted data and password are required'
            }), 400
            
        result = file_encryption.decrypt_text(encrypted_data, password)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/encrypt-file', methods=['POST'])
def encrypt_file():
    try:
        data = request.get_json()
        file_content = data.get('file_content', '')
        password = data.get('password', '')
        
        if not file_content or not password:
            return jsonify({
                'success': False,
                'error': 'File content and password are required'
            }), 400
            
        # Convert text content to bytes
        file_data = file_content.encode('utf-8')
        result = file_encryption.encrypt_file(file_data, password)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/decrypt-file', methods=['POST'])
def decrypt_file():
    try:
        data = request.get_json()
        encrypted_data = data.get('encrypted_data', '')
        password = data.get('password', '')
        
        if not encrypted_data or not password:
            return jsonify({
                'success': False,
                'error': 'Encrypted data and password are required'
            }), 400
            
        result = file_encryption.decrypt_file(encrypted_data, password)
        
        if result['success']:
            # Convert bytes back to text
            try:
                decrypted_text = result['decrypted_data'].decode('utf-8')
                result['decrypted_text'] = decrypted_text
                del result['decrypted_data']  # Remove binary data
            except UnicodeDecodeError:
                result = {
                    'success': False,
                    'error': 'Decrypted file is not a valid text file'
                }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
