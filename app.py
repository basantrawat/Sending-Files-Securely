from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
import os
import base64
from crypto_service import generate_rsa_keypair, hybrid_encrypt, hybrid_decrypt
from file_handler import (
    read_file_content, detect_content_type, prepare_download_response,
    validate_file_type, validate_file_size, validate_pem_format
)
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User

app = Flask(__name__)

# Configuration class for environment-based settings
class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-secret-key'
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH') or 10 * 1024 * 1024)
    RSA_KEY_SIZE = int(os.environ.get('RSA_KEY_SIZE') or 2048)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def create_tables():
    db.create_all()

@app.route('/')
@login_required
def index():
    """Serve the home page"""
    return render_template('home.html', current_user=current_user)

@app.route('/generate')
@login_required
def generate_page():
    """Serve the generate keys page"""
    return render_template('generate.html', current_user=current_user)

@app.route('/encrypt-page')
@login_required
def encrypt_page():
    """Serve the encrypt page"""
    return render_template('encrypt.html', current_user=current_user)

@app.route('/decrypt-page')
@login_required
def decrypt_page():
    """Serve the decrypt page"""
    return render_template('decrypt.html', current_user=current_user)


@app.route('/generate-keys', methods=['POST'])
@login_required
def generate_keys():
    """
    Generate RSA key pair and return base64-encoded keys.
    
    Returns:
        JSON response with private_key and public_key (base64-encoded)
    """
    try:
        # Get RSA key size from configuration
        key_size = app.config['RSA_KEY_SIZE']
        
        # Generate RSA key pair
        private_key_pem, public_key_pem = generate_rsa_keypair(key_size)
        
        # Encode keys to base64 for JSON transport
        private_key_b64 = base64.b64encode(private_key_pem).decode('utf-8')
        public_key_b64 = base64.b64encode(public_key_pem).decode('utf-8')
        
        return jsonify({
            'success': True,
            'data': {
                'private_key': private_key_b64,
                'public_key': public_key_b64
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Failed to generate keys. Please try again.',
            'error_code': 'KEY_GENERATION_ERROR'
        }), 500


@app.route('/encrypt', methods=['POST'])
@login_required
def encrypt():
    """
    Encrypt content (text or file) using recipient's public key.
    
    Accepts:
        - text_content: Plain text to encrypt (optional)
        - file_content: File to encrypt (optional)
        - public_key: Recipient's public key file (required)
    
    Returns:
        Encrypted data as downloadable file
    """
    try:
        # Check if public key is provided
        if 'public_key' not in request.files:
            return jsonify({
                'success': False,
                'error': 'Recipient\'s public key is required.',
                'error_code': 'MISSING_PUBLIC_KEY'
            }), 400
        
        # Read and validate recipient's public key
        public_key_file = request.files['public_key']
        try:
            # Validate file size
            validate_file_size(public_key_file)
            public_key_pem = read_file_content(public_key_file)
            # Validate PEM format
            validate_pem_format(public_key_pem)
        except ValueError as e:
            return jsonify({
                'success': False,
                'error': str(e),
                'error_code': 'INVALID_PUBLIC_KEY'
            }), 400
        except Exception as e:
            return jsonify({
                'success': False,
                'error': 'Failed to read public key file.',
                'error_code': 'INVALID_PUBLIC_KEY_FILE'
            }), 400
        
        # Determine content type and get content to encrypt
        content_to_encrypt = None
        content_type = None
        
        # Check for text input
        if 'text_content' in request.form and request.form['text_content']:
            content_to_encrypt = request.form['text_content'].encode('utf-8')
            content_type = 'text/plain'
        
        # Check for file upload (takes precedence over text)
        elif 'file_content' in request.files:
            file_content = request.files['file_content']
            if file_content.filename:
                try:
                    # Validate file type
                    validate_file_type(file_content.filename)
                    # Validate file size
                    validate_file_size(file_content)
                    # Detect content type
                    content_type = detect_content_type(file_content.filename)
                    # Read file content
                    content_to_encrypt = read_file_content(file_content)
                except ValueError as e:
                    return jsonify({
                        'success': False,
                        'error': str(e),
                        'error_code': 'FILE_VALIDATION_ERROR'
                    }), 400
                except Exception as e:
                    return jsonify({
                        'success': False,
                        'error': 'Failed to read file content.',
                        'error_code': 'FILE_READ_ERROR'
                    }), 400
        
        # Check if content was provided
        if content_to_encrypt is None:
            return jsonify({
                'success': False,
                'error': 'No content provided. Please provide text or upload a file.',
                'error_code': 'MISSING_CONTENT'
            }), 400
        
        # Validate public key format
        try:
            # Attempt to use the public key for encryption
            encrypted_package = hybrid_encrypt(content_to_encrypt, public_key_pem, content_type)
        except ValueError as e:
            return jsonify({
                'success': False,
                'error': 'Invalid public key format. Please provide a valid PEM-encoded public key.',
                'error_code': 'INVALID_PUBLIC_KEY'
            }), 400
        except Exception as e:
            return jsonify({
                'success': False,
                'error': 'Encryption failed. Please check your inputs and try again.',
                'error_code': 'ENCRYPTION_ERROR'
            }), 500
        
        # Return encrypted data as downloadable file
        return prepare_download_response(
            encrypted_package,
            'encrypted_data.bin',
            'application/octet-stream'
        )
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred during encryption.',
            'error_code': 'UNEXPECTED_ERROR'
        }), 500

@app.route('/decrypt', methods=['POST'])
@login_required
def decrypt():
    """
    Decrypt encrypted file using private key.
    
    Accepts:
        - encrypted_file: Encrypted data file (required)
        - private_key: Private key file (required)
    
    Returns:
        JSON response with decrypted text or image data
    """
    try:
        # Check if encrypted file is provided
        if 'encrypted_file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'Encrypted file is required.',
                'error_code': 'MISSING_ENCRYPTED_FILE'
            }), 400
        
        # Check if private key is provided
        if 'private_key' not in request.files:
            return jsonify({
                'success': False,
                'error': 'Private key is required.',
                'error_code': 'MISSING_PRIVATE_KEY'
            }), 400
        
        # Read and validate encrypted file
        encrypted_file = request.files['encrypted_file']
        try:
            # Validate file size
            validate_file_size(encrypted_file)
            encrypted_package = read_file_content(encrypted_file)
        except ValueError as e:
            return jsonify({
                'success': False,
                'error': str(e),
                'error_code': 'INVALID_ENCRYPTED_FILE'
            }), 400
        except Exception as e:
            return jsonify({
                'success': False,
                'error': 'Failed to read encrypted file.',
                'error_code': 'INVALID_ENCRYPTED_FILE'
            }), 400
        
        # Read and validate private key
        private_key_file = request.files['private_key']
        try:
            # Validate file size
            validate_file_size(private_key_file)
            private_key_pem = read_file_content(private_key_file)
            # Validate PEM format
            validate_pem_format(private_key_pem)
        except ValueError as e:
            return jsonify({
                'success': False,
                'error': str(e),
                'error_code': 'INVALID_PRIVATE_KEY'
            }), 400
        except Exception as e:
            return jsonify({
                'success': False,
                'error': 'Failed to read private key file.',
                'error_code': 'INVALID_PRIVATE_KEY_FILE'
            }), 400
        
        # Attempt to decrypt
        try:
            decrypted_data, content_type = hybrid_decrypt(encrypted_package, private_key_pem)
        except ValueError as e:
            return jsonify({
                'success': False,
                'error': 'Invalid private key format. Please provide a valid PEM-encoded private key.',
                'error_code': 'INVALID_PRIVATE_KEY'
            }), 400
        except Exception as e:
            # Could be wrong key, corrupted data, or other decryption failure
            return jsonify({
                'success': False,
                'error': 'Decryption failed. Please ensure you are using the correct private key and the file is not corrupted.',
                'error_code': 'DECRYPTION_ERROR'
            }), 400
        
        # Return decrypted content based on content type
        if content_type == 'text/plain':
            # Return text as JSON
            try:
                decrypted_text = decrypted_data.decode('utf-8')
                return jsonify({
                    'success': True,
                    'data': {
                        'content_type': 'text',
                        'content': decrypted_text
                    }
                }), 200
            except UnicodeDecodeError:
                return jsonify({
                    'success': False,
                    'error': 'Failed to decode decrypted text. The file may be corrupted.',
                    'error_code': 'TEXT_DECODE_ERROR'
                }), 400
        
        elif content_type in ['image/png', 'image/jpeg']:
            # Return image data as base64-encoded JSON
            image_b64 = base64.b64encode(decrypted_data).decode('utf-8')
            return jsonify({
                'success': True,
                'data': {
                    'content_type': 'image',
                    'mime_type': content_type,
                    'content': image_b64
                }
            }), 200
        
        else:
            # Unknown content type
            return jsonify({
                'success': False,
                'error': f'Unsupported content type: {content_type}',
                'error_code': 'UNSUPPORTED_CONTENT_TYPE'
            }), 400
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred during decryption.',
            'error_code': 'UNEXPECTED_ERROR'
        }), 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists.')
            return redirect(url_for('register'))
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=True)
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
