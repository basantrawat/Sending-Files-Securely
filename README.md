# Secure File and Message Sharing Application

A Flask-based web application that provides end-to-end encryption for messages and files using hybrid encryption (RSA + AES). Users can generate RSA key pairs, encrypt content with a recipient's public key, and decrypt content with their private key.

## Features

- **RSA Key Pair Generation**: Generate 2048-bit or 4096-bit RSA key pairs
- **Hybrid Encryption**: Combines RSA asymmetric encryption with AES-256-GCM symmetric encryption
- **Multiple Content Types**: Encrypt and decrypt text messages, .txt files, and images (.png, .jpg)
- **Responsive UI**: Single-page interface styled with Tailwind CSS
- **Secure File Handling**: All files processed in memory without persistent storage
- **No Server Storage**: Private keys and decrypted content never stored on server

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Steps

1. Clone or download this repository

2. Create a virtual environment (recommended):
```bash
python -m venv venv
```

3. Activate the virtual environment:
   - Windows:
     ```bash
     venv\Scripts\activate
     ```
   - macOS/Linux:
     ```bash
     source venv/bin/activate
     ```

4. Install dependencies:
```bash
pip install -r requirements.txt
```

## Running the Application

### Development Mode

Run the application in development mode with debug enabled:

```bash
python app.py
```

The application will be available at `http://127.0.0.1:5000`

### Production Mode

For production deployment, use a production WSGI server like Gunicorn:

1. Install Gunicorn:
```bash
pip install gunicorn
```

2. Set environment variables:
```bash
# Windows (cmd)
set FLASK_ENV=production
set SECRET_KEY=your-secure-random-secret-key

# Windows (PowerShell)
$env:FLASK_ENV="production"
$env:SECRET_KEY="your-secure-random-secret-key"

# macOS/Linux
export FLASK_ENV=production
export SECRET_KEY=your-secure-random-secret-key
```

3. Run with Gunicorn:
```bash
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

## Configuration

The application can be configured using environment variables:

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `FLASK_ENV` | Environment mode (`development` or `production`) | `development` | No |
| `SECRET_KEY` | Flask secret key for session security | Auto-generated in dev | Yes (production) |
| `MAX_CONTENT_LENGTH` | Maximum file upload size in bytes | `10485760` (10MB) | No |
| `RSA_KEY_SIZE` | RSA key size in bits (2048 or 4096) | `2048` | No |

## Usage Instructions

### 1. Generate RSA Key Pair

1. Navigate to the **Key Generation** section
2. Click the **Generate Keys** button
3. Download both the **private key** and **public key** files
4. **Important**: Store your private key securely and never share it
5. Share your public key with anyone who wants to send you encrypted messages

### 2. Encrypt Content

1. Navigate to the **Encryption** section
2. Choose your input type:
   - **Text**: Enter plain text in the text area
   - **Text File**: Upload a .txt file
   - **Image**: Upload a .png or .jpg file
3. Upload the recipient's **public key** file
4. Click the **Encrypt** button
5. Download the encrypted file (`encrypted_data.bin`)
6. Send the encrypted file to the recipient

### 3. Decrypt Content

1. Navigate to the **Decryption** section
2. Upload the **encrypted data file** you received
3. Upload your **private key** file
4. Click the **Decrypt** button
5. View the decrypted content:
   - Text messages display directly in the browser
   - Images display inline in the browser

## Example Workflow

**Scenario**: Alice wants to send Bob a secure message

1. **Bob generates his key pair**:
   - Bob clicks "Generate Keys"
   - Bob downloads `private_key.pem` (keeps it secret)
   - Bob downloads `public_key.pem` (shares with Alice)

2. **Alice encrypts a message for Bob**:
   - Alice types her message in the text area
   - Alice uploads Bob's `public_key.pem`
   - Alice clicks "Encrypt"
   - Alice downloads `encrypted_data.bin`
   - Alice sends `encrypted_data.bin` to Bob

3. **Bob decrypts Alice's message**:
   - Bob uploads `encrypted_data.bin`
   - Bob uploads his `private_key.pem`
   - Bob clicks "Decrypt"
   - Bob reads Alice's message in the browser

## Security Considerations

### Key Management

- **Private keys are never stored on the server** - they are generated and immediately sent to your browser
- **You are responsible for storing your private key securely** - if you lose it, you cannot decrypt messages
- **Never share your private key** - only share your public key
- **Use strong passwords** if you choose to encrypt your private key file separately

### Encryption Strength

- RSA key size: 2048 bits (default) or 4096 bits (configurable)
- AES key size: 256 bits
- AES mode: GCM (provides both encryption and authentication)
- Random nonce generated for each encryption operation

### Data Privacy

- All file uploads are processed in memory only
- No files are permanently stored on the server
- Server memory is cleared after each request
- Use HTTPS in production to protect data in transit

### File Validation

- Supported file types: .txt, .png, .jpg
- Maximum file size: 10MB (configurable)
- PEM format validation for keys
- Content type verification

### Production Deployment

- **Always use HTTPS** in production (use Let's Encrypt for free SSL certificates)
- **Set a strong SECRET_KEY** environment variable
- **Use a production WSGI server** (Gunicorn, uWSGI) instead of Flask's development server
- **Configure firewall rules** to restrict access as needed
- **Keep dependencies updated** to patch security vulnerabilities

## Troubleshooting

### "Decryption failed" error

- Ensure you're using the correct private key that matches the public key used for encryption
- Verify the encrypted file is not corrupted
- Check that the file was encrypted using this application

### "Invalid public key format" error

- Ensure the public key file is in PEM format
- Verify the file was generated by this application or is compatible

### "File too large" error

- The default maximum file size is 10MB
- Increase `MAX_CONTENT_LENGTH` environment variable if needed
- Consider compressing large files before encryption

### Application won't start in production

- Ensure `SECRET_KEY` environment variable is set
- Check that all dependencies are installed
- Verify Python version is 3.8 or higher

## Technical Details

### Architecture

- **Backend**: Flask (Python web framework)
- **Cryptography**: Python `cryptography` library
- **Frontend**: HTML5, JavaScript, Tailwind CSS
- **Encryption**: Hybrid RSA + AES-GCM

### Encrypted Package Format

The application uses a custom binary format for encrypted data:
- Encrypted AES key (RSA encrypted)
- AES-GCM nonce
- AES-GCM authentication tag
- Content type metadata
- Encrypted content (AES-GCM encrypted)

## License

This project is provided as-is for educational and practical use.

## Support

For issues, questions, or contributions, please refer to the project repository.
