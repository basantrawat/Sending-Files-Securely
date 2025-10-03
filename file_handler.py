"""
File handler module for secure file and message sharing application.
Handles file uploads, content type detection, and download responses.
"""

from flask import send_file, Response
from werkzeug.datastructures import FileStorage
import io

# File validation constants
ALLOWED_FILE_EXTENSIONS = {'.txt', '.png', '.jpg', '.jpeg'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB in bytes


def read_file_content(file_storage):
    """
    Read Flask FileStorage object and return content as bytes.
    Files are read entirely into memory without writing to disk.
    
    Args:
        file_storage: Flask FileStorage object from request.files
        
    Returns:
        bytes: File content as bytes
        
    Raises:
        ValueError: If file_storage is None or invalid
        IOError: If file read fails
    """
    if file_storage is None:
        raise ValueError("No file provided")
    
    if not isinstance(file_storage, FileStorage):
        raise ValueError("Invalid file storage object")
    
    try:
        # Seek to beginning to ensure we read from start
        file_storage.seek(0)
        
        # Read file content as bytes (entirely in memory)
        content = file_storage.read()
        
        if not content:
            raise ValueError("File is empty")
        
        # Reset file pointer for potential re-reads
        file_storage.seek(0)
        
        return content
    except Exception as e:
        raise IOError(f"Failed to read file content: {str(e)}")


def detect_content_type(filename, content=None):
    """
    Detect content type based on filename and optionally content.
    
    Args:
        filename: Name of the file
        content: Optional bytes content for additional validation
        
    Returns:
        str: Standardized content type string ('text/plain', 'image/png', 'image/jpeg')
        
    Raises:
        ValueError: If file type is not supported
    """
    if not filename:
        raise ValueError("Filename is required")
    
    # Get file extension
    filename_lower = filename.lower()
    
    # Check for supported file types
    if filename_lower.endswith('.txt'):
        return 'text/plain'
    elif filename_lower.endswith('.png'):
        return 'image/png'
    elif filename_lower.endswith('.jpg') or filename_lower.endswith('.jpeg'):
        return 'image/jpeg'
    else:
        raise ValueError(f"Unsupported file type. Only .txt, .png, and .jpg files are allowed")


def validate_file_type(filename):
    """
    Validate that file has an allowed extension.
    
    Args:
        filename: Name of the file to validate
        
    Returns:
        bool: True if file type is allowed
        
    Raises:
        ValueError: If file type is not allowed
    """
    if not filename:
        raise ValueError("Filename is required")
    
    # Get file extension
    filename_lower = filename.lower()
    extension = None
    
    for ext in ALLOWED_FILE_EXTENSIONS:
        if filename_lower.endswith(ext):
            extension = ext
            break
    
    if not extension:
        allowed_types = ', '.join(ALLOWED_FILE_EXTENSIONS)
        raise ValueError(f"Unsupported file type. Only {allowed_types} files are allowed")
    
    return True


def validate_file_size(file_storage, max_size=MAX_FILE_SIZE):
    """
    Validate that file size is within allowed limit.
    
    Args:
        file_storage: Flask FileStorage object
        max_size: Maximum allowed file size in bytes
        
    Returns:
        bool: True if file size is within limit
        
    Raises:
        ValueError: If file size exceeds limit
    """
    if not isinstance(file_storage, FileStorage):
        raise ValueError("Invalid file storage object")
    
    # Read file to check size
    file_storage.seek(0, 2)  # Seek to end
    file_size = file_storage.tell()
    file_storage.seek(0)  # Reset to beginning
    
    if file_size > max_size:
        max_size_mb = max_size / (1024 * 1024)
        raise ValueError(f"File size exceeds maximum allowed size of {max_size_mb:.0f}MB")
    
    if file_size == 0:
        raise ValueError("File is empty")
    
    return True


def validate_pem_format(pem_data):
    """
    Validate that data is in PEM format.
    
    Args:
        pem_data: Bytes data to validate
        
    Returns:
        bool: True if data appears to be valid PEM format
        
    Raises:
        ValueError: If data is not valid PEM format
    """
    if not pem_data:
        raise ValueError("PEM data is empty")
    
    try:
        # Convert to string if bytes
        if isinstance(pem_data, bytes):
            pem_str = pem_data.decode('utf-8')
        else:
            pem_str = pem_data
        
        # Check for PEM markers
        has_begin = '-----BEGIN' in pem_str
        has_end = '-----END' in pem_str
        
        if not (has_begin and has_end):
            raise ValueError("Invalid PEM format. PEM file must contain BEGIN and END markers")
        
        # Check for common PEM key types
        valid_key_types = [
            'RSA PRIVATE KEY',
            'PRIVATE KEY',
            'PUBLIC KEY',
            'RSA PUBLIC KEY'
        ]
        
        has_valid_type = any(key_type in pem_str for key_type in valid_key_types)
        
        if not has_valid_type:
            raise ValueError("Invalid PEM format. File does not contain a recognized key type")
        
        return True
        
    except UnicodeDecodeError:
        raise ValueError("Invalid PEM format. File contains invalid characters")


def prepare_download_response(data, filename, mimetype):
    """
    Create Flask response for file download with appropriate headers.
    
    Args:
        data: File content as bytes
        filename: Name for the downloaded file
        mimetype: MIME type for the file
        
    Returns:
        Flask Response object configured for file download
        
    Raises:
        ValueError: If required parameters are missing or invalid
    """
    if not data:
        raise ValueError("No data provided for download")
    
    if not filename:
        raise ValueError("Filename is required")
    
    if not mimetype:
        raise ValueError("MIME type is required")
    
    try:
        # Create BytesIO object from data
        file_obj = io.BytesIO(data)
        file_obj.seek(0)
        
        # Create response with appropriate headers
        response = Response(
            file_obj.read(),
            mimetype=mimetype,
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Type': mimetype,
                'Content-Length': str(len(data))
            }
        )
        
        return response
    except Exception as e:
        raise IOError(f"Failed to prepare download response: {str(e)}")
