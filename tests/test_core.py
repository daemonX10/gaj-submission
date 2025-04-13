import os
import sys
import pytest
import tempfile
import shutil
import hashlib
import random
import string
import numpy as np

# Add parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Try to import required modules
try:
    import joblib
    has_joblib = True
except ImportError:
    has_joblib = False

try:
    import pefile
    has_pefile = True
except ImportError:
    has_pefile = False

# Import our modules with fallback handling
from app import allowed_file, fallback_extract_features, fallback_detect_malware
try:
    from feature_extraction import extract_features
    has_feature_extractor = True
except ImportError:
    has_feature_extractor = False

try:
    from malware_types import MalwareTypeDetector
    has_malware_type_detector = True
except ImportError:
    has_malware_type_detector = False

try:
    from document_analyzer import DocumentAnalyzer
    has_document_analyzer = True
except ImportError:
    has_document_analyzer = False

# Paths
MODEL_PATH = 'ML_model/malwareclassifier-V2.pkl'
TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_data')
SAMPLE_EXE_PATH = os.path.join(TEST_DATA_DIR, 'sample.exe')
SAMPLE_DOC_PATH = os.path.join(TEST_DATA_DIR, 'sample.doc')
TEMP_DIR = tempfile.mkdtemp()

# Setup and teardown
def setup_module(module):
    """Setup test environment"""
    # Create test data directory if it doesn't exist
    os.makedirs(TEST_DATA_DIR, exist_ok=True)
    # Create temporary directory
    os.makedirs(TEMP_DIR, exist_ok=True)
    # Generate test files
    create_test_files()

def teardown_module(module):
    """Cleanup test environment"""
    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)

def create_test_files():
    """Create test files for testing"""
    # Create a benign sample executable
    create_benign_exe()
    # Create a malicious sample executable
    create_malicious_exe()
    # Create a sample document
    create_sample_document()

def create_benign_exe():
    """Create a benign sample executable for testing"""
    exe_path = os.path.join(TEST_DATA_DIR, 'benign.exe')
    with open(exe_path, 'wb') as f:
        # PE file header
        f.write(b'MZ')
        f.write(b'\x90' * 58)  # Padding
        f.write(b'\x00\x00\x00\x00')  # PE header offset
        # Simple content
        f.write(b'This is a benign test file.\x00')
        f.write(b'\x00' * 100)  # Padding

def create_malicious_exe():
    """Create a malicious sample executable for testing"""
    exe_path = os.path.join(TEST_DATA_DIR, 'malicious.exe')
    with open(exe_path, 'wb') as f:
        # PE file header
        f.write(b'MZ')
        f.write(b'\x90' * 58)  # Padding
        f.write(b'\x00\x00\x00\x00')  # PE header offset
        # Add some suspicious strings
        f.write(b'CreateRemoteThread\x00')
        f.write(b'VirtualAllocEx\x00')
        f.write(b'WriteProcessMemory\x00')
        f.write(b'cmd.exe /c\x00')
        f.write(b'ShellExecute\x00')
        f.write(b'HTTP://malicious.example.com\x00')
        f.write(b'WinExec\x00')
        f.write(b'\x00' * 50)  # Padding

def create_sample_document():
    """Create a sample document for testing"""
    doc_path = os.path.join(TEST_DATA_DIR, 'sample.doc')
    with open(doc_path, 'wb') as f:
        # Document header
        f.write(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1')  # OLE header
        f.write(b'\x00' * 16)  # Padding
        # Content
        f.write(b'This is a sample document for testing.\x00')
        f.write(b'\x00' * 100)  # Padding

def generate_random_file(path, size=1024, has_malicious_content=False):
    """Generate a random file with optional malicious content"""
    with open(path, 'wb') as f:
        # Generate random content
        content = bytes(''.join(random.choices(string.ascii_letters + string.digits, k=size)), 'utf-8')
        
        # Add malicious content if specified
        if has_malicious_content:
            malicious_strings = [
                b'CreateRemoteThread',
                b'VirtualAllocEx',
                b'WriteProcessMemory',
                b'cmd.exe /c',
                b'powershell -enc',
                b'HTTP://malicious.example.com',
                b'bitcoin',
                b'ransom'
            ]
            
            for s in malicious_strings:
                pos = random.randint(0, max(0, len(content) - len(s)))
                content = content[:pos] + s + content[pos + len(s):]
        
        f.write(content)

# Tests
def test_allowed_file():
    """Test allowed_file function"""
    assert allowed_file('test.exe') == True
    assert allowed_file('test.dll') == True
    assert allowed_file('test.doc') == True
    assert allowed_file('test.pdf') == True
    assert allowed_file('test.zip') == True
    assert allowed_file('test.js') == True
    assert allowed_file('test.nosupported') == False
    assert allowed_file('test') == False

def test_fallback_extract_features():
    """Test fallback_extract_features function"""
    # Create test file
    test_file = os.path.join(TEMP_DIR, 'test_file.exe')
    with open(test_file, 'wb') as f:
        f.write(b'MZ' + b'\x00' * 1000)  # Simple executable-like file
    
    # Extract features
    features = fallback_extract_features(test_file)
    
    # Check result
    assert isinstance(features, np.ndarray)
    assert features.shape[1] == 5  # Should have 5 features

def test_fallback_detect_malware():
    """Test fallback_detect_malware function"""
    # Create benign test file
    benign_file = os.path.join(TEMP_DIR, 'benign_test.txt')
    with open(benign_file, 'w') as f:
        f.write('This is a benign test file with no suspicious content.')
    
    # Create malicious test file
    malicious_file = os.path.join(TEMP_DIR, 'malicious_test.txt')
    with open(malicious_file, 'w') as f:
        f.write('CreateRemoteThread VirtualAllocEx WriteProcessMemory cmd.exe ransom bitcoin')
    
    # Test detection
    assert fallback_detect_malware(benign_file) == False
    assert fallback_detect_malware(malicious_file) == True

@pytest.mark.skipif(not has_feature_extractor, reason="Feature extractor not available")
def test_feature_extraction():
    """Test feature extraction if available"""
    # Create test file
    test_file = os.path.join(TEMP_DIR, 'test_feature.exe')
    generate_random_file(test_file, size=2048)
    
    # Extract features
    features = extract_features(test_file)
    
    # Check result
    assert features is not None
    assert isinstance(features, np.ndarray) or hasattr(features, 'shape')

@pytest.mark.skipif(not has_malware_type_detector, reason="Malware type detector not available")
def test_malware_type_detection():
    """Test malware type detection if available"""
    # Create test file with malicious content
    test_file = os.path.join(TEMP_DIR, 'malware_detection_test.exe')
    generate_random_file(test_file, has_malicious_content=True)
    
    # Initialize detector
    detector = MalwareTypeDetector()
    
    # Detect malware type
    result = detector.detect_malware_type(test_file)
    
    # Check result
    assert result is not None
    assert isinstance(result, dict)
    assert 'detected_type' in result
    assert 'confidence' in result

@pytest.mark.skipif(not has_document_analyzer, reason="Document analyzer not available")
def test_document_analysis():
    """Test document analysis if available"""
    # Create test document
    test_doc = os.path.join(TEMP_DIR, 'test_doc.doc')
    with open(test_doc, 'wb') as f:
        f.write(b'\xD0\xCF\x11\xE0')  # OLE header
        f.write(b'Document content with macro = "test"')
    
    # Initialize analyzer
    analyzer = DocumentAnalyzer()
    
    # Analyze document
    result = analyzer.analyze_document(test_doc)
    
    # Check result
    assert result is not None
    assert isinstance(result, dict)

@pytest.mark.skipif(not has_joblib or not os.path.exists(MODEL_PATH), reason="ML model not available")
def test_model_loading():
    """Test loading the ML model"""
    # Load model
    model = joblib.load(MODEL_PATH)
    
    # Check model
    assert model is not None
    assert hasattr(model, 'predict')

def test_file_hash_functions():
    """Test file hash calculation functions"""
    # Create test file
    test_file = os.path.join(TEMP_DIR, 'hash_test.txt')
    with open(test_file, 'w') as f:
        f.write('Test content for hashing')
    
    # Calculate MD5 hash
    md5 = hashlib.md5()
    with open(test_file, 'rb') as f:
        md5.update(f.read())
    md5_hash = md5.hexdigest()
    
    # Calculate SHA-256 hash
    sha256 = hashlib.sha256()
    with open(test_file, 'rb') as f:
        sha256.update(f.read())
    sha256_hash = sha256.hexdigest()
    
    # Check hashes
    assert len(md5_hash) == 32
    assert len(sha256_hash) == 64

if __name__ == '__main__':
    pytest.main(['-xvs', __file__]) 