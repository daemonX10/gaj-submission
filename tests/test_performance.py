import os
import sys
import time
import pytest
import tempfile
import shutil
import random
import multiprocessing
import threading

# Add parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import with fallbacks
try:
    from batch_processor import BatchProcessor
    has_batch_processor = True
except ImportError:
    has_batch_processor = False

try:
    from app import analyze_file
    has_analyzer = True
except ImportError:
    has_analyzer = False

# Paths
TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_data')
TEMP_DIR = tempfile.mkdtemp()
RESULTS_DIR = os.path.join(TEMP_DIR, 'results')

# Setup and teardown
def setup_module(module):
    """Setup test environment"""
    # Create test data directory if it doesn't exist
    os.makedirs(TEST_DATA_DIR, exist_ok=True)
    # Create temporary directory
    os.makedirs(TEMP_DIR, exist_ok=True)
    # Create results directory
    os.makedirs(RESULTS_DIR, exist_ok=True)
    # Generate test files for batch processing
    generate_batch_files()

def teardown_module(module):
    """Cleanup test environment"""
    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)

def generate_batch_files(num_files=20):
    """Generate a batch of test files"""
    batch_dir = os.path.join(TEMP_DIR, 'batch')
    os.makedirs(batch_dir, exist_ok=True)
    
    # Generate files with different sizes
    files = []
    for i in range(num_files):
        # Alternate between small and large files
        size = random.choice([10*1024, 100*1024, 500*1024])
        is_malicious = (i % 5 == 0)  # Make every 5th file malicious
        
        if i % 3 == 0:
            # Executable
            ext = '.exe'
            filename = f'test_{i}_exe{ext}'
        elif i % 3 == 1:
            # Document
            ext = '.doc'
            filename = f'test_{i}_doc{ext}'
        else:
            # Archive
            ext = '.zip'
            filename = f'test_{i}_zip{ext}'
        
        filepath = os.path.join(batch_dir, filename)
        create_test_file(filepath, size, is_malicious)
        files.append(filepath)
    
    return files

def create_test_file(filepath, size, is_malicious=False):
    """Create a test file with specified size and malicious content"""
    with open(filepath, 'wb') as f:
        # Start with appropriate header
        if filepath.endswith('.exe'):
            # PE header
            f.write(b'MZ')
            f.write(b'\x90' * 58)
            f.write(b'\x00\x00\x00\x00')
        elif filepath.endswith('.doc'):
            # Document header
            f.write(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1')
        elif filepath.endswith('.zip'):
            # Zip header
            f.write(b'PK\x03\x04')
        
        # Add malicious content if specified
        if is_malicious:
            malicious_content = [
                b'CreateRemoteThread',
                b'VirtualAllocEx',
                b'WriteProcessMemory',
                b'cmd.exe /c',
                b'powershell.exe -enc',
                b'HTTP://malicious.example.com',
                b'RegCreateKey',
                b'system32\\drivers',
                b'bitcoin',
                b'ransom',
                b'.onion',
                b'URLDownloadToFile'
            ]
            for content in malicious_content:
                f.write(content + b'\x00')
        
        # Fill the rest with random data to reach the desired size
        current_size = f.tell()
        remaining = size - current_size
        if remaining > 0:
            random_data = os.urandom(remaining)
            f.write(random_data)

# Performance tests
@pytest.mark.skipif(not has_batch_processor, reason="Batch processor not available")
def test_batch_processing_performance():
    """Test batch processing performance"""
    if not has_batch_processor:
        pytest.skip("Batch processor not available")
    
    # Generate batch files
    batch_files = generate_batch_files(num_files=10)
    
    # Initialize processor
    processor = BatchProcessor(output_dir=RESULTS_DIR)
    
    # Start timer
    start_time = time.time()
    
    # Process files with single worker
    processor.max_workers = 1
    result1 = processor.process_files(batch_files)
    
    # Measure time with single worker
    single_worker_time = time.time() - start_time
    
    # Process files with multiple workers
    start_time = time.time()
    processor.max_workers = multiprocessing.cpu_count()
    result2 = processor.process_files(batch_files)
    
    # Measure time with multiple workers
    multiple_worker_time = time.time() - start_time
    
    # Check speedup
    assert multiple_worker_time < single_worker_time, "Multiple workers should be faster"
    
    # Print times for reference
    print(f"Single worker time: {single_worker_time:.2f}s")
    print(f"Multiple worker time: {multiple_worker_time:.2f}s")
    print(f"Speedup: {single_worker_time / multiple_worker_time:.2f}x")

@pytest.mark.skipif(not has_analyzer, reason="File analyzer not available")
def test_large_file_processing():
    """Test processing of large files"""
    if not has_analyzer:
        pytest.skip("File analyzer not available")
    
    # Create large test files
    large_exe = os.path.join(TEMP_DIR, 'large.exe')
    create_test_file(large_exe, 5*1024*1024, False)  # 5MB
    
    large_malicious_exe = os.path.join(TEMP_DIR, 'large_malicious.exe')
    create_test_file(large_malicious_exe, 5*1024*1024, True)  # 5MB
    
    # Analyze large benign file
    start_time = time.time()
    benign_result = analyze_file(large_exe)
    benign_time = time.time() - start_time
    
    # Analyze large malicious file
    start_time = time.time()
    malicious_result = analyze_file(large_malicious_exe)
    malicious_time = time.time() - start_time
    
    # Check results
    assert benign_result is not None
    assert malicious_result is not None
    
    # Print times for reference
    print(f"Large benign file analysis time: {benign_time:.2f}s")
    print(f"Large malicious file analysis time: {malicious_time:.2f}s")

@pytest.mark.skipif(not has_batch_processor, reason="Batch processor not available")
def test_batch_memory_usage():
    """Test memory usage during batch processing"""
    if not has_batch_processor:
        pytest.skip("Batch processor not available")
    
    # Generate batch files
    batch_files = generate_batch_files(num_files=30)
    
    # Initialize processor
    processor = BatchProcessor(output_dir=RESULTS_DIR)
    
    # Track memory usage
    memory_usage = []
    stop_tracking = threading.Event()
    
    def track_memory():
        try:
            import psutil
        except ImportError:
            print("psutil not available, skipping memory tracking")
            return
        
        process = psutil.Process(os.getpid())
        while not stop_tracking.is_set():
            memory_usage.append(process.memory_info().rss / 1024 / 1024)  # MB
            time.sleep(0.1)
    
    # Start memory tracking
    tracker = threading.Thread(target=track_memory)
    tracker.daemon = True
    tracker.start()
    
    # Process files
    processor.max_workers = multiprocessing.cpu_count()
    processor.process_files(batch_files)
    
    # Stop memory tracking
    stop_tracking.set()
    tracker.join(timeout=1.0)
    
    # Check memory usage
    if memory_usage:
        avg_memory = sum(memory_usage) / len(memory_usage)
        max_memory = max(memory_usage)
        print(f"Average memory usage: {avg_memory:.2f} MB")
        print(f"Peak memory usage: {max_memory:.2f} MB")
        
        # Memory should not exceed 1GB for this test
        assert max_memory < 1024, f"Memory usage too high: {max_memory:.2f} MB"

@pytest.mark.skipif(not has_analyzer, reason="File analyzer not available")
def test_multi_format_batch():
    """Test batch processing with multiple file formats"""
    # Create files of different formats
    files = []
    formats = [
        ('test_exe.exe', '.exe'),
        ('test_dll.dll', '.dll'),
        ('test_doc.doc', '.doc'),
        ('test_pdf.pdf', '.pdf'),
        ('test_zip.zip', '.zip'),
        ('test_js.js', '.js'),
        ('test_py.py', '.py')
    ]
    
    for name, ext in formats:
        path = os.path.join(TEMP_DIR, name)
        create_test_file(path, 100*1024, False)
        files.append(path)
    
    # If batch processor is available, use it
    if has_batch_processor:
        processor = BatchProcessor(output_dir=RESULTS_DIR)
        results = processor.process_files(files)
        
        # Check results
        assert results is not None
        assert len(results) == len(files)
    else:
        # Fallback: process files one by one
        for file_path in files:
            result = analyze_file(file_path)
            assert result is not None

if __name__ == '__main__':
    pytest.main(['-xvs', __file__]) 