import os
import time
import hashlib
import psutil
import threading
import queue
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from malware_types import MalwareTypeDetector
import importlib.util

# Check if we can import the ML model
if importlib.util.find_spec("joblib") is not None:
    import joblib
    has_ml_model = True
    # Try to load the model
    try:
        model = joblib.load('ML_model/malwareclassifier-V2.pkl')
        feature_extraction_module = __import__('feature_extraction')
        def extract_features_for_file(file_path):
            return feature_extraction_module.extract_features(file_path)
    except:
        has_ml_model = False
else:
    has_ml_model = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='realtime_monitor.log'
)
logger = logging.getLogger('RealTimeMonitor')

class MalwareMonitor:
    def __init__(self, watch_directories=None, scan_interval=300):
        """
        Initialize the malware monitor
        
        Args:
            watch_directories: List of directories to watch for new files
            scan_interval: Interval in seconds for periodic system scans
        """
        self.watch_directories = watch_directories or []
        self.scan_interval = scan_interval
        self.file_queue = queue.Queue()
        self.malware_detector = MalwareTypeDetector()
        self.observer = Observer()
        self.is_running = False
        self.workers = []
        self.known_processes = set()
        self.suspicious_files = {}
        self.suspicious_processes = {}
        
    def start_monitoring(self, num_workers=2):
        """Start the monitoring process"""
        logger.info("Starting real-time malware monitoring")
        self.is_running = True
        
        # Start file event handlers
        for directory in self.watch_directories:
            if os.path.exists(directory):
                event_handler = FileCreatedHandler(self.file_queue)
                self.observer.schedule(event_handler, directory, recursive=True)
                logger.info(f"Watching directory: {directory}")
        
        # Start the file system observer
        self.observer.start()
        
        # Start worker threads to process files
        for i in range(num_workers):
            worker = threading.Thread(target=self._process_file_queue, daemon=True)
            worker.start()
            self.workers.append(worker)
        
        # Start periodic system scan
        scan_thread = threading.Thread(target=self._periodic_system_scan, daemon=True)
        scan_thread.start()
        self.workers.append(scan_thread)
        
        # Start process monitoring
        process_thread = threading.Thread(target=self._monitor_processes, daemon=True)
        process_thread.start()
        self.workers.append(process_thread)
        
        logger.info("Malware monitoring system started successfully")
    
    def stop_monitoring(self):
        """Stop the monitoring process"""
        logger.info("Stopping real-time malware monitoring")
        self.is_running = False
        
        # Stop the observer
        self.observer.stop()
        self.observer.join()
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=1.0)
        
        logger.info("Malware monitoring system stopped")
    
    def _process_file_queue(self):
        """Worker thread to process files in the queue"""
        while self.is_running:
            try:
                file_path = self.file_queue.get(timeout=1.0)
                self._analyze_file(file_path)
                self.file_queue.task_done()
            except queue.Empty:
                pass  # Queue is empty, continue waiting
            except Exception as e:
                logger.error(f"Error processing file: {e}")
    
    def _analyze_file(self, file_path):
        """Analyze a file for malware"""
        logger.info(f"Analyzing file: {file_path}")
        
        # Skip large files (>50MB) for performance
        try:
            if os.path.getsize(file_path) > 50 * 1024 * 1024:
                logger.info(f"Skipping large file: {file_path}")
                return
        except OSError:
            logger.warning(f"Cannot access file: {file_path}")
            return
            
        # Get file hash
        try:
            file_hash = self.malware_detector.calculate_file_hash(file_path)
        except Exception as e:
            logger.error(f"Error calculating hash: {e}")
            return
        
        # First, check with malware type detector
        try:
            result = self.malware_detector.detect_malware_type(file_path)
            if result["confidence"] > 0.5:
                logger.warning(f"Potential {result['detected_type']} detected: {file_path}")
                self.suspicious_files[file_path] = result
        except Exception as e:
            logger.error(f"Error detecting malware type: {e}")
        
        # If ML model is available, also check with it
        if has_ml_model:
            try:
                file_extension = os.path.splitext(file_path)[1].lower()
                if file_extension in ['.exe', '.dll']:
                    features = extract_features_for_file(file_path)
                    prediction = model.predict(features)
                    if prediction[0] == 1:
                        logger.warning(f"ML model detected malware: {file_path}")
                        # Update existing or add new entry
                        if file_path in self.suspicious_files:
                            self.suspicious_files[file_path]["ml_detection"] = True
                        else:
                            self.suspicious_files[file_path] = {
                                "detected_type": "Unknown (ML Detection)",
                                "confidence": 0.8,
                                "file_hash": file_hash,
                                "ml_detection": True
                            }
            except Exception as e:
                logger.error(f"Error running ML analysis: {e}")

    def _periodic_system_scan(self):
        """Periodically scan the system for suspicious files"""
        while self.is_running:
            logger.info("Starting periodic system scan")
            
            # Scan specific directories of interest
            critical_dirs = [
                os.path.join(os.environ.get('TEMP', 'C:\\Windows\\Temp')),
                os.path.join(os.environ.get('APPDATA', '')),
                os.path.join(os.environ.get('LOCALAPPDATA', ''))
            ]
            
            # Add user-specified directories
            all_dirs = list(set(critical_dirs + self.watch_directories))
            
            for directory in all_dirs:
                if os.path.exists(directory):
                    for root, _, files in os.walk(directory):
                        for file in files:
                            file_path = os.path.join(root, file)
                            # Only scan executables, scripts, and documents
                            if file.endswith(('.exe', '.dll', '.js', '.vbs', '.ps1', '.bat', '.docm', '.xlsm')):
                                self.file_queue.put(file_path)
            
            # Sleep until next scan
            time.sleep(self.scan_interval)
    
    def _monitor_processes(self):
        """Monitor running processes for suspicious activity"""
        while self.is_running:
            try:
                current_processes = set()
                
                # Get all running processes
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                    try:
                        process_info = proc.info
                        pid = process_info['pid']
                        exe_path = process_info.get('exe', '')
                        
                        current_processes.add(pid)
                        
                        # Check new processes only
                        if pid not in self.known_processes and exe_path:
                            # Analyze the executable file
                            if os.path.exists(exe_path):
                                self.file_queue.put(exe_path)
                                
                            # Additional checks for suspicious process behavior
                            try:
                                # Check for high CPU or memory usage
                                with proc.oneshot():
                                    cpu_percent = proc.cpu_percent(interval=0.1)
                                    memory_percent = proc.memory_percent()
                                    
                                    if cpu_percent > 80 or memory_percent > 50:
                                        process_name = process_info.get('name', 'Unknown')
                                        logger.warning(f"Suspicious resource usage by process: {process_name} (PID: {pid})")
                                        
                                        self.suspicious_processes[pid] = {
                                            'name': process_name,
                                            'exe': exe_path,
                                            'cpu': cpu_percent,
                                            'memory': memory_percent
                                        }
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                # Update known processes
                self.known_processes = current_processes
                
                # Sleep for a short time
                time.sleep(5)
            except Exception as e:
                logger.error(f"Error monitoring processes: {e}")
                time.sleep(10)  # Wait longer if there's an error
    
    def get_status_report(self):
        """Generate a status report of detected threats"""
        return {
            'suspicious_files': self.suspicious_files,
            'suspicious_processes': self.suspicious_processes,
            'monitored_directories': self.watch_directories,
            'is_running': self.is_running
        }


class FileCreatedHandler(FileSystemEventHandler):
    """Watches for file creation events and adds them to the queue"""
    def __init__(self, file_queue):
        self.file_queue = file_queue
    
    def on_created(self, event):
        if not event.is_directory:
            self.file_queue.put(event.src_path)
    
    def on_modified(self, event):
        if not event.is_directory:
            self.file_queue.put(event.src_path)


# Sample usage
if __name__ == "__main__":
    # Example of how to use the monitor
    watch_dirs = [
        os.path.join(os.path.expanduser('~'), 'Downloads'), 
        os.path.join(os.path.expanduser('~'), 'Documents')
    ]
    
    monitor = MalwareMonitor(watch_directories=watch_dirs)
    monitor.start_monitoring()
    
    try:
        # Keep the main thread alive
        while True:
            time.sleep(10)
            status = monitor.get_status_report()
            print(f"Monitoring {len(status['monitored_directories'])} directories")
            print(f"Suspicious files detected: {len(status['suspicious_files'])}")
            print(f"Suspicious processes detected: {len(status['suspicious_processes'])}")
    except KeyboardInterrupt:
        monitor.stop_monitoring()
        print("Monitoring stopped") 