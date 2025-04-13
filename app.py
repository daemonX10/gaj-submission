from flask import Flask, request, render_template, jsonify, send_file, redirect, url_for, flash
import joblib
import os
import logging
import importlib.util
import json
import hashlib
import tempfile
import shutil
from werkzeug.utils import secure_filename
from datetime import datetime
import threading
import argparse
import magic
import numpy as np
import re

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='app.log'
)
logger = logging.getLogger('Malware-Detector')

# Initialize Flask app
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload size

# Configuration
UPLOAD_FOLDER = 'uploads'
RESULTS_FOLDER = 'results'
BATCH_FOLDER = 'batch_uploads'
MODEL_PATH = 'ML_model/malwareclassifier-V2.pkl'
ALLOWED_EXTENSIONS = {
    'executable': {'exe', 'dll', 'sys', 'ocx', 'com', 'scr'},
    'document': {'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'pdf', 'rtf', 'txt'},
    'script': {'js', 'py', 'ps1', 'vbs', 'bat', 'sh', 'cmd'},
    'archive': {'zip', 'rar', '7z', 'tar', 'gz'}
}

# Create required directories
for folder in [UPLOAD_FOLDER, RESULTS_FOLDER, BATCH_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# Initialize components with fallback options
def init_components():
    components = {
        'ml_model': {'status': 'unavailable', 'instance': None, 'error': None},
        'feature_extractor': {'status': 'unavailable', 'instance': None, 'error': None},
        'malware_type_detector': {'status': 'unavailable', 'instance': None, 'error': None},
        'document_analyzer': {'status': 'unavailable', 'instance': None, 'error': None},
        'vt_scanner': {'status': 'unavailable', 'instance': None, 'error': None},
        'dynamic_analyzer': {'status': 'unavailable', 'instance': None, 'error': None},
        'batch_processor': {'status': 'unavailable', 'instance': None, 'error': None},
        'model_explainer': {'status': 'unavailable', 'instance': None, 'error': None},
        'realtime_monitor': {'status': 'unavailable', 'instance': None, 'error': None}
    }
    
    # Try to initialize ML model
    try:
        import joblib
        components['ml_model']['instance'] = joblib.load(MODEL_PATH)
        components['ml_model']['status'] = 'available'
        logger.info("ML model loaded successfully")
    except Exception as e:
        logger.error(f"Error loading ML model: {e}")
        components['ml_model']['error'] = str(e)
    
    # Try to initialize feature extractor
    try:
        import feature_extraction
        components['feature_extractor']['instance'] = feature_extraction
        components['feature_extractor']['status'] = 'available'
        logger.info("Feature extractor loaded successfully")
    except Exception as e:
        logger.error(f"Error loading feature extractor: {e}")
        components['feature_extractor']['error'] = str(e)
    
    # Try to initialize malware type detector
    try:
        from malware_types import MalwareTypeDetector
        components['malware_type_detector']['instance'] = MalwareTypeDetector()
        components['malware_type_detector']['status'] = 'available'
        logger.info("Malware type detector loaded successfully")
    except Exception as e:
        logger.error(f"Error loading malware type detector: {e}")
        components['malware_type_detector']['error'] = str(e)
    
    # Try to initialize document analyzer
    try:
        from document_analyzer import DocumentAnalyzer
        components['document_analyzer']['instance'] = DocumentAnalyzer()
        components['document_analyzer']['status'] = 'available'
        logger.info("Document analyzer loaded successfully")
    except Exception as e:
        logger.error(f"Error loading document analyzer: {e}")
        components['document_analyzer']['error'] = str(e)
    
    # Try to initialize VirusTotal scanner
    try:
        from vt_api import VirusTotalScanner
        vt_scanner = VirusTotalScanner()
        if vt_scanner.enabled:
            components['vt_scanner']['instance'] = vt_scanner
            components['vt_scanner']['status'] = 'available'
            logger.info("VirusTotal scanner loaded successfully")
        else:
            components['vt_scanner']['error'] = "VirusTotal API key not configured"
            logger.warning("VirusTotal scanner initialized but API key not configured")
    except Exception as e:
        logger.error(f"Error loading VirusTotal scanner: {e}")
        components['vt_scanner']['error'] = str(e)
    
    # Try to initialize dynamic analyzer
    try:
        from dynamic_analysis import DynamicAnalyzer
        components['dynamic_analyzer']['instance'] = DynamicAnalyzer()
        components['dynamic_analyzer']['status'] = 'available'
        logger.info("Dynamic analyzer loaded successfully")
    except Exception as e:
        logger.error(f"Error loading dynamic analyzer: {e}")
        components['dynamic_analyzer']['error'] = str(e)
    
    # Try to initialize batch processor
    try:
        from batch_processor import BatchProcessor
        components['batch_processor']['instance'] = BatchProcessor(output_dir=RESULTS_FOLDER)
        components['batch_processor']['status'] = 'available'
        logger.info("Batch processor loaded successfully")
    except Exception as e:
        logger.error(f"Error loading batch processor: {e}")
        components['batch_processor']['error'] = str(e)
    
    # Try to initialize model explainer
    try:
        from model_explainer import ModelExplainer
        components['model_explainer']['instance'] = ModelExplainer(model_path=MODEL_PATH)
        components['model_explainer']['status'] = 'available'
        logger.info("Model explainer loaded successfully")
    except Exception as e:
        logger.error(f"Error loading model explainer: {e}")
        components['model_explainer']['error'] = str(e)
    
    # Try to initialize realtime monitor
    try:
        from realtime_monitor import RealtimeMonitor
        components['realtime_monitor']['instance'] = RealtimeMonitor()
        components['realtime_monitor']['status'] = 'available'
        logger.info("Realtime monitor loaded successfully")
    except Exception as e:
        logger.error(f"Error loading realtime monitor: {e}")
        components['realtime_monitor']['error'] = str(e)
    
    return components

# Initialize components
COMPONENTS = init_components()

def allowed_file(filename):
    """Check if a file is allowed based on its extension"""
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    return ext in sum(ALLOWED_EXTENSIONS.values(), set())

def get_file_category(filename):
    """Determine the file category based on extension"""
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    for category, extensions in ALLOWED_EXTENSIONS.items():
        if ext in extensions:
            return category
    return "unknown"

def calculate_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating file hash: {e}")
        return None

def analyze_file(file_path):
    """Analyze a file using all available components"""
    try:
        filename = os.path.basename(file_path)
        file_category = get_file_category(filename)
        file_hash = calculate_hash(file_path)
        
        results = {
            "filename": filename,
            "file_path": file_path,
            "file_size": os.path.getsize(file_path),
            "file_hash": file_hash,
            "file_category": file_category,
            "is_malware": False,
            "confidence": 0,
            "malware_type": "Unknown",
            "risk_score": 0,
            "timestamp": datetime.now().isoformat(),
            "details": {}
        }
        
        # ML model analysis (for executables)
        if file_category == "executable" and 'ml_model' in COMPONENTS and COMPONENTS['ml_model']['status'] == 'available' and COMPONENTS['ml_model']['instance']:
            try:
                features = COMPONENTS['feature_extractor']['instance'](file_path)
                prediction = COMPONENTS['ml_model']['instance'].predict(features)[0]
                
                if prediction == 1:
                    results["is_malware"] = True
                    results["confidence"] = 0.85  # Default confidence for ML model
                
                # Try to get probability if model supports it
                if hasattr(COMPONENTS['ml_model']['instance'], 'predict_proba'):
                    proba = COMPONENTS['ml_model']['instance'].predict_proba(features)[0, 1]
                    results["confidence"] = proba
                
                results["details"]["ml_model"] = {
                    "prediction": int(prediction),
                    "probability": float(results["confidence"])
                }
                
                # Add feature importance if model explainer is available
                if 'model_explainer' in COMPONENTS and COMPONENTS['model_explainer']['status'] == 'available' and COMPONENTS['model_explainer']['instance']:
                    try:
                        explanation = COMPONENTS['model_explainer']['instance'].explain_prediction(file_path)
                        results["details"]["ml_model"]["explanation"] = explanation
                    except Exception as e:
                        logger.error(f"Error getting model explanation: {e}")
            except Exception as e:
                logger.error(f"Error in ML model analysis: {e}")
                results["details"]["ml_model"] = {"error": str(e)}
        
        # Malware type detection
        if 'malware_type_detector' in COMPONENTS and COMPONENTS['malware_type_detector']['status'] == 'available' and COMPONENTS['malware_type_detector']['instance']:
            try:
                type_result = COMPONENTS['malware_type_detector']['instance'].detect_malware_type(file_path)
                
                if type_result["confidence"] > 0.5:
                    results["is_malware"] = True
                    results["confidence"] = max(results["confidence"], type_result["confidence"])
                    results["malware_type"] = type_result["detected_type"]
                
                results["details"]["malware_type"] = type_result
            except Exception as e:
                logger.error(f"Error in malware type detection: {e}")
                results["details"]["malware_type"] = {"error": str(e)}
        
        # Document analysis (for documents)
        if file_category == "document" and 'document_analyzer' in COMPONENTS and COMPONENTS['document_analyzer']['status'] == 'available' and COMPONENTS['document_analyzer']['instance']:
            try:
                doc_result = COMPONENTS['document_analyzer']['instance'].analyze_document(file_path)
                
                # Update risk score
                doc_risk_score = doc_result.get("risk_score", {}).get("score", 0)
                results["risk_score"] = max(results["risk_score"], doc_risk_score)
                
                # If high risk or suspicious objects found, consider it potential malware
                if doc_risk_score > 70 or doc_result.get("has_suspicious_objects", False):
                    results["is_malware"] = True
                    results["confidence"] = max(results["confidence"], doc_risk_score / 100)
                
                results["details"]["document_analysis"] = doc_result
            except Exception as e:
                logger.error(f"Error in document analysis: {e}")
                results["details"]["document_analysis"] = {"error": str(e)}
        
        # Dynamic analysis (for executables)
        if file_category == "executable" and 'dynamic_analyzer' in COMPONENTS and COMPONENTS['dynamic_analyzer']['status'] == 'available' and COMPONENTS['dynamic_analyzer']['instance']:
            try:
                # Dynamic analysis can be resource-intensive, so we'll do it only for suspicious files
                # or if specifically requested
                if results["is_malware"] or results["risk_score"] > 50:
                    dyn_result = COMPONENTS['dynamic_analyzer']['instance'].analyze_file(file_path)
                    
                    # Update risk score and confidence
                    dyn_risk_score = dyn_result.get("risk_score", {}).get("score", 0)
                    results["risk_score"] = max(results["risk_score"], dyn_risk_score)
                    
                    if dyn_risk_score > 70:
                        results["is_malware"] = True
                        results["confidence"] = max(results["confidence"], dyn_risk_score / 100)
                    
                    # Update malware type if found
                    if 'malware_type_indicators' in dyn_result:
                        malware_type = dyn_result['malware_type_indicators'].get('likely_type', '')
                        if malware_type and malware_type != "Unknown" and results["malware_type"] == "Unknown":
                            results["malware_type"] = malware_type
                    
                    results["details"]["dynamic_analysis"] = dyn_result
            except Exception as e:
                logger.error(f"Error in dynamic analysis: {e}")
                results["details"]["dynamic_analysis"] = {"error": str(e)}
        
        # VirusTotal analysis (optional)
        if 'vt_scanner' in COMPONENTS and COMPONENTS['vt_scanner']['status'] == 'available' and COMPONENTS['vt_scanner']['instance']:
            try:
                vt_result = COMPONENTS['vt_scanner']['instance'].scan_file(file_path)
                
                if vt_result.get("positives", 0) > 3:  # Arbitrary threshold
                    results["is_malware"] = True
                    results["confidence"] = max(results["confidence"], vt_result.get("positives", 0) / vt_result.get("total", 100))
                    
                    # Get malware type from VT if not determined yet
                    if results["malware_type"] == "Unknown" and 'scans' in vt_result:
                        for engine, scan in vt_result['scans'].items():
                            if scan.get('detected', False):
                                result_text = scan.get('result', '').lower()
                                malware_types = ['trojan', 'backdoor', 'spyware', 'ransom', 'worm', 'virus']
                                for t in malware_types:
                                    if t in result_text:
                                        results["malware_type"] = t.capitalize()
                                        break
                                if results["malware_type"] != "Unknown":
                                    break
                
                results["details"]["virustotal"] = vt_result
            except Exception as e:
                logger.error(f"Error in VirusTotal analysis: {e}")
                results["details"]["virustotal"] = {"error": str(e)}
        
        # Final risk assessment if not determined by other methods
        if not results["is_malware"] and results["risk_score"] > 70:
            results["is_malware"] = True
            results["confidence"] = max(results["confidence"], results["risk_score"] / 100)
        
        # Save result to file
        result_path = os.path.join(RESULTS_FOLDER, f"{file_hash}.json")
        with open(result_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
        
    except Exception as e:
        logger.error(f"Error analyzing file {file_path}: {e}")
        return {
            "error": str(e),
            "filename": os.path.basename(file_path),
            "is_malware": False
        }

# Flask routes
@app.route('/')
def index():
    """Render the main page"""
    available_features = {k: (v['status'] == 'available') for k, v in COMPONENTS.items()}
    return render_template('index.html', features=available_features)

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze a single uploaded file"""
    if 'file' not in request.files:
        return render_template('index.html', error="No file provided")

        file = request.files['file']
    if file.filename == '':
        return render_template('index.html', error="No file selected")

    if file and allowed_file(file.filename):
        try:
            # Clean filename and save file
            filename = secure_filename(file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)
            
            # Analyze the file
            result = analyze_file(file_path)
            
            # Return results
            return render_template('result.html', result=result)
        except Exception as e:
            logger.error(f"Error processing file: {e}")
            return render_template('index.html', error=f"Error processing file: {str(e)}")
    else:
        return render_template('index.html', error="Unsupported file type")

@app.route('/batch', methods=['GET', 'POST'])
def batch_analysis():
    """Handle batch analysis requests"""
    if request.method == 'POST':
        if 'files[]' not in request.files:
            return render_template('batch.html', error="No files provided")
        
        files = request.files.getlist('files[]')
        
        if not files or files[0].filename == '':
            return render_template('batch.html', error="No files selected")
        
        # Get processing options from form
        memory_limit = request.form.get('memory_limit', type=int, default=500)  # Default 500MB
        large_file_threshold = request.form.get('large_file_threshold', type=int, default=50)  # Default 50MB
        
        # Save files temporarily
        saved_files = []
        batch_dir = os.path.join(BATCH_FOLDER, datetime.now().strftime('%Y%m%d_%H%M%S'))
        os.makedirs(batch_dir, exist_ok=True)
        
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(batch_dir, filename)
                file.save(file_path)
                saved_files.append(file_path)
        
        if saved_files:
            # Process in background if batch processor is available
            if 'batch_processor' in COMPONENTS and COMPONENTS['batch_processor']['status'] == 'available' and COMPONENTS['batch_processor']['instance']:
                process_thread = threading.Thread(
                    target=COMPONENTS['batch_processor']['instance'].process_files_optimized,
                    args=(saved_files, memory_limit, large_file_threshold)
                )
                process_thread.daemon = True
                process_thread.start()
                
                # Return confirmation page
                return render_template('batch_submitted.html', 
                                      count=len(saved_files),
                                      timestamp=os.path.basename(batch_dir))
            else:
                return render_template('batch.html', 
                                      error="Batch processing is not available")
        else:
            return render_template('batch.html', 
                                  error="No valid files were uploaded")
    
    # GET request - show the batch upload form
    return render_template('batch.html')

@app.route('/realtime', methods=['GET', 'POST'])
def realtime_monitoring():
    """Manage real-time monitoring"""
    global COMPONENTS['realtime_monitor']['instance']
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'start':
            if 'realtime_monitor' in COMPONENTS and COMPONENTS['realtime_monitor']['status'] == 'available' and COMPONENTS['realtime_monitor']['instance']:
                if COMPONENTS['realtime_monitor']['instance'].is_running is None or not COMPONENTS['realtime_monitor']['instance'].is_running:
                    # Get directories to monitor
                    directories = request.form.get('directories', '')
                    watch_dirs = [d.strip() for d in directories.split(',') if d.strip()]
                    
                    # Start monitoring
                    COMPONENTS['realtime_monitor']['instance'].start_monitoring(watch_directories=watch_dirs)
                    
                    return render_template('realtime.html', 
                                          status="running", 
                                          dirs=watch_dirs,
                                          monitor=COMPONENTS['realtime_monitor']['instance'])
                else:
                    return render_template('realtime.html', 
                                          status="already_running",
                                          monitor=COMPONENTS['realtime_monitor']['instance'],
                                          dirs=COMPONENTS['realtime_monitor']['instance'].watch_directories)
            else:
                return render_template('realtime.html', 
                                      error="Real-time monitoring is not available")
        
        elif action == 'stop':
            if COMPONENTS['realtime_monitor']['instance'] and COMPONENTS['realtime_monitor']['instance'].is_running:
                COMPONENTS['realtime_monitor']['instance'].stop_monitoring()
                return render_template('realtime.html', 
                                      status="stopped",
                                      dirs=[])
            else:
                return render_template('realtime.html', 
                                      status="not_running")
        
        elif action == 'status':
            if COMPONENTS['realtime_monitor']['instance']:
                status_report = COMPONENTS['realtime_monitor']['instance'].get_status_report()
                return render_template('realtime.html', 
                                      status="running" if COMPONENTS['realtime_monitor']['instance'].is_running else "stopped",
                                      report=status_report,
                                      dirs=COMPONENTS['realtime_monitor']['instance'].watch_directories,
                                      monitor=COMPONENTS['realtime_monitor']['instance'])
            else:
                return render_template('realtime.html', 
                                      status="not_initialized")
    
    # GET request - show the real-time monitoring page
    if COMPONENTS['realtime_monitor']['instance']:
        status = "running" if COMPONENTS['realtime_monitor']['instance'].is_running else "stopped"
        report = COMPONENTS['realtime_monitor']['instance'].get_status_report() if COMPONENTS['realtime_monitor']['instance'].is_running else None
        return render_template('realtime.html', 
                              status=status,
                              report=report,
                              dirs=COMPONENTS['realtime_monitor']['instance'].watch_directories if COMPONENTS['realtime_monitor']['instance'].is_running else [],
                              monitor=COMPONENTS['realtime_monitor']['instance'])
    else:
        return render_template('realtime.html', 
                              status="not_initialized")

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for file analysis"""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    if file and allowed_file(file.filename):
        try:
            # Clean filename and save file
            filename = secure_filename(file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

            # Analyze the file
            result = analyze_file(file_path)
            
            # Return JSON response
            return jsonify(result)
        except Exception as e:
            logger.error(f"API error: {e}")
            return jsonify({"error": str(e)}), 500
    else:
        return jsonify({"error": "Unsupported file type"}), 400

@app.route('/api/status', methods=['GET'])
def api_status():
    """API endpoint to get system status"""
    status = {
        "components": {k: (v['status'] == 'available') for k, v in COMPONENTS.items()},
        "realtime_monitoring": False
    }
    
    if COMPONENTS['realtime_monitor']['status'] == 'available' and COMPONENTS['realtime_monitor']['instance']:
        status["realtime_monitoring"] = COMPONENTS['realtime_monitor']['instance'].is_running
        
    return jsonify(status)

@app.route('/api/realtime/start', methods=['POST'])
def api_realtime_start():
    """API endpoint to start real-time monitoring"""
    global COMPONENTS['realtime_monitor']['instance']
    
    if 'realtime_monitor' not in COMPONENTS or COMPONENTS['realtime_monitor']['status'] != 'available' or not COMPONENTS['realtime_monitor']['instance']:
        return jsonify({"error": "Real-time monitoring is not available"}), 400
    
    if COMPONENTS['realtime_monitor']['instance'] and COMPONENTS['realtime_monitor']['instance'].is_running:
        return jsonify({"error": "Real-time monitoring is already running"}), 400
    
    try:
        # Get directories from JSON
        data = request.get_json() or {}
        watch_dirs = data.get('directories', [])
        
        # Start monitoring
        COMPONENTS['realtime_monitor']['instance'].start_monitoring(watch_directories=watch_dirs)
        
        return jsonify({"status": "success", "message": "Real-time monitoring started"})
    except Exception as e:
        logger.error(f"API error starting monitoring: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/realtime/stop', methods=['POST'])
def api_realtime_stop():
    """API endpoint to stop real-time monitoring"""
    global COMPONENTS['realtime_monitor']['instance']
    
    if not COMPONENTS['realtime_monitor']['instance'] or not COMPONENTS['realtime_monitor']['instance'].is_running:
        return jsonify({"error": "Real-time monitoring is not running"}), 400
    
    try:
        COMPONENTS['realtime_monitor']['instance'].stop_monitoring()
        return jsonify({"status": "success", "message": "Real-time monitoring stopped"})
    except Exception as e:
        logger.error(f"API error stopping monitoring: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/realtime/status', methods=['GET'])
def api_realtime_status():
    """API endpoint to get real-time monitoring status"""
    global COMPONENTS['realtime_monitor']['instance']
    
    if not COMPONENTS['realtime_monitor']['instance']:
        return jsonify({
            "running": False,
            "message": "Real-time monitoring not initialized"
        })
    
    try:
        status_report = COMPONENTS['realtime_monitor']['instance'].get_status_report()
        return jsonify({
            "running": COMPONENTS['realtime_monitor']['instance'].is_running,
            "report": status_report
        })
    except Exception as e:
        logger.error(f"API error getting monitoring status: {e}")
        return jsonify({"error": str(e)}), 500

# Error handlers
@app.errorhandler(413)
def request_entity_too_large(error):
    return render_template('error.html', error="File too large"), 413

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def server_error(error):
    return render_template('error.html', error="Server error"), 500

# Route to display component status
@app.route('/status')
def component_status():
    return render_template('status.html', components=COMPONENTS)

# Fallback method to extract features when feature extractor fails
def fallback_extract_features(file_path):
    """
    A simple fallback feature extractor when the main one fails
    """
    logger.warning(f"Using fallback feature extraction for {file_path}")
    import os
    import hashlib
    import magic
    import numpy as np
    
    features = {}
    
    # File metadata
    try:
        file_size = os.path.getsize(file_path)
        features['file_size'] = file_size
    except:
        features['file_size'] = 0
    
    # File type
    try:
        file_type = magic.from_file(file_path)
        features['is_executable'] = 1 if 'executable' in file_type.lower() else 0
        features['is_dll'] = 1 if '.dll' in file_path.lower() or 'dll' in file_type.lower() else 0
    except:
        features['is_executable'] = 1 if file_path.endswith('.exe') else 0
        features['is_dll'] = 1 if file_path.endswith('.dll') else 0
    
    # Entropy calculation
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        if data:
            entropy = 0
            for x in range(256):
                p_x = data.count(bytes([x])) / len(data)
                if p_x > 0:
                    entropy += -p_x * np.log2(p_x)
            features['entropy'] = entropy
        else:
            features['entropy'] = 0
    except:
        features['entropy'] = 0
    
    # File hash
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        md5 = hashlib.md5(data).hexdigest()
        features['md5_hash'] = int(md5[:8], 16) / (1 << 32)  # Normalize to [0, 1]
    except:
        features['md5_hash'] = 0
    
    # Convert to 2D array for sklearn compatibility
    return np.array([[
        features['file_size'], 
        features['is_executable'],
        features['is_dll'],
        features['entropy'],
        features['md5_hash']
    ]])

# Simplified fallback malware detector
def fallback_detect_malware(file_path):
    """
    A simple fallback method when ML model fails
    """
    logger.warning(f"Using fallback malware detection for {file_path}")
    import re
    import os
    
    # Read file content
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
    except:
        return True  # Consider suspicious if we can't read it
    
    # Suspicious patterns
    patterns = [
        rb'CreateRemoteThread',
        rb'VirtualAllocEx', 
        rb'WriteProcessMemory',
        rb'NtUnmapViewOfSection',
        rb'ShellExecute',
        rb'GetProcAddress',
        rb'LoadLibrary',
        rb'CreateProcess',
        rb'CreateFile',
        rb'WriteFile',
        rb'RegSetValue',
        rb'WinExec',
        rb'URLDownloadToFile',
        rb'GetTempPath',
        rb'SetWindowsHookEx',
        rb'WSASocket',
        rb'connect',
        rb'HTTP',
        rb'HTTPS',
        rb'WScript.Shell',
        rb'powershell',
        rb'cmd.exe',
        rb'rundll32',
        rb'encrypt',
        rb'ransom',
        rb'bitcoin',
        rb'password',
        rb'malware',
        rb'trojan',
        rb'virus',
        rb'threat',
        rb'exploit',
        rb'attack',
        rb'hack',
    ]
    
    # Check for suspicious patterns
    suspicious_matches = 0
    for pattern in patterns:
        if re.search(pattern, content, re.IGNORECASE):
            suspicious_matches += 1
    
    # File entropy
    entropy = 0
    if content:
        byte_counters = {}
        file_size = len(content)
        for byte in content:
            if byte not in byte_counters:
                byte_counters[byte] = 0
            byte_counters[byte] += 1
        
        import math
        for count in byte_counters.values():
            probability = count / file_size
            entropy -= probability * math.log2(probability)
    
    # File size (large files or very small files can be suspicious)
    file_size = os.path.getsize(file_path)
    
    # Decision factors
    high_entropy = entropy > 7.0  # Very high entropy often indicates encryption or packing
    strange_size = file_size < 1000 or file_size > 20000000  # Unusually small or large
    many_patterns = suspicious_matches > 5  # Multiple suspicious API calls
    
    # Final decision
    is_suspicious = high_entropy and (strange_size or many_patterns)
    
    logger.debug(f"Fallback detection: entropy={entropy}, patterns={suspicious_matches}, "
                f"size={file_size}, suspicious={is_suspicious}")
    
    return is_suspicious

# Add route for model explanation visualization
@app.route('/explain/<file_id>')
def explain_result(file_id):
    """
    Display model explanation for a specific result
    
    Args:
        file_id: ID of the analyzed file
    
    Returns:
        Rendered explanation template
    """
    try:
        # Get the analysis results for the file
        result_file = os.path.join(app.config['UPLOAD_FOLDER'], 'results', f"{file_id}.json")
        if not os.path.exists(result_file):
            flash('Analysis result not found', 'danger')
            return redirect(url_for('index'))
            
        with open(result_file, 'r') as f:
            result = json.load(f)
            
        # Get the feature vector from the result
        if 'features' not in result:
            flash('Feature data not available for explanation', 'warning')
            return redirect(url_for('result', file_id=file_id))
            
        feature_vector = result['features']
        feature_names = result.get('feature_names', [f"Feature_{i}" for i in range(len(feature_vector))])
        
        # Load the model explainer
        from model_explainer import ModelExplainer
        explainer = ModelExplainer(app.config['MODEL_PATH'])
        
        # Generate the explanation
        explanation = explainer.explain_prediction(feature_vector, feature_names)
        
        # Generate the visualization
        explanation_image = os.path.join(app.config['UPLOAD_FOLDER'], 'explanations', f"{file_id}.png")
        os.makedirs(os.path.dirname(explanation_image), exist_ok=True)
        explainer.generate_explanation_plot(explanation, explanation_image)
        
        # Prepare data for the template
        explanation_data = {
            'top_features': explanation['top_features'],
            'prediction': explanation['prediction'],
            'confidence': explanation['confidence'],
            'image_path': f"/uploads/explanations/{file_id}.png"
        }
        
        return render_template('explanation.html', 
                               file_id=file_id, 
                               result=result, 
                               explanation=explanation_data)
                               
    except Exception as e:
        logger.error(f"Error generating explanation: {e}")
        flash(f"Error generating explanation: {str(e)}", 'danger')
        return redirect(url_for('result', file_id=file_id))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run the Malware Detection System')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    parser.add_argument('--host', default='0.0.0.0', help='Host to run the server on')
    parser.add_argument('--port', type=int, default=5000, help='Port to run the server on')
    args = parser.parse_args()
    
    if args.debug:
        app.run(debug=True, host=args.host, port=args.port)
    else:
        # In production, use Waitress WSGI server
        from waitress import serve
        print(f"Starting production server on {args.host}:{args.port}")
        serve(app, host=args.host, port=args.port, threads=10)

