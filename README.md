# Malware Detection and Analysis Platform

A comprehensive platform for detecting, analyzing, and classifying malware using machine learning and dynamic analysis techniques.

## Features

- **Machine Learning-Based Detection**: Uses advanced ML algorithms to detect malicious files
- **Static Analysis**: Examines file properties and structures without execution
- **Dynamic Analysis**: Analyzes behavior of suspicious files in a controlled environment
- **Multi-File Type Support**: Analysis of executables, documents, scripts, and archives
- **Malware Classification**: Identifies specific malware types (ransomware, trojans, worms, etc.)
- **Document Analysis**: Specialized analysis of potentially malicious documents
- **Batch Processing**: Analyze multiple files at once
- **Real-time Monitoring**: Continuously monitor specified directories for new files
- **VirusTotal Integration**: Compare results with VirusTotal database
- **Model Explanation**: Understand why a file was classified as malicious
- **Web Interface**: User-friendly web application to interact with the system


For processing:
```
python run_batch_test.py --interactive
```

## Project Structure

- `app.py` - Main web application
- `feature_extraction.py` - Extracts features from PE files
- `malware_types.py` - Classifies malware types
- `predict_file.py` - CLI tool for single file analysis
- `document_analyzer.py` - Analyzes document files
- `dynamic_analysis.py` - Performs dynamic behavioral analysis
- `batch_processor.py` - Processes multiple files
- `realtime_monitor.py` - Monitors directories for new files
- `vt_api.py` - VirusTotal API integration
- `model_explainer.py` - Explains ML model decisions
- `ML_model/` - Contains trained ML models
- `templates/` - HTML templates for web interface
- `test_samples/` - Sample files for testing
- `batch_results/` - Output from batch processing


