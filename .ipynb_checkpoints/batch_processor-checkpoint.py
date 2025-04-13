import os
import time
import json
import glob
import csv
import threading
import multiprocessing
import logging
import hashlib
import concurrent.futures
import importlib.util
from datetime import datetime
from queue import Queue
import traceback

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='batch_processor.log'
)
logger = logging.getLogger('BatchProcessor')

class BatchProcessor:
    """
    Processes multiple files for malware analysis in batch mode
    """
    def __init__(self, output_dir="batch_results", max_workers=None):
        """
        Initialize the batch processor
        
        Args:
            output_dir: Directory to store results
            max_workers: Maximum number of worker processes/threads
        """
        self.output_dir = output_dir
        self.max_workers = max_workers or max(1, multiprocessing.cpu_count() - 1)
        self.results = {}
        self.analyzers = {}
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize available analyzers
        self._init_analyzers()
    
    def _init_analyzers(self):
        """Initialize available analyzer modules"""
        try:
            # Check for ML model analyzer
            if importlib.util.find_spec("feature_extraction") is not None:
                import feature_extraction
                import joblib
                
                try:
                    # Try to load the model
                    model = joblib.load('ML_model/malwareclassifier-V2.pkl')
                    self.analyzers['ml_model'] = {
                        'model': model,
                        'extract_features': feature_extraction.extract_features
                    }
                    logger.info("Loaded ML model analyzer")
                except Exception as e:
                    logger.error(f"Error loading ML model: {e}")
        except Exception as e:
            logger.error(f"Error setting up ML analyzer: {e}")
        
        # Check for document analyzer
        try:
            if importlib.util.find_spec("document_analyzer") is not None:
                from document_analyzer import DocumentAnalyzer
                self.analyzers['document'] = DocumentAnalyzer()
                logger.info("Loaded document analyzer")
        except Exception as e:
            logger.error(f"Error setting up document analyzer: {e}")
        
        # Check for malware type detector
        try:
            if importlib.util.find_spec("malware_types") is not None:
                from malware_types import MalwareTypeDetector
                self.analyzers['malware_type'] = MalwareTypeDetector()
                logger.info("Loaded malware type detector")
        except Exception as e:
            logger.error(f"Error setting up malware type detector: {e}")
            
        # Check for dynamic analyzer
        try:
            if importlib.util.find_spec("dynamic_analysis") is not None:
                from dynamic_analysis import DynamicAnalyzer
                self.analyzers['dynamic'] = DynamicAnalyzer(timeout=30)
                logger.info("Loaded dynamic analyzer")
        except Exception as e:
            logger.error(f"Error setting up dynamic analyzer: {e}")
        
        # Check if VirusTotal API is available
        try:
            if importlib.util.find_spec("vt_api") is not None:
                from vt_api import VirusTotalScanner
                self.analyzers['virustotal'] = VirusTotalScanner()
                logger.info("Loaded VirusTotal scanner")
        except Exception as e:
            logger.error(f"Error setting up VirusTotal scanner: {e}")
    
    def process_directory(self, directory_path, recursive=True, file_pattern="*"):
        """
        Process all files in a directory
        
        Args:
            directory_path: Path to directory containing files to analyze
            recursive: Whether to search subdirectories recursively
            file_pattern: Glob pattern to match files (e.g., "*.exe")
            
        Returns:
            dict: Summary of processing results
        """
        if not os.path.exists(directory_path):
            logger.error(f"Directory not found: {directory_path}")
            return {"error": "Directory not found"}
        
        logger.info(f"Processing directory: {directory_path} (recursive={recursive})")
        
        # Get list of files
        pattern = os.path.join(directory_path, "**", file_pattern) if recursive else os.path.join(directory_path, file_pattern)
        files = glob.glob(pattern, recursive=recursive)
        
        return self.process_files(files)
    
    def process_files(self, file_list):
        """
        Process a list of files
        
        Args:
            file_list: List of file paths to analyze
            
        Returns:
            dict: Summary of processing results
        """
        if not file_list:
            logger.warning("No files to process")
            return {"error": "No files to process"}
        
        total_files = len(file_list)
        logger.info(f"Processing {total_files} files with {self.max_workers} workers")
        
        start_time = time.time()
        processed_count = 0
        malware_count = 0
        
        # Create a timestamp for this batch
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        batch_dir = os.path.join(self.output_dir, f"batch_{timestamp}")
        os.makedirs(batch_dir, exist_ok=True)
        
        # Initialize CSV result file
        csv_file = os.path.join(batch_dir, "results.csv")
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'File', 'Hash', 'Is Malware', 'Confidence', 'Malware Type',
                'Risk Score', 'Analysis Method', 'Processing Time'
            ])
        
        # Process files in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(self._process_single_file, file_path, batch_dir): file_path
                for file_path in file_list
            }
            
            # Process as they complete
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    
                    # Update counters
                    processed_count += 1
                    if result.get('is_malware', False):
                        malware_count += 1
                    
                    # Add to CSV
                    self._add_to_csv(csv_file, file_path, result)
                    
                    # Log progress
                    if processed_count % 10 == 0 or processed_count == total_files:
                        logger.info(f"Progress: {processed_count}/{total_files} files processed")
                        
                except Exception as e:
                    logger.error(f"Error processing {file_path}: {e}")
                    traceback.print_exc()
        
        # Generate summary
        end_time = time.time()
        processing_time = end_time - start_time
        
        summary = {
            "total_files": total_files,
            "processed_files": processed_count,
            "malware_detected": malware_count,
            "clean_files": processed_count - malware_count,
            "processing_time_seconds": processing_time,
            "average_time_per_file": processing_time / total_files if total_files > 0 else 0,
            "results_directory": batch_dir,
            "csv_report": csv_file
        }
        
        # Write summary to JSON
        summary_file = os.path.join(batch_dir, "summary.json")
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"Batch processing complete. Results saved to {batch_dir}")
        return summary
    
    def _process_single_file(self, file_path, batch_dir):
        """Process a single file with all available analyzers"""
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            return {"error": "File not found or is a directory"}
        
        file_name = os.path.basename(file_path)
        logger.info(f"Processing file: {file_name}")
        
        start_time = time.time()
        
        # Calculate file hash
        file_hash = self._calculate_hash(file_path)
        
        # Get file extension
        file_extension = os.path.splitext(file_path)[1].lower()
        
        # Determine which analyzers to use based on file type
        analysis_results = {}
        is_malware = False
        confidence = 0
        malware_type = "Unknown"
        risk_score = 0
        analysis_method = []
        
        # ML model analysis (for exe/dll files)
        if 'ml_model' in self.analyzers and file_extension in ['.exe', '.dll']:
            try:
                features = self.analyzers['ml_model']['extract_features'](file_path)
                prediction = self.analyzers['ml_model']['model'].predict(features)
                
                if prediction[0] == 1:
                    is_malware = True
                    confidence = max(confidence, 0.8)  # Arbitrary confidence value
                
                analysis_results['ml_model'] = {
                    'is_malware': prediction[0] == 1
                }
                analysis_method.append('ML')
            except Exception as e:
                logger.error(f"Error in ML analysis of {file_name}: {e}")
                analysis_results['ml_model'] = {'error': str(e)}
        
        # Document analysis
        if 'document' in self.analyzers:
            try:
                doc_result = self.analyzers['document'].analyze_document(file_path)
                
                # If risk score is high or has suspicious objects, consider it malware
                doc_risk_score = doc_result.get('risk_score', {}).get('score', 0)
                if doc_risk_score > 70 or doc_result.get('has_suspicious_objects', False):
                    is_malware = True
                    confidence = max(confidence, doc_risk_score / 100)
                    risk_score = max(risk_score, doc_risk_score)
                
                analysis_results['document'] = doc_result
                analysis_method.append('Document')
            except Exception as e:
                logger.error(f"Error in document analysis of {file_name}: {e}")
                analysis_results['document'] = {'error': str(e)}
        
        # Malware type detection
        if 'malware_type' in self.analyzers:
            try:
                type_result = self.analyzers['malware_type'].detect_malware_type(file_path)
                
                if type_result.get('confidence', 0) > 0.5:
                    is_malware = True
                    confidence = max(confidence, type_result.get('confidence', 0))
                    malware_type = type_result.get('detected_type', 'Unknown')
                
                analysis_results['malware_type'] = type_result
                analysis_method.append('Type')
            except Exception as e:
                logger.error(f"Error in malware type detection of {file_name}: {e}")
                analysis_results['malware_type'] = {'error': str(e)}
        
        # Dynamic analysis (for executable files)
        if 'dynamic' in self.analyzers and file_extension in ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.js']:
            try:
                dyn_result = self.analyzers['dynamic'].analyze_file(file_path)
                
                # Check risk score
                dyn_risk_score = dyn_result.get('risk_score', {}).get('score', 0)
                if dyn_risk_score > 70:
                    is_malware = True
                    confidence = max(confidence, dyn_risk_score / 100)
                    risk_score = max(risk_score, dyn_risk_score)
                    
                    # Get malware type if available
                    if 'malware_type_indicators' in dyn_result:
                        detected_type = dyn_result['malware_type_indicators'].get('likely_type', '')
                        if detected_type and detected_type != 'Unknown':
                            malware_type = detected_type
                
                analysis_results['dynamic'] = dyn_result
                analysis_method.append('Dynamic')
            except Exception as e:
                logger.error(f"Error in dynamic analysis of {file_name}: {e}")
                analysis_results['dynamic'] = {'error': str(e)}
        
        # VirusTotal analysis
        if 'virustotal' in self.analyzers:
            try:
                vt_result = self.analyzers['virustotal'].scan_file(file_path)
                
                # Check if detected by multiple engines
                if vt_result.get('positives', 0) > 3:  # Arbitrary threshold
                    is_malware = True
                    confidence = max(confidence, vt_result.get('positives', 0) / vt_result.get('total', 100))
                    
                    # Get malware type from VirusTotal if available
                    if 'scans' in vt_result:
                        for engine, scan in vt_result['scans'].items():
                            if scan.get('detected', False):
                                # Extract malware type from result
                                result = scan.get('result', '').lower()
                                if any(t in result for t in ['trojan', 'backdoor', 'spyware', 'ransom', 'worm', 'virus']):
                                    for t in ['trojan', 'backdoor', 'spyware', 'ransom', 'worm', 'virus']:
                                        if t in result:
                                            malware_type = t.capitalize()
                                            break
                                    break
                
                analysis_results['virustotal'] = vt_result
                analysis_method.append('VirusTotal')
            except Exception as e:
                logger.error(f"Error in VirusTotal analysis of {file_name}: {e}")
                analysis_results['virustotal'] = {'error': str(e)}
        
        # Calculate processing time
        processing_time = time.time() - start_time
        
        # Prepare result
        result = {
            'file_path': file_path,
            'file_name': file_name,
            'file_hash': file_hash,
            'is_malware': is_malware,
            'confidence': confidence,
            'malware_type': malware_type,
            'risk_score': risk_score,
            'analysis_method': ','.join(analysis_method),
            'processing_time': processing_time,
            'detailed_results': analysis_results
        }
        
        # Save to JSON file
        result_file = os.path.join(batch_dir, f"{file_hash}.json")
        with open(result_file, 'w') as f:
            json.dump(result, f, indent=2)
        
        return result
    
    def _add_to_csv(self, csv_file, file_path, result):
        """Add a result to the CSV file"""
        try:
            with open(csv_file, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    file_path,
                    result.get('file_hash', ''),
                    result.get('is_malware', False),
                    f"{result.get('confidence', 0):.2f}",
                    result.get('malware_type', 'Unknown'),
                    result.get('risk_score', 0),
                    result.get('analysis_method', ''),
                    f"{result.get('processing_time', 0):.2f}s"
                ])
        except Exception as e:
            logger.error(f"Error writing to CSV file: {e}")
    
    def _calculate_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256.update(byte_block)
                
        return sha256.hexdigest()
    
    def process_files_in_chunks(self, file_paths, chunk_size=10):
        """
        Process large batches of files in smaller chunks to manage memory usage
        
        Args:
            file_paths: List of file paths to process
            chunk_size: Number of files to process in each chunk
            
        Returns:
            list: Results for all processed files
        """
        logger.info(f"Processing {len(file_paths)} files in chunks of {chunk_size}")
        
        # Split files into chunks
        file_chunks = [file_paths[i:i + chunk_size] for i in range(0, len(file_paths), chunk_size)]
        
        all_results = []
        chunk_count = len(file_chunks)
        
        for i, chunk in enumerate(file_chunks):
            logger.info(f"Processing chunk {i+1}/{chunk_count} ({len(chunk)} files)")
            
            # Process chunk
            chunk_results = self.process_files(chunk)
            all_results.extend(chunk_results)
            
            # Force garbage collection after each chunk
            try:
                import gc
                gc.collect()
            except:
                pass
            
            # Short delay between chunks to allow system to free resources
            time.sleep(0.5)
        
        return all_results
    
    def process_files_with_memory_limit(self, file_paths, memory_limit_mb=500):
        """
        Process files with a memory usage limit
        
        Args:
            file_paths: List of file paths to process
            memory_limit_mb: Maximum memory usage in MB
            
        Returns:
            list: Results for all processed files
        """
        logger.info(f"Processing files with memory limit of {memory_limit_mb}MB")
        
        # Check if psutil is available for memory monitoring
        try:
            import psutil
            has_psutil = True
        except ImportError:
            has_psutil = False
            logger.warning("psutil not available, memory limit will not be enforced")
        
        all_results = []
        pending_files = list(file_paths)
        processed_count = 0
        
        # Start with a reasonable chunk size
        current_chunk_size = min(10, len(pending_files))
        
        while pending_files:
            # Take next chunk
            current_chunk = pending_files[:current_chunk_size]
            del pending_files[:current_chunk_size]
            
            # Process chunk
            logger.info(f"Processing chunk of {len(current_chunk)} files " +
                        f"({processed_count}/{len(file_paths)} completed)")
            chunk_results = self.process_files(current_chunk)
            all_results.extend(chunk_results)
            processed_count += len(current_chunk)
            
            # Check memory usage and adjust chunk size if needed
            if has_psutil:
                process = psutil.Process()
                memory_usage_mb = process.memory_info().rss / (1024 * 1024)
                logger.debug(f"Current memory usage: {memory_usage_mb:.2f}MB")
                
                # Adjust chunk size based on memory usage
                if memory_usage_mb > memory_limit_mb * 0.8:
                    # Too close to limit, reduce chunk size
                    current_chunk_size = max(1, current_chunk_size // 2)
                    logger.warning(f"Memory usage high ({memory_usage_mb:.2f}MB), " +
                                  f"reducing chunk size to {current_chunk_size}")
                    
                    # Force garbage collection
                    try:
                        import gc
                        gc.collect()
                    except:
                        pass
                    
                    # Wait for memory to be freed
                    time.sleep(1.0)
                elif memory_usage_mb < memory_limit_mb * 0.5 and current_chunk_size < 50:
                    # Well below limit, can increase chunk size
                    current_chunk_size = min(len(pending_files), current_chunk_size * 2)
                    logger.info(f"Memory usage acceptable ({memory_usage_mb:.2f}MB), " +
                               f"increasing chunk size to {current_chunk_size}")
        
        return all_results
    
    def _prefilter_large_files(self, file_paths, size_threshold_mb=50):
        """
        Prefilter very large files for specialized processing
        
        Args:
            file_paths: List of file paths to process
            size_threshold_mb: Size threshold in MB
            
        Returns:
            tuple: (regular_files, large_files)
        """
        regular_files = []
        large_files = []
        
        for file_path in file_paths:
            try:
                file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
                if file_size_mb > size_threshold_mb:
                    large_files.append(file_path)
                else:
                    regular_files.append(file_path)
            except Exception as e:
                logger.error(f"Error checking file size for {file_path}: {e}")
                # If we can't determine size, treat as regular file
                regular_files.append(file_path)
        
        return regular_files, large_files
    
    def _process_large_file(self, file_path, sample_size_mb=5):
        """
        Process a very large file by analyzing samples
        
        Args:
            file_path: Path to the large file
            sample_size_mb: Size of each sample in MB
            
        Returns:
            dict: Analysis result
        """
        logger.info(f"Processing large file {file_path} using sampling")
        
        try:
            file_size = os.path.getsize(file_path)
            file_size_mb = file_size / (1024 * 1024)
            
            # Calculate sample positions
            sample_size = sample_size_mb * 1024 * 1024
            sample_count = min(5, max(3, int(file_size_mb // 10)))  # At least 3, at most 5 samples
            
            # Always include start and end, plus some samples in between
            sample_positions = [0]  # Start
            
            if sample_count > 2:
                # Add middle samples
                for i in range(1, sample_count - 1):
                    pos = int((i / (sample_count - 1)) * (file_size - sample_size))
                    sample_positions.append(pos)
            
            # Add end sample
            sample_positions.append(max(0, file_size - sample_size))
            
            # Create temporary sample files
            sample_files = []
            try:
                with open(file_path, 'rb') as f:
                    for i, pos in enumerate(sample_positions):
                        sample_path = os.path.join(self.temp_dir, f"sample_{i}_{os.path.basename(file_path)}")
                        f.seek(pos)
                        sample_data = f.read(sample_size)
                        
                        with open(sample_path, 'wb') as sf:
                            sf.write(sample_data)
                        
                        sample_files.append(sample_path)
                
                # Analyze each sample
                sample_results = []
                for sample_path in sample_files:
                    result = self._analyze_file(sample_path)
                    sample_results.append(result)
                
                # Combine results
                combined_result = self._combine_sample_results(file_path, sample_results)
                return combined_result
                
            finally:
                # Clean up sample files
                for sample_path in sample_files:
                    try:
                        if os.path.exists(sample_path):
                            os.remove(sample_path)
                    except:
                        pass
                        
        except Exception as e:
            logger.error(f"Error processing large file {file_path}: {e}")
            # Fallback: analyze file without sampling
            return self._analyze_file(file_path)
    
    def _combine_sample_results(self, file_path, sample_results):
        """
        Combine results from multiple file samples
        
        Args:
            file_path: Original file path
            sample_results: List of results from analyzing samples
            
        Returns:
            dict: Combined result
        """
        # If any sample is detected as malware, consider the whole file malicious
        is_malware = any(result.get('is_malware', False) for result in sample_results if result)
        
        # Calculate average risk score
        risk_scores = [result.get('risk_score', 0) for result in sample_results if result]
        avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        # Get highest confidence value
        confidence_values = [result.get('confidence', 0) for result in sample_results if result]
        max_confidence = max(confidence_values) if confidence_values else 0
        
        # Combine malware types
        malware_types = set()
        for result in sample_results:
            if result and 'malware_type' in result and result['malware_type']:
                malware_types.add(result['malware_type'])
        
        # Combine details from all samples
        combined_details = {}
        for result in sample_results:
            if result and 'details' in result:
                for key, value in result['details'].items():
                    if key not in combined_details:
                        combined_details[key] = value
                    elif isinstance(value, dict) and isinstance(combined_details[key], dict):
                        combined_details[key].update(value)
        
        # Create combined result
        return {
            'filename': os.path.basename(file_path),
            'file_path': file_path,
            'file_size': os.path.getsize(file_path),
            'is_malware': is_malware,
            'risk_score': max(avg_risk_score, 100 if is_malware else 0),
            'confidence': max_confidence,
            'malware_type': ', '.join(malware_types) if malware_types else 'Unknown',
            'details': combined_details,
            'sampled_analysis': True,
            'sample_count': len(sample_results),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def process_files_optimized(self, file_paths, memory_limit_mb=None, large_file_threshold_mb=50):
        """
        Process files with optimizations for large batches and files
        
        Args:
            file_paths: List of file paths to process
            memory_limit_mb: Memory limit in MB (if None, no limit)
            large_file_threshold_mb: Size threshold for large file handling
            
        Returns:
            list: Results for all processed files
        """
        logger.info(f"Processing {len(file_paths)} files with optimizations")
        
        # Pre-filter large files
        regular_files, large_files = self._prefilter_large_files(file_paths, large_file_threshold_mb)
        
        logger.info(f"Split into {len(regular_files)} regular files and {len(large_files)} large files")
        
        # Process regular files with memory management if needed
        regular_results = []
        if regular_files:
            if memory_limit_mb:
                regular_results = self.process_files_with_memory_limit(regular_files, memory_limit_mb)
            else:
                # If more than 100 files, use chunking to avoid memory issues
                if len(regular_files) > 100:
                    regular_results = self.process_files_in_chunks(regular_files)
                else:
                    regular_results = self.process_files(regular_files)
        
        # Process large files separately
        large_results = []
        for file_path in large_files:
            try:
                result = self._process_large_file(file_path)
                large_results.append(result)
            except Exception as e:
                logger.error(f"Error processing large file {file_path}: {e}")
                # Add minimal error result
                large_results.append({
                    'filename': os.path.basename(file_path),
                    'file_path': file_path,
                    'error': str(e),
                    'is_malware': False,
                    'risk_score': 0,
                    'confidence': 0,
                    'details': {'error': str(e)},
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
        
        # Combine results
        all_results = regular_results + large_results
        
        return all_results


# Example usage
if __name__ == "__main__":
    processor = BatchProcessor()
    
    # Example directory path - should be replaced with actual directory to analyze
    test_dir = "path/to/test/directory"
    
    if os.path.exists(test_dir):
        summary = processor.process_directory(test_dir, recursive=True)
        print(json.dumps(summary, indent=2))
    else:
        print(f"Test directory not found: {test_dir}") 