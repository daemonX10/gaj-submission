#!/usr/bin/env python3
"""
Script to run batch testing of malware detection on multiple files
"""

import os
import json
import argparse
import random
import warnings
import sys
import glob
import time
from batch_processor import BatchProcessor

# Suppress scikit-learn warnings about model versions
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

# Initialize JSONEncoder to handle non-serializable objects
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        # Convert non-serializable objects to serializable ones
        if isinstance(obj, (bool, int, float, str, list, dict, tuple, type(None))):
            return obj
        return str(obj)  # Convert anything else to string

# Monkey patch json.JSONEncoder.default
json.JSONEncoder.default = CustomJSONEncoder().default

def get_files_from_directory(directory, file_pattern="*.exe", recursive=True):
    """Get list of files from directory matching the pattern"""
    pattern = os.path.join(directory, "**", file_pattern) if recursive else os.path.join(directory, file_pattern)
    return glob.glob(pattern, recursive=recursive)

def print_colored(text, color=None, bold=False):
    """Print colored text if supported by the terminal"""
    colors = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'purple': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'reset': '\033[0m'
    }
    
    bold_code = '\033[1m' if bold else ''
    
    if sys.platform.startswith('win'):
        # Check if Windows console supports ANSI codes
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            has_color = True
        except:
            has_color = False
    else:
        has_color = True
    
    if color and has_color and color in colors:
        print(f"{bold_code}{colors[color]}{text}{colors['reset']}")
    else:
        print(text)

def print_summary(result):
    """Print formatted summary of batch processing results"""
    print("\n" + "="*60)
    print_colored("BATCH PROCESSING SUMMARY", "cyan", True)
    print("="*60)
    
    print(f"\nProcessed Files: {result.get('processed_files', 0)}")
    
    malware_count = result.get('malware_detected', 0)
    clean_count = result.get('clean_files', 0)
    
    if malware_count > 0:
        print_colored(f"Malware Detected: {malware_count}", "red", malware_count > 0)
    else:
        print(f"Malware Detected: {malware_count}")
        
    print(f"Clean Files: {clean_count}")
    print(f"Processing Time: {result.get('processing_time_seconds', 0):.2f}s")
    
    print("\nOutput:")
    print(f"  Results Directory: {result.get('results_directory', '')}")
    print(f"  CSV Report: {result.get('csv_report', '')}")
    print("="*60)

def print_progress_bar(current, total, width=50):
    """Print a progress bar to the console"""
    progress = current / total
    bar_length = int(width * progress)
    bar = '█' * bar_length + '░' * (width - bar_length)
    
    # Clear current line and print progress
    sys.stdout.write('\r')
    sys.stdout.write(f"Progress: [{bar}] {current}/{total} ({progress:.1%})")
    sys.stdout.flush()
    
    # Add newline if we're done
    if current == total:
        print()

def interactive_mode():
    """Run in interactive mode, prompting user for options"""
    print_colored("\n===== MALWARE DETECTION SYSTEM =====", "cyan", True)
    print("Welcome to the malware detection system. This tool will help you analyze files for potential malware.")
    
    # Ask for target file or directory
    while True:
        target = input("\nEnter the path to file or directory to scan: ").strip()
        if os.path.exists(target):
            break
        print_colored("Error: File or directory not found. Please try again.", "red")
    
    # Determine if it's a file or directory
    if os.path.isfile(target):
        files_to_process = [target]
        print_colored(f"Target is a single file: {target}", "blue")
    else:
        # Use "*" as default file pattern without asking
        file_pattern = "*"
        
        # Get files
        files_to_process = get_files_from_directory(target, file_pattern, recursive=True)
        print_colored(f"Found {len(files_to_process)} files matching '{file_pattern}' in {target}", "blue")
        
        if not files_to_process:
            print_colored("No files found matching the pattern.", "yellow")
            return
    
    # Always use 100% of files (skip asking for sample percentage)
    
    # Ask for analysis mode
    print("\nSelect analysis mode:")
    print("  1. Static analysis only (ML model)")
    print("  2. Dynamic analysis only (Runtime behavior)")
    print("  3. Hybrid analysis")
    
    while True:
        mode = input("Select mode [3]: ").strip() or "3"
        if mode in ["1", "2", "3"]:
            break
        print_colored("Invalid selection. Please enter 1, 2, or 3.", "red")
    
    # Hardcoded VirusTotal API key for hybrid mode
    vt_api_key = "9945c44ec7c6e131d6e6c49bf6185bd7d51b82a8a56204a7711c5199eed27675"
    if mode == "3":  # Hybrid mode
        os.environ['VT_API_KEY'] = vt_api_key
        print_colored("VirusTotal API key configured", "green")
    
    # Ask for output directory
    print("\nEnter output directory for results:")
    output_dir = input("Output directory [batch_results]: ").strip() or "batch_results"
    
    # Ask for custom model path
    model_path = None
    if mode == "1" or mode == "3":  # Static or Hybrid
        print("\nYou can use a custom ML model for analysis.")
        model_input = input("Enter path to custom model (or leave blank for default): ").strip()
        if model_input and os.path.exists(model_input):
            model_path = model_input
            print_colored(f"Using custom ML model: {model_path}", "purple")
    
    # Configure processor
    processor = BatchProcessor(output_dir=output_dir, model_path=model_path)
    
    # Set mode
    if mode == "1":
        processor.static_only = True
        print_colored("Using static analysis only (ML model)", "yellow")
    elif mode == "2":
        processor.dynamic_only = True
        print_colored("Using dynamic analysis only (runtime behavior)", "yellow")
    else:  # mode == "3"
        print_colored("Using hybrid analysis mode", "yellow")
    
    # Show confirmation
    print("\n" + "="*60)
    print_colored("ANALYSIS CONFIGURATION:", "cyan", True)
    print("="*60)
    print(f"Mode: {'Static only' if mode=='1' else 'Dynamic only' if mode=='2' else 'Hybrid'}")
    print(f"Files to analyze: {len(files_to_process)}")
    print(f"Output directory: {output_dir}")
    if model_path:
        print(f"Custom model: {model_path}")
    print("="*60)
    
    confirm = input("\nStart analysis? [Y/n]: ").strip().lower() or "y"
    if confirm != "y":
        print_colored("Analysis cancelled.", "yellow")
        return
    
    # Process files
    print_colored("\nStarting analysis...", "green")
    
    # Initialize counters and tracking variables
    total_files = len(files_to_process)
    processed_count = 0
    malware_detected = 0
    start_time = time.time()
    
    # Create a custom process_files function with progress tracking
    def process_with_progress(processor, file_list, batch_dir):
        nonlocal processed_count, malware_detected
        results = []
        
        # Process each file and show progress
        for file_path in file_list:
            # Process the file
            result = processor._process_single_file(file_path, batch_dir)
            
            # Update counters
            processed_count += 1
            if result.get('is_malware', False):
                malware_detected += 1
                file_status = "MALWARE DETECTED"
                status_color = "red"
            else:
                file_status = "Clean"
                status_color = "green"
            
            # Show progress
            print_progress_bar(processed_count, total_files)
            print(f" | {processed_count}/{total_files} | ", end="")
            print_colored(f"{os.path.basename(file_path)}: {file_status}", status_color)
            
            # Add to results
            results.append(result)
            
        return results
    
    # Create timestamp for batch directory
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    batch_dir = os.path.join(output_dir, f"batch_{timestamp}")
    os.makedirs(batch_dir, exist_ok=True)
    
    # Process files with our custom progress tracking
    try:
        # Process files and collect results
        results = process_with_progress(processor, files_to_process, batch_dir)
        
        # Create summary data
        end_time = time.time()
        processing_time = end_time - start_time
        
        summary = {
            "total_files": total_files,
            "processed_files": processed_count,
            "malware_detected": malware_detected,
            "clean_files": processed_count - malware_detected,
            "processing_time_seconds": processing_time,
            "average_time_per_file": processing_time / total_files if total_files > 0 else 0,
            "results_directory": batch_dir,
            "csv_report": os.path.join(batch_dir, "results.csv")
        }
        
        # Save CSV report
        with open(summary["csv_report"], 'w', newline='') as f:
            import csv
            writer = csv.writer(f)
            writer.writerow([
                'File', 'Hash', 'Is Malware', 'Confidence', 'Malware Type',
                'Risk Score', 'Analysis Method', 'Processing Time'
            ])
            
            # Add each result to CSV
            for result in results:
                file_path = result.get('file_path', '')
                processor._add_to_csv(summary["csv_report"], file_path, result)
        
        # Save summary to JSON
        summary_file = os.path.join(batch_dir, "summary.json")
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Print summary
        print_summary(summary)
        
    except KeyboardInterrupt:
        print_colored("\nAnalysis interrupted by user.", "yellow")
    except Exception as e:
        print_colored(f"\nError during analysis: {str(e)}", "red")
        
    print_colored("\nAnalysis complete!", "green", True)

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Run batch testing of malware detection on multiple files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run in interactive mode
  run_batch_test.py --interactive
  
  # Test a single file with default model
  run_batch_test.py malware_sample.exe
  
  # Test 10% of files in a directory
  run_batch_test.py test_samples/ --sample 10
  
  # Use a custom ML model and only static analysis
  run_batch_test.py test_samples/ --model-path my_model.pkl --static-only
  
  # Use VirusTotal scanning (hybrid mode)
  run_batch_test.py test_samples/ --hybrid --vt-api-key YOUR_API_KEY
        """
    )
    parser.add_argument("--interactive", "-i", action="store_true",
                      help="Run in interactive mode (ignore other arguments)")
    parser.add_argument("target", nargs="?", help="File, directory, or dataset to process")
    parser.add_argument("--output-dir", "-o", default="batch_results", 
                        help="Directory to store results")
    parser.add_argument("--sample", "-s", type=float, default=100.0, 
                        help="Percentage of dataset to use (1-100, default: 100)")
    parser.add_argument("--pattern", "-p", default="*.exe", 
                        help="File pattern to match (default: *.exe)")
    parser.add_argument("--recursive", "-r", action="store_true", default=True, 
                        help="Process directories recursively")
    parser.add_argument("--workers", "-w", type=int, default=None, 
                        help="Number of worker processes (default: CPU count - 1)")
    parser.add_argument("--model-path", "-m", default=None,
                        help="Path to the ML model to use for testing")
    parser.add_argument("--quiet", "-q", action="store_true", 
                        help="Suppress detailed output and warnings")
    parser.add_argument("--vt-api-key", default=None,
                        help="VirusTotal API key for online scanning (required for VirusTotal analysis)")
    parser.add_argument("--static-only", action="store_true", default=False,
                        help="Use only static analysis (ML model) for testing")
    parser.add_argument("--dynamic-only", action="store_true", default=False,
                        help="Use only dynamic analysis (runtime behavior) for testing")
    parser.add_argument("--hybrid", action="store_true", default=False, 
                        help="Use hybrid analysis (combination of static, dynamic, and VirusTotal)")
    args = parser.parse_args()

    # Run in interactive mode if requested
    if args.interactive:
        interactive_mode()
        return
    
    # In non-interactive mode, a target is required
    if not args.target:
        parser.error("target is required unless --interactive mode is used")

    # Validate sample percentage
    if args.sample <= 0 or args.sample > 100:
        parser.error("Sample percentage must be between 0 and 100")

    # Validate command-line options
    if sum([args.static_only, args.dynamic_only, args.hybrid]) > 1:
        parser.error("Cannot use more than one of: --static-only, --dynamic-only, --hybrid")

    # Set VirusTotal API key in environment if provided
    if args.vt_api_key:
        os.environ['VT_API_KEY'] = args.vt_api_key
        if not args.quiet:
            print_colored("VirusTotal API key configured", "green")
    
    # Suppress stdout if quiet mode
    if args.quiet:
        old_stdout = sys.stdout
        sys.stdout = open(os.devnull, 'w')

    try:
        # Initialize the batch processor
        processor = BatchProcessor(output_dir=args.output_dir, max_workers=args.workers, 
                                  model_path=args.model_path)

        # Set analysis mode
        if args.static_only:
            if not args.quiet:
                print_colored("Using static analysis only (ML model)", "yellow")
            processor.static_only = True
            
        if args.dynamic_only:
            if not args.quiet:
                print_colored("Using dynamic analysis only (runtime behavior)", "yellow")
            processor.dynamic_only = True
            
        if args.hybrid:
            if not args.quiet:
                print_colored("Using hybrid analysis mode", "yellow")
            # Hybrid mode uses all available analyzers

        # Determine what to process
        if os.path.isfile(args.target):
            # Process single file
            files_to_process = [args.target]
            if not args.quiet:
                print_colored(f"Processing single file: {args.target}", "blue")
        elif os.path.isdir(args.target):
            # Process directory
            files_to_process = get_files_from_directory(args.target, args.pattern, args.recursive)
            if not args.quiet:
                print_colored(f"Found {len(files_to_process)} files matching '{args.pattern}' in {args.target}", "blue")
        else:
            print_colored(f"Error: Target '{args.target}' not found", "red")
            return

        # Take a sample if requested
        if args.sample < 100 and len(files_to_process) > 1:
            sample_size = max(1, int(len(files_to_process) * args.sample / 100))
            files_to_process = random.sample(files_to_process, sample_size)
            if not args.quiet:
                print_colored(f"Using {args.sample}% sample: {len(files_to_process)} files", "yellow")

        # Print model info
        if args.model_path and not args.quiet:
            print_colored(f"Using custom ML model: {args.model_path}", "purple")
        
        # Process files
        if files_to_process:
            if not args.quiet:
                print_colored("\nStarting analysis...", "green")
            
            result = processor.process_files(files_to_process)
            
            # Restore stdout before printing summary
            if args.quiet:
                sys.stdout = old_stdout
            
            # Print summary
            print_summary(result)
        else:
            print_colored("No files to process", "yellow")
    
    finally:
        # Ensure stdout is restored
        if args.quiet:
            sys.stdout = old_stdout

if __name__ == "__main__":
    main()