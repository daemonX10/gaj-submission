# Modify your analyze_document.py file with this updated code:

#!/usr/bin/env python3
"""
Script to analyze documents for malicious content
"""

import os
import sys
import argparse
from document_analyzer import DocumentAnalyzer

def analyze_document(file_path):
    """Analyze a document file for malicious content"""
    print(f"Analyzing document: {os.path.basename(file_path)}")
    
    # Create document analyzer instance
    analyzer = DocumentAnalyzer()
    
    # Analyze the document
    try:
        result = analyzer.analyze_document(file_path)
        return result
    except Exception as e:
        print(f"Error analyzing document: {e}")
        raise

def main():
    parser = argparse.ArgumentParser(description='Analyze a document file for malicious content')
    parser.add_argument('file_path', help='Path to the document file to analyze')
    args = parser.parse_args()
    
    if not os.path.exists(args.file_path):
        print(f"Error: File '{args.file_path}' does not exist")
        sys.exit(1)
    
    try:
        result = analyze_document(args.file_path)
        
        print("\n" + "="*60)
        print("DOCUMENT ANALYSIS RESULT:")
        print("="*60)
        print(f"File: {os.path.basename(args.file_path)}")
        
        # Risk assessment (with more robust error handling)
        if 'risk_score' in result:
            if isinstance(result['risk_score'], dict):
                risk_score = result['risk_score'].get('score', 'Unknown')
                risk_level = result['risk_score'].get('level', 'Unknown')
                print(f"Risk Score: {risk_score}/100 ({risk_level})")
            else:
                print(f"Risk Score: {result['risk_score']}")
        
        # Suspicious elements
        if 'has_suspicious_objects' in result:
            print(f"Contains Suspicious Objects: {'Yes' if result['has_suspicious_objects'] else 'No'}")
        
        # Macros detection
        if 'has_macros' in result:
            print(f"Contains Macros: {'Yes' if result['has_macros'] else 'No'}")
            if result.get('macros_analysis'):
                print("\nMacros Analysis:")
                for macro_detail in result['macros_analysis']:
                    print(f"  - {macro_detail}")
        
        # Embedded objects
        if 'embedded_objects' in result and result['embedded_objects']:
            print("\nEmbedded Objects:")
            for obj in result['embedded_objects']:
                print(f"  - {obj.get('type', 'Unknown')}: {obj.get('name', 'Unnamed')}")
        
        # Suspicious URLs
        if 'urls' in result and result['urls']:
            print("\nDetected URLs:")
            for url in result['urls'][:5]:  # Show first 5 URLs
                print(f"  - {url}")
            if len(result['urls']) > 5:
                print(f"  ... and {len(result['urls']) - 5} more")
        
        # Suspicious indicators
        if 'indicators' in result and result['indicators']:
            print("\nSuspicious Indicators:")
            for indicator, details in result['indicators'].items():
                print(f"  - {indicator}: {details}")
        
        # Print all other keys for debugging
        print("\nAll Analysis Results:")
        for key, value in result.items():
            if key not in ['risk_score', 'has_suspicious_objects', 'has_macros', 
                          'macros_analysis', 'embedded_objects', 'urls', 'indicators']:
                print(f"  - {key}: {value}")
        
        print("="*60)
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()