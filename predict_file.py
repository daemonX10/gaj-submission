#!/usr/bin/env python3
"""
Script to predict if a file is malware using the trained model
"""

import os
import sys
import joblib
import pandas as pd
import argparse
from feature_extraction import extract_features

def predict_malware(file_path):
    """Predict if a file is malware"""
    print(f"Analyzing file: {os.path.basename(file_path)}")
    
    # Load the trained model
    model_path = "malwareclassifier-V2.pkl"
    if not os.path.exists(model_path):
        model_path = "ML_model/malwareclassifier-V2.pkl"
    
    classifier = joblib.load(model_path)
    print(f"Model loaded successfully from {model_path}")
    
    # Extract features from the file
    features_df = extract_features(file_path)
    print(f"Extracted {features_df.shape[1]} features")
    
    # Align features with what the model expects
    if hasattr(classifier, 'feature_names_in_'):
        expected_features = classifier.feature_names_in_
        
        # Add missing features with default value 0
        for feature in expected_features:
            if feature not in features_df.columns:
                features_df[feature] = 0
        
        # Select only the features the model expects, in the right order
        features_df = features_df[expected_features]
        
        print(f"Features aligned to match model requirements ({len(expected_features)} features)")
    
    # Make prediction
    prediction = classifier.predict(features_df)[0]
    
    # Get probability if available
    if hasattr(classifier, 'predict_proba'):
        probabilities = classifier.predict_proba(features_df)[0]
        confidence = probabilities[1] if prediction == 1 else probabilities[0]
    else:
        confidence = None
    
    result = {
        "is_malware": bool(prediction == 1),
        "confidence": float(confidence) if confidence is not None else None,
        "prediction": int(prediction),
        "file_name": os.path.basename(file_path)
    }
    
    return result

def main():
    parser = argparse.ArgumentParser(description='Predict if a file is malware')
    parser.add_argument('file_path', help='Path to the file to analyze')
    args = parser.parse_args()
    
    try:
        result = predict_malware(args.file_path)
        
        print("\n" + "="*50)
        print("PREDICTION RESULT:")
        print("="*50)
        print(f"File: {result['file_name']}")
        print(f"Prediction: {'MALWARE' if result['is_malware'] else 'BENIGN'}")
        if result['confidence'] is not None:
            print(f"Confidence: {result['confidence']:.2%}")
        print("="*50)
        
    except Exception as e:
        print(f"Error analyzing file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()