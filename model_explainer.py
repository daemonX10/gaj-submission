import os
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import joblib
import logging
import importlib.util
from sklearn.metrics import (
    confusion_matrix, precision_recall_curve, roc_curve, 
    auc, accuracy_score, recall_score, precision_score, f1_score
)
from sklearn.model_selection import cross_val_score, KFold, StratifiedKFold
import itertools

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='model_explainer.log'
)
logger = logging.getLogger('ModelExplainer')

# Add SHAP for model explainability
import shap

class ModelExplainer:
    """
    Provides evaluation metrics and explanations for the malware detection model
    """
    def __init__(self, model_path='ML_model/malwareclassifier-V2.pkl'):
        """
        Initialize the model explainer
        
        Args:
            model_path: Path to the trained ML model
        """
        try:
            self.model = joblib.load(model_path)
            logger.info(f"Loaded model from {model_path}")
            
            # Import feature extraction module
            if importlib.util.find_spec("feature_extraction") is not None:
                self.feature_extractor = __import__('feature_extraction')
                logger.info("Loaded feature extraction module")
            else:
                self.feature_extractor = None
                logger.warning("Feature extraction module not found")
                
            # Try to determine if we have a feature importance attribute
            if hasattr(self.model, 'feature_importances_'):
                self.has_feature_importance = True
            else:
                self.has_feature_importance = False
                
        except Exception as e:
            logger.error(f"Error initializing model explainer: {e}")
            self.model = None
    
    def evaluate_model(self, X_test, y_test):
        """
        Evaluate the model performance on test data
        
        Args:
            X_test: Test features
            y_test: Test labels
            
        Returns:
            dict: Evaluation metrics
        """
        if self.model is None:
            return {"error": "Model not loaded"}
        
        try:
            # Make predictions
            y_pred = self.model.predict(X_test)
            y_proba = None
            
            # Try to get probability scores if available
            if hasattr(self.model, 'predict_proba'):
                try:
                    y_proba = self.model.predict_proba(X_test)[:, 1]
                except:
                    pass
            
            # Calculate metrics
            acc = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred)
            recall = recall_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred)
            
            metrics = {
                "accuracy": float(acc),
                "precision": float(precision),
                "recall": float(recall),
                "f1_score": float(f1),
                "confusion_matrix": confusion_matrix(y_test, y_pred).tolist()
            }
            
            # Calculate ROC and PR curves if probabilities are available
            if y_proba is not None:
                # ROC curve
                fpr, tpr, _ = roc_curve(y_test, y_proba)
                roc_auc = auc(fpr, tpr)
                
                # PR curve
                precision_curve, recall_curve, _ = precision_recall_curve(y_test, y_proba)
                pr_auc = auc(recall_curve, precision_curve)
                
                metrics.update({
                    "roc_auc": float(roc_auc),
                    "pr_auc": float(pr_auc)
                })
                
                # Save ROC curve plot
                self._save_roc_curve(fpr, tpr, roc_auc)
                
                # Save PR curve plot
                self._save_pr_curve(precision_curve, recall_curve, pr_auc)
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error evaluating model: {e}")
            return {"error": str(e)}
    
    def cross_validate(self, X, y, cv=5, random_state=42):
        """
        Perform k-fold cross-validation on the model
        
        Args:
            X: Features
            y: Target labels
            cv: Number of folds
            random_state: Random seed for reproducibility
            
        Returns:
            dict: Cross-validation results
        """
        try:
            from sklearn.model_selection import cross_val_score, KFold, StratifiedKFold
            import numpy as np
            
            # Create stratified k-fold for imbalanced datasets
            skf = StratifiedKFold(n_splits=cv, shuffle=True, random_state=random_state)
            
            # Calculate various metrics
            accuracy = cross_val_score(self.model, X, y, cv=skf, scoring='accuracy')
            precision = cross_val_score(self.model, X, y, cv=skf, scoring='precision')
            recall = cross_val_score(self.model, X, y, cv=skf, scoring='recall')
            f1 = cross_val_score(self.model, X, y, cv=skf, scoring='f1')
            roc_auc = cross_val_score(self.model, X, y, cv=skf, scoring='roc_auc')
            
            # Summarize results
            cv_results = {
                'accuracy': {
                    'mean': np.mean(accuracy),
                    'std': np.std(accuracy),
                    'values': accuracy.tolist()
                },
                'precision': {
                    'mean': np.mean(precision),
                    'std': np.std(precision),
                    'values': precision.tolist()
                },
                'recall': {
                    'mean': np.mean(recall),
                    'std': np.std(recall),
                    'values': recall.tolist()
                },
                'f1': {
                    'mean': np.mean(f1),
                    'std': np.std(f1),
                    'values': f1.tolist()
                },
                'roc_auc': {
                    'mean': np.mean(roc_auc),
                    'std': np.std(roc_auc),
                    'values': roc_auc.tolist()
                }
            }
            
            # Create visualizations if matplotlib is available
            if self._has_matplotlib:
                plt.figure(figsize=(10, 6))
                metrics = ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']
                
                means = [cv_results[m]['mean'] for m in metrics]
                stds = [cv_results[m]['std'] for m in metrics]
                
                # Create bar chart with error bars
                bars = plt.bar(metrics, means, yerr=stds, alpha=0.7, capsize=10)
                plt.axhline(y=0.5, color='r', linestyle='--', alpha=0.3, label='Random Classifier')
                plt.ylim(0, 1.0)
                plt.title('Cross-Validation Results')
                plt.ylabel('Score')
                plt.grid(axis='y', linestyle='--', alpha=0.3)
                
                # Add values on top of bars
                for bar in bars:
                    height = bar.get_height()
                    plt.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                            f'{height:.3f}', ha='center', va='bottom')
                
                plt.tight_layout()
                cv_results['plot'] = self._fig_to_base64(plt.gcf())
                plt.close()
            
            return cv_results
            
        except Exception as e:
            logger.error(f"Error in cross-validation: {e}")
            return {"error": str(e)}
    
    def sensitivity_analysis(self, X, y, thresholds=None, random_state=42):
        """
        Perform threshold sensitivity analysis for probability predictions
        
        Args:
            X: Features
            y: Target labels
            thresholds: List of threshold values to evaluate (default: 10 values from 0.1 to 0.9)
            random_state: Random seed for reproducibility
            
        Returns:
            dict: Sensitivity analysis results
        """
        try:
            from sklearn.model_selection import train_test_split
            import numpy as np
            
            if thresholds is None:
                thresholds = np.linspace(0.1, 0.9, 9)
            
            # Split data for sensitivity analysis
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.3, random_state=random_state, stratify=y
            )
            
            # Train model
            self.model.fit(X_train, y_train)
            
            # Get probability predictions
            y_proba = self.model.predict_proba(X_test)[:, 1]
            
            # Calculate metrics for each threshold
            results = []
            for threshold in thresholds:
                y_pred = (y_proba >= threshold).astype(int)
                
                # Calculate metrics
                tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
                accuracy = (tp + tn) / (tp + tn + fp + fn)
                precision = tp / (tp + fp) if (tp + fp) > 0 else 0
                recall = tp / (tp + fn) if (tp + fn) > 0 else 0
                f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
                specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
                
                results.append({
                    'threshold': threshold,
                    'accuracy': accuracy,
                    'precision': precision,
                    'recall': recall,
                    'f1': f1,
                    'specificity': specificity,
                    'tn': tn,
                    'fp': fp,
                    'fn': fn,
                    'tp': tp
                })
            
            # Optimal threshold based on F1 score
            optimal_idx = max(range(len(results)), key=lambda i: results[i]['f1'])
            optimal_threshold = results[optimal_idx]['threshold']
            
            # Create visualizations if matplotlib is available
            if self._has_matplotlib:
                # Metrics vs threshold plot
                plt.figure(figsize=(12, 6))
                plt.subplot(1, 2, 1)
                plt.plot([r['threshold'] for r in results], [r['accuracy'] for r in results], 'o-', label='Accuracy')
                plt.plot([r['threshold'] for r in results], [r['precision'] for r in results], 's-', label='Precision')
                plt.plot([r['threshold'] for r in results], [r['recall'] for r in results], '^-', label='Recall')
                plt.plot([r['threshold'] for r in results], [r['f1'] for r in results], 'D-', label='F1 Score')
                plt.axvline(x=optimal_threshold, color='r', linestyle='--', 
                           label=f'Optimal Threshold = {optimal_threshold:.2f}')
                plt.xlabel('Threshold')
                plt.ylabel('Score')
                plt.title('Metrics vs. Threshold')
                plt.legend()
                plt.grid(True, alpha=0.3)
                
                # ROC curve
                plt.subplot(1, 2, 2)
                fpr, tpr, _ = roc_curve(y_test, y_proba)
                roc_auc = auc(fpr, tpr)
                plt.plot(fpr, tpr, label=f'ROC Curve (AUC = {roc_auc:.3f})')
                plt.plot([0, 1], [0, 1], 'k--', label='Random')
                plt.xlabel('False Positive Rate')
                plt.ylabel('True Positive Rate')
                plt.title('ROC Curve')
                plt.legend()
                plt.grid(True, alpha=0.3)
                
                plt.tight_layout()
                
                # Create confusion matrix at optimal threshold
                optimal_result = results[optimal_idx]
                plt.figure(figsize=(8, 6))
                cm = np.array([
                    [optimal_result['tn'], optimal_result['fp']],
                    [optimal_result['fn'], optimal_result['tp']]
                ])
                
                self.plot_confusion_matrix(
                    cm, 
                    classes=['Benign', 'Malware'], 
                    title=f'Confusion Matrix (Threshold = {optimal_threshold:.2f})'
                )
                
                sensitivity_results = {
                    'results': results,
                    'optimal_threshold': optimal_threshold,
                    'metrics_plot': self._fig_to_base64(plt.figure(1)),
                    'confusion_matrix': self._fig_to_base64(plt.figure(2))
                }
                
                plt.close('all')
            else:
                sensitivity_results = {
                    'results': results,
                    'optimal_threshold': optimal_threshold
                }
            
            return sensitivity_results
            
        except Exception as e:
            logger.error(f"Error in sensitivity analysis: {e}")
            return {"error": str(e)}
    
    def plot_confusion_matrix(self, cm, classes, title='Confusion Matrix', cmap=None):
        """
        Plot confusion matrix
        
        Args:
            cm: Confusion matrix
            classes: Class labels
            title: Plot title
            cmap: Color map
        """
        if cmap is None:
            cmap = plt.cm.Blues
        
        plt.imshow(cm, interpolation='nearest', cmap=cmap)
        plt.title(title)
        plt.colorbar()
        tick_marks = np.arange(len(classes))
        plt.xticks(tick_marks, classes, rotation=45)
        plt.yticks(tick_marks, classes)
        
        # Text formatting
        fmt = 'd'
        thresh = cm.max() / 2.
        for i, j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
            plt.text(j, i, format(cm[i, j], fmt),
                    horizontalalignment="center",
                    color="white" if cm[i, j] > thresh else "black")
        
        plt.tight_layout()
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
    
    def feature_importance_analysis(self, X, feature_names=None):
        """
        Analyze feature importance and provide visualizations
        
        Args:
            X: Feature matrix or DataFrame
            feature_names: List of feature names (if X is not a DataFrame)
            
        Returns:
            dict: Feature importance results
        """
        try:
            import numpy as np
            import pandas as pd
            from sklearn.inspection import permutation_importance
            
            if feature_names is None:
                if hasattr(X, 'columns'):  # Check if X is a DataFrame
                    feature_names = X.columns.tolist()
                else:
                    feature_names = [f'Feature {i}' for i in range(X.shape[1])]
            
            # Get feature importance
            if hasattr(self.model, 'feature_importances_'):
                # For tree-based models
                importance = self.model.feature_importances_
            elif hasattr(self.model, 'coef_'):
                # For linear models
                importance = np.abs(self.model.coef_[0])
            else:
                # Calculate permutation importance if model doesn't expose feature importance
                perm_importance = permutation_importance(self.model, X, np.zeros(X.shape[0]))
                importance = perm_importance.importances_mean
            
            # Sort features by importance
            indices = np.argsort(importance)[::-1]
            sorted_importance = importance[indices]
            sorted_features = [feature_names[i] for i in indices]
            
            # Truncate to top N features for readability
            top_n = min(30, len(sorted_features))
            top_features = sorted_features[:top_n]
            top_importance = sorted_importance[:top_n]
            
            results = {
                'importance': sorted_importance.tolist(),
                'features': sorted_features,
                'top_features': top_features,
                'top_importance': top_importance.tolist()
            }
            
            # Create visualizations if matplotlib is available
            if self._has_matplotlib:
                plt.figure(figsize=(10, 8))
                plt.barh(range(top_n), top_importance, align='center')
                plt.yticks(range(top_n), top_features)
                plt.xlabel('Feature Importance')
                plt.title('Top Feature Importance')
                plt.tight_layout()
                results['plot'] = self._fig_to_base64(plt.gcf())
                plt.close()
            
            return results
            
        except Exception as e:
            logger.error(f"Error in feature importance analysis: {e}")
            return {"error": str(e)}
    
    def _save_roc_curve(self, fpr, tpr, roc_auc):
        """Save ROC curve plot to file"""
        try:
            plt.figure(figsize=(10, 8))
            plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
            plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title('Receiver Operating Characteristic (ROC) Curve')
            plt.legend(loc="lower right")
            plt.savefig('eval_roc_curve.png')
            plt.close()
        except Exception as e:
            logger.error(f"Error saving ROC curve: {e}")
    
    def _save_pr_curve(self, precision, recall, pr_auc):
        """Save precision-recall curve plot to file"""
        try:
            plt.figure(figsize=(10, 8))
            plt.plot(recall, precision, color='blue', lw=2, label=f'PR curve (area = {pr_auc:.2f})')
            plt.xlabel('Recall')
            plt.ylabel('Precision')
            plt.ylim([0.0, 1.05])
            plt.xlim([0.0, 1.0])
            plt.title('Precision-Recall Curve')
            plt.legend(loc="lower left")
            plt.savefig('eval_pr_curve.png')
            plt.close()
        except Exception as e:
            logger.error(f"Error saving PR curve: {e}")
    
    def _save_feature_importance_plot(self, feature_importance):
        """Save feature importance plot to file"""
        try:
            # Extract feature names and importance values
            names = [item['feature_name'] for item in feature_importance]
            values = [item['importance'] for item in feature_importance]
            
            # Create horizontal bar plot
            plt.figure(figsize=(12, 10))
            plt.barh(range(len(names)), values, align='center')
            plt.yticks(range(len(names)), names)
            plt.xlabel('Importance')
            plt.title('Feature Importance')
            plt.tight_layout()
            plt.savefig('feature_importance.png')
            plt.close()
        except Exception as e:
            logger.error(f"Error saving feature importance plot: {e}")
    
    def _save_feature_contribution_plot(self, contributions):
        """Save feature contribution plot for a specific prediction"""
        try:
            # Extract feature names and contribution values
            names = [item['feature_name'] for item in contributions]
            values = [item['contribution'] for item in contributions]
            
            # Determine colors based on positive/negative contribution
            colors = ['green' if x > 0 else 'red' for x in values]
            
            # Create horizontal bar plot
            plt.figure(figsize=(12, 10))
            plt.barh(range(len(names)), values, align='center', color=colors)
            plt.yticks(range(len(names)), names)
            plt.xlabel('Contribution to prediction')
            plt.title('Feature Contributions to Prediction')
            plt.axvline(x=0, color='black', linestyle='-', alpha=0.3)
            plt.tight_layout()
            plt.savefig('feature_contributions.png')
            plt.close()
        except Exception as e:
            logger.error(f"Error saving feature contribution plot: {e}")

    def explain_prediction(self, feature_vector, feature_names):
        """
        Provide detailed explanation for an individual prediction using SHAP values.
        
        Args:
            feature_vector: Feature vector for a single sample
            feature_names: Names of features in the vector
            
        Returns:
            Dictionary containing prediction, confidence, and feature importance details
        """
        # Make prediction
        prediction = self.model.predict([feature_vector])[0]
        confidence = np.max(self.model.predict_proba([feature_vector])[0])
        
        # Create explanation using SHAP
        try:
            # Initialize SHAP explainer
            explainer = shap.TreeExplainer(self.model)
            
            # Calculate SHAP values
            shap_values = explainer.shap_values(feature_vector)
            
            # If it's a binary classification model with 2 outputs
            if isinstance(shap_values, list) and len(shap_values) == 2:
                shap_values = shap_values[1]  # For binary classification, use the positive class
            
            # Get top contributing features (positive and negative)
            feature_importance = [(feature_names[i], shap_values[i]) for i in range(len(feature_names))]
            feature_importance.sort(key=lambda x: abs(x[1]), reverse=True)
            
            # Top 10 contributing features
            top_features = feature_importance[:10]
            
            return {
                'prediction': int(prediction),
                'confidence': float(confidence),
                'top_features': top_features,
                'all_features': feature_importance
            }
        except Exception as e:
            # Fallback if SHAP fails
            print(f"SHAP explanation failed: {e}. Using feature importances instead.")
            feature_importance = [(feature_names[i], self.model.feature_importances_[i]) 
                                   for i in range(len(feature_names))]
            feature_importance.sort(key=lambda x: x[1], reverse=True)
            top_features = feature_importance[:10]
            
            return {
                'prediction': int(prediction),
                'confidence': float(confidence),
                'top_features': top_features,
                'all_features': feature_importance
            }

    def generate_explanation_plot(self, explanation, output_path=None):
        """
        Generate visualization of feature contributions for a prediction
        
        Args:
            explanation: Explanation dictionary from explain_prediction
            output_path: Path to save the visualization (optional)
        """
        # Extract data
        features = [f[0] for f in explanation['top_features']]
        values = [f[1] for f in explanation['top_features']]
        
        # Create waterfall plot
        plt.figure(figsize=(10, 6))
        colors = ['red' if x < 0 else 'blue' for x in values]
        plt.barh(range(len(features)), values, color=colors)
        plt.yticks(range(len(features)), features)
        plt.xlabel('Feature Contribution (SHAP value)')
        plt.title(f"Prediction: {'Malware' if explanation['prediction'] == 1 else 'Benign'} " + 
                  f"(Confidence: {explanation['confidence']:.2f})")
        plt.tight_layout()
        
        if output_path:
            plt.savefig(output_path)
            plt.close()
        else:
            plt.show()


class ModelValidator:
    """
    Validates the model against new malware samples to assess generalization
    """
    def __init__(self, model_path='ML_model/malwareclassifier-V2.pkl', output_dir='model_validation'):
        """
        Initialize the model validator
        
        Args:
            model_path: Path to the trained ML model
            output_dir: Directory to store validation results
        """
        try:
            self.model = joblib.load(model_path)
            logger.info(f"Loaded model from {model_path}")
            
            # Import feature extraction module
            if importlib.util.find_spec("feature_extraction") is not None:
                self.feature_extractor = __import__('feature_extraction')
                logger.info("Loaded feature extraction module")
            else:
                self.feature_extractor = None
                logger.warning("Feature extraction module not found")
                
            # Create output directory
            self.output_dir = output_dir
            os.makedirs(output_dir, exist_ok=True)
            
        except Exception as e:
            logger.error(f"Error initializing model validator: {e}")
            self.model = None
    
    def validate_on_directory(self, benign_dir, malware_dir):
        """
        Validate model on directories of benign and malware samples
        
        Args:
            benign_dir: Directory containing benign samples
            malware_dir: Directory containing malware samples
            
        Returns:
            dict: Validation results
        """
        if self.model is None or self.feature_extractor is None:
            return {"error": "Model or feature extractor not loaded"}
        
        try:
            # Get list of files
            benign_files = [os.path.join(benign_dir, f) for f in os.listdir(benign_dir) 
                          if os.path.isfile(os.path.join(benign_dir, f)) and f.endswith(('.exe', '.dll'))]
            
            malware_files = [os.path.join(malware_dir, f) for f in os.listdir(malware_dir) 
                          if os.path.isfile(os.path.join(malware_dir, f)) and f.endswith(('.exe', '.dll'))]
            
            logger.info(f"Found {len(benign_files)} benign files and {len(malware_files)} malware files")
            
            # Process benign files
            benign_results = []
            for file_path in benign_files:
                result = self._validate_file(file_path, expected_label=0)
                benign_results.append(result)
            
            # Process malware files
            malware_results = []
            for file_path in malware_files:
                result = self._validate_file(file_path, expected_label=1)
                malware_results.append(result)
            
            # Calculate metrics
            benign_correct = sum(1 for r in benign_results if r['correct'])
            malware_correct = sum(1 for r in malware_results if r['correct'])
            
            total_files = len(benign_files) + len(malware_files)
            total_correct = benign_correct + malware_correct
            
            benign_accuracy = benign_correct / len(benign_files) if benign_files else 0
            malware_accuracy = malware_correct / len(malware_files) if malware_files else 0
            overall_accuracy = total_correct / total_files if total_files > 0 else 0
            
            # Calculate confusion matrix
            true_negatives = benign_correct
            false_positives = len(benign_files) - benign_correct
            true_positives = malware_correct
            false_negatives = len(malware_files) - malware_correct
            
            # Calculate metrics
            precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
            recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            
            # Prepare results
            results = {
                "benign_files": len(benign_files),
                "malware_files": len(malware_files),
                "total_files": total_files,
                "benign_accuracy": benign_accuracy,
                "malware_accuracy": malware_accuracy,
                "overall_accuracy": overall_accuracy,
                "precision": precision,
                "recall": recall,
                "f1_score": f1,
                "confusion_matrix": {
                    "true_negatives": true_negatives,
                    "false_positives": false_positives,
                    "true_positives": true_positives,
                    "false_negatives": false_negatives
                },
                "benign_results": benign_results,
                "malware_results": malware_results
            }
            
            # Save results to file
            results_file = os.path.join(self.output_dir, "validation_results.json")
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            # Save visualization
            self._visualize_results(results)
            
            return results
            
        except Exception as e:
            logger.error(f"Error validating on directories: {e}")
            return {"error": str(e)}
    
    def _validate_file(self, file_path, expected_label):
        """Validate a single file"""
        try:
            # Extract features
            features = self.feature_extractor.extract_features(file_path)
            
            # Make prediction
            prediction = self.model.predict(features)[0]
            
            # Try to get probability scores if available
            probability = None
            if hasattr(self.model, 'predict_proba'):
                try:
                    probability = self.model.predict_proba(features)[0, 1]
                except:
                    pass
            
            # Check if prediction matches expected label
            correct = prediction == expected_label
            
            return {
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "expected_label": expected_label,
                "predicted_label": int(prediction),
                "probability": float(probability) if probability is not None else None,
                "correct": correct
            }
            
        except Exception as e:
            logger.error(f"Error validating file {file_path}: {e}")
            return {
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "expected_label": expected_label,
                "error": str(e)
            }
    
    def _visualize_results(self, results):
        """Create visualizations for validation results"""
        try:
            # Confusion matrix heatmap
            cm = np.array([
                [results["confusion_matrix"]["true_negatives"], results["confusion_matrix"]["false_positives"]],
                [results["confusion_matrix"]["false_negatives"], results["confusion_matrix"]["true_positives"]]
            ])
            
            plt.figure(figsize=(10, 8))
            plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
            plt.title('Confusion Matrix')
            plt.colorbar()
            classes = ['Benign', 'Malware']
            tick_marks = np.arange(len(classes))
            plt.xticks(tick_marks, classes)
            plt.yticks(tick_marks, classes)
            
            # Add text annotations
            thresh = cm.max() / 2.
            for i in range(cm.shape[0]):
                for j in range(cm.shape[1]):
                    plt.text(j, i, format(cm[i, j], 'd'),
                            horizontalalignment="center",
                            color="white" if cm[i, j] > thresh else "black")
            
            plt.ylabel('True label')
            plt.xlabel('Predicted label')
            plt.tight_layout()
            plt.savefig(os.path.join(self.output_dir, 'confusion_matrix.png'))
            plt.close()
            
            # Metrics bar chart
            metrics = ['Accuracy', 'Precision', 'Recall', 'F1 Score']
            values = [
                results["overall_accuracy"],
                results["precision"],
                results["recall"],
                results["f1_score"]
            ]
            
            plt.figure(figsize=(12, 8))
            plt.bar(metrics, values, color='teal')
            plt.ylim([0, 1.1])
            plt.ylabel('Score')
            plt.title('Model Performance Metrics')
            plt.savefig(os.path.join(self.output_dir, 'performance_metrics.png'))
            plt.close()
            
            # Class-specific accuracy
            classes = ['Benign', 'Malware']
            class_acc = [results["benign_accuracy"], results["malware_accuracy"]]
            
            plt.figure(figsize=(10, 8))
            plt.bar(classes, class_acc, color=['green', 'red'])
            plt.ylim([0, 1.1])
            plt.ylabel('Accuracy')
            plt.title('Class-specific Accuracy')
            plt.savefig(os.path.join(self.output_dir, 'class_accuracy.png'))
            plt.close()
            
        except Exception as e:
            logger.error(f"Error creating visualizations: {e}")


# Example usage
if __name__ == "__main__":
    explainer = ModelExplainer()
    
    # Example file path - should be replaced with actual file to explain
    test_file = "path/to/test/file.exe"
    
    if os.path.exists(test_file):
        explanation = explainer.explain_prediction(test_file)
        print(json.dumps(explanation, indent=2))
    else:
        print(f"Test file not found: {test_file}") 