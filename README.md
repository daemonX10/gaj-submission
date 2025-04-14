
# Cerebrus - AI-Powered Malware Analysis Shield

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) <!-- Placeholder License Badge -->
<!-- Add other badges if applicable: Build Status, Coverage, etc. -->

**Tagline:** Intelligent Static, Dynamic & Real-time Malware Analysis with Explainability.

---
# *Note* : Don't run on your system directly , test_sample file contain harmful malware . Use VM environment for dynamic and hybrid analysis

## Table of Contents

*   [The Problem Cerebrus Solves](#the-problem-cerebrus-solves)
*   [Our Solution: Cerebrus](#our-solution-cerebrus)
*   [Key Features](#key-features)
*   [Architecture](#architecture)
*   [Technology Stack](#technology-stack)
*   [Installation](#installation)
*   [Configuration](#configuration)
*   [Usage](#usage)
    *   [Command-Line Prediction](#command-line-prediction)
    *   [Batch Analysis](#batch-analysis)
    *   [Web Application (Flask)](#web-application-flask)
    *   [Model Evaluation & Explanation](#model-evaluation--explanation)
    *   [Real-Time Monitoring](#real-time-monitoring)
*   [Challenges We Ran Into](#challenges-we-ran-into)
*   [Future Work](#future-work)
*   [Contributing](#contributing)
*   [License](#license)
*   [Acknowledgements](#acknowledgements)

---

## The Problem Cerebrus Solves

In the ever-evolving cybersecurity landscape, traditional malware detection methods, often relying solely on known signatures, are struggling to keep pace with increasingly sophisticated threats. Malware is becoming more diverse (ransomware, trojans, spyware, worms, fileless attacks), targeting a wide array of file types (`.exe`, `.dll`, `.pdf`, Office documents, scripts, etc.), and the sheer volume of new strains, including **zero-day attacks** with no prior signatures, is overwhelming.

Key challenges faced by security teams and developers include:

1.  **Zero-Day Attacks:** Signature-based detection is fundamentally ineffective against malware that hasn't been seen before.
2.  **Manual Analysis Bottleneck:** Security analysts are bombarded with a huge volume of files requiring investigation. Manual static and dynamic analysis is time-consuming, requires significant expertise, and doesn't scale effectively.
3.  **Lack of Transparency & Trust:** Many automated tools flag potential malware but operate as "black boxes," failing to explain *why* a file is deemed malicious. This makes it difficult to trust the output, differentiate sophisticated threats from false positives, and take confident remediation actions.

Cerebrus aims to bridge these gaps by providing a comprehensive, AI-powered solution that enhances detection capabilities, improves efficiency, and builds trust through explainability.

---

## Our Solution: Cerebrus

`Cerebrus` is an intelligent malware analysis framework designed to provide multi-layered defense against modern cyber threats. It integrates static analysis, machine learning, external threat intelligence, and explainable AI (XAI) to deliver a robust platform for detecting known and unknown malware across various file formats.

It empowers security analysts, incident responders, and developers to:

*   **Triage files quickly and safely:** Gain significant insights through static analysis *before* execution.
*   **Detect novel threats:** Leverage machine learning models trained on deep file features, moving beyond simple signature matching.
*   **Understand the verdict:** Utilize XAI features to see *why* the AI classified a file as malicious or benign.
*   **Automate analysis:** Use batch processing and API capabilities for large-scale scanning.
*   **(Experimental) Monitor proactively:** Employ real-time monitoring to detect threats as they appear on the system.

---

## Key Features

Cerebrus combines several powerful techniques for comprehensive analysis:

1.  **🤖 AI-Driven Static Analysis:**
    *   **Deep Feature Extraction:** Performs in-depth static analysis *without executing the file*. Extracts a rich set of features tailored to file type (currently strong focus on PE files `.exe`/`.dll`, modular design for extension):
        *   **PE Files:** Detailed parsing of DOS, File, Optional Headers; Section analysis (name patterns, entropy min/max, raw vs. virtual size, RWX permissions); Import Table analysis (suspicious API/DLL counts); Export Table analysis; Resource analysis (count, entropy). Features are structured to align with common malware research datasets (e.g., `dataset_malwares.csv` structure). (Logic primarily in `StaticPEAnalyzer` class)
        *   **General Files:** File size, Accurate Type ID (`python-magic`), Hashes (MD5, SHA1, SHA256, SSDeep fuzzy hash), Overall Shannon Entropy.
        *   **String Analysis:** Extracts ASCII/Unicode strings; calculates count, average length, string block entropy; identifies suspicious patterns (URLs, IPs, file paths, registry keys, common shell commands, suspicious API names, long Base64 strings).
    *   **Benefit:** Enables risk assessment and feature gathering *before* running potentially harmful code, making triage safer and faster.

2.  **💡 Machine Learning Detection:**
    *   Utilizes a **Random Forest Classifier** (trained via `model_training.ipynb` and saved using `joblib`) on the extracted static features.
    *   Learns complex relationships between features to identify malicious patterns missed by traditional signatures.
    *   Effective against **known malware families** and has the potential to flag **unknown variants** exhibiting similar static characteristics.
    *   Provides a **Malware/Benign prediction** and a **Confidence Score** (`predict_proba`).

3.  **🔬 Dynamic Analysis (**" DON'T RUN IN YOUR SYSTEM USE VM "**):**
    *   Includes modules (`dynamic_analysis.py`) demonstrating the capability to run executable files and scripts in a **controlled, isolated environment** (requires user-configured Sandbox/VM like VirtualBox).
    *   Designed to capture behavioral indicators like: Process activity (creation, resource usage via `psutil`), File system modifications, Registry changes (Windows), Network connections.
    *   **Benefit:** Detects malware using obfuscation, packing, or polymorphism that might evade static-only analysis. *(Note: Full sandbox integration and log parsing require further development/configuration).*

4.  **❓ Explainable AI (XAI):**
    *   Integrates **SHAP (SHapley Additive exPlanations)** via `model_explainer.py` to interpret the Machine Learning model's predictions.
    *   Shows **which specific static features** most influenced the classification (positive or negative contribution).
    *   Generates **visualizations** (e.g., waterfall plots) for easy understanding.
    *   Provides **global feature importance** analysis to understand the model's overall decision logic.
    *   **Benefit:** Builds trust in the AI detection, aids analysts in verifying findings, helps debug the model, and provides clear justification for actions taken.

5.  **🌍 External Threat Intelligence:**
    *   Uses the **VirusTotal API** (`vt_api.py`) to check the file's SHA256 hash against its vast database.
    *   Provides immediate context: Is this hash known malware? How many AV engines detect it?
    *   **Benefit:** Quickly identifies known threats and leverages community intelligence.

6.  **🛡️ Signature Scanning:**
    *   Integrates with **ClamAV** (via `subprocess` calls) to perform traditional signature-based scanning.
    *   **Benefit:** Catches common, known malware efficiently using an established open-source engine and database.

7.  **⏱️ Real-Time Monitoring (Experimental):**
    *   Offers a file system (`watchdog`) and process (`psutil`) monitoring module (`realtime_monitor.py`).
    *   Detects new/modified files in specified directories and identifies potentially suspicious process behavior (e.g., high resource usage).
    *   Queues detected items for analysis using other Cerebrus components.
    *   **Benefit:** Enables proactive detection of threats as they emerge on a monitored system. *(Note: Requires careful configuration and runs as a separate process/service).*

8.  **🖥️ Flexible Interfaces:**
    *   **Command-Line Tools:** For prediction (`predict_file.py`), batch processing (`run_batch_test.py`, `scan_and_report.py`), model evaluation (`model_explainer.py`, `test_model_on_subset.py`).
    *   **Web Application:** A Flask-based UI (`app.py`) for user-friendly file uploads and viewing results.
    *   **API Endpoints:** (`app.py`, `run_batch_test.py --api`) allow programmatic integration with other security tools or workflows.

9.  **⚙️ Modular Design:** Built with distinct Python modules/classes for different functionalities (static analysis, dynamic analysis, ML prediction, explanation, external checks, UI), facilitating maintenance and future extensions (e.g., adding analyzers for PDF, Office, scripts).

---

## Architecture

Cerebrus employs a multi-stage pipeline to analyze files:




---

## Technology Stack

*   **Core Language:** Python 3
*   **Machine Learning:** Scikit-learn (RandomForestClassifier), Joblib, Pandas, NumPy, imbalanced-learn
*   **Explainability:** SHAP
*   **Static Analysis:** PEFile, python-magic, SSDeep, standard libraries (re, hashlib, math)
*   **External Checks:** Requests (VirusTotal API), Subprocess (ClamAV CLI)
*   **Web Framework:** Flask (`app.py`)
*   **Real-Time Monitoring:** Watchdog, psutil
*   **System Tools:** ClamAV (External Dependency)
*   **Visualization:** Matplotlib, Seaborn (primarily in `model_explainer.py`)

---

## Installation

1.  **Prerequisites:**
    *   Python 3.8+
    *   `pip` and `venv` (usually included with Python)
    *   Git
    *   **ClamAV:** Install the ClamAV engine and signature updater.
        *   *Debian/Ubuntu:* `sudo apt-get update && sudo apt-get install -y clamav clamav-daemon p7zip-full build-essential libmagic1`
        *   *Fedora/CentOS:* `sudo dnf install -y clamav clamav-update p7zip p7zip-plugins gcc-c++ file-devel`
        *   *macOS (Homebrew):* `brew install clamav`
        *   *Windows:* Download from ClamAV website or use via WSL. Ensure `clamscan` is in PATH.
    *   **Update ClamAV Database:** **Crucial!** Run `sudo freshclam` (Linux/macOS) or the equivalent update command. This may need to be run periodically.

2.  **Clone Repository:**
    ```bash
    git clone https://github.com/YOUR_USERNAME/Cerebrus.git
    cd Cerebrus
    ```
    *(Replace with your actual repository URL)*

3.  **Set up Virtual Environment:** (Recommended)
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # Linux/macOS
    # venv\Scripts\activate   # Windows
    ```

4.  **Install Python Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

5.  **Download/Train ML Model:** Ensure the pre-trained model file (e.g., `ML_model/balanced_malwareclassifier.pkl`) exists. If not, you may need to run the training script (`improved_model_training.py`) using an appropriate dataset (like `Dataset/dataset_malwares.csv` if available).

---

## Configuration

*   **VirusTotal API Key:** (Optional, for enhanced threat intelligence)
    *   Create a `config.json` file in the root directory:
        ```json
        {
            "virustotal_api_key": "YOUR_ACTUAL_VIRUSTOTAL_API_KEY"
        }
        ```
    *   Replace `"YOUR_ACTUAL_VIRUSTOTAL_API_KEY"` with your key obtained from VirusTotal.
    *   Alternatively, set the environment variable `VT_API_KEY`.
*   **Model Path:** The scripts generally expect the model at `ML_model/balanced_malwareclassifier.pkl`. Adjust paths in the scripts (`MODEL_PATH` variables) if your model is located elsewhere.
*   **Analysis Preferences:** Modify `config.json` (as used by `batch_processor.py`) to customize which analysis modules run for different file types.

---

## Usage

### Command-Line Prediction (`predict_file.py`)

Quickly analyze a single **PE file** (`.exe`, `.dll`).

```bash
python predict_file.py /path/to/your/file.exe
```

Output:
```
Analyzing file: file.exe
Model loaded successfully from ML_model/balanced_malwareclassifier.pkl
Extracted 77 features
Features aligned to match model requirements (77 features)

==================================================
PREDICTION RESULT:
==================================================
File: file.exe
Prediction: MALWARE
Confidence: 98.50%
==================================================
```

### Batch Analysis (`run_batch_test.py`)

Analyze multiple files or directories. Creates detailed JSON reports and a summary CSV in `batch_results/`.

```bash
# Analyze all files in a directory (recursive)
python run_batch_test.py -d /path/to/samples --recursive

# Analyze only DLL files in a directory (non-recursive)
python run_batch_test.py -d /path/to/dlls --file_patterns "*.dll" --no-recursive # Assuming --no-recursive flag exists

# Analyze a single file via batch processor logic
python run_batch_test.py -f /path/to/single/file.exe
```

### Web Application (Flask) (`app.py`)

Provides a user-friendly web interface.

1.  **Start Server:**
    ```bash
    # Development:
    flask run --host=0.0.0.0

    # Production (example with Waitress):
    waitress-serve --host=0.0.0.0 --port=5000 app:app
    ```
2.  **Access:** Open `http://<your-server-ip>:5000` in a browser.
3.  **Features:** Upload single files, view analysis results, potentially view batch results and real-time status (depending on `app.py` implementation).

### Model Evaluation & Explanation (`model_explainer.py`)

Used for evaluating the trained ML model and understanding predictions. Typically run after training or for specific analysis tasks.

```bash
# Example (Conceptual - requires data):
# python model_explainer.py --evaluate --X_test features.csv --y_test labels.csv
# Check model_explainer.log for detailed output
# Generates plots (ROC, PR, Confusion Matrix) in current dir or specified output
```

### Real-Time Monitoring (`realtime_monitor.py`)

Monitors directories and processes continuously. Run as a background service or separate process.

```bash
# Example: Monitor Downloads and Temp directories
python realtime_monitor.py -w /path/to/Downloads -w /tmp
```

Check `realtime_monitor.log` for detected events and analysis triggers.

---

## Challenges We Ran Into

Implementing **Explainable AI (XAI)** presented a significant challenge. While our Random Forest model achieved good classification accuracy, it functioned as a "black box." Making its decisions transparent was crucial for user trust, especially for security analysts who need to validate findings.

*   **Interpreting SHAP Values:** The raw numerical outputs from SHAP, while mathematically sound, were initially difficult to translate into actionable insights. Understanding how multiple features interacted within the complex tree ensemble to influence the final prediction required careful processing.
*   **SHAP Library Integration:** Ensuring the `shap.TreeExplainer` was correctly applied to our specific `scikit-learn` `RandomForestClassifier` instance and handling the multi-output nature (probabilities for both classes) needed specific implementation details within `model_explainer.py`.

**How We Overcame It:**

1.  **Value Processing:** We developed functions within `model_explainer.py` to parse the raw SHAP values, calculate the absolute impact of each feature, and rank them to identify the **top positive (contributing to malware verdict) and negative (contributing to benign verdict) influencers** for any given prediction.
2.  **Visualization:** We implemented the `generate_explanation_plot` function to create clear **waterfall or bar plots**. These visuals directly map feature names to their SHAP contribution, making the 'why' behind a prediction immediately apparent.
3.  **Integration:** The explanation logic was integrated into the analysis workflow (callable via `app.py` or used directly in reports) to provide context alongside the verdict and confidence score.

This focus on processing and visualizing the XAI output transformed the explainability feature from a technical possibility into a practical tool for analysts using Cerebrus.

---

## Future Work

*   ** ADVANCE++ Dynamic Analysis:** Implement a robust sandbox environment (e.g., using VirtualBox/QEMU via Python) and integrate the `DynamicAnalyzer` logic fully, including parsing logs from tools like Procmon/tshark to extract behavioral features.
*   **Expand ALL File Type Support:** Create dedicated static analyzer classes (inheriting from `BaseStaticAnalyzer`) for:
    *   Scripts (PowerShell, VBS, JS, Batch) - using regex, keyword analysis, deobfuscation techniques.
    *   Office Documents (OLE/OOXML) - using `olefile`/`zipfile`, checking for macros, embedded objects, external links (`document_analyzer.py`).
    *   PDFs - using `PyPDF2` or `PyMuPDF` to check for JavaScript, auto-actions, embedded files, obfuscation.
    *   Archives - unpacking various formats and analyzing contents.
    *   Android APKs.
*   **Advanced ML Models:** Although our model have accuracy of 99% you can explore Deep Learning models (CNNs for binary visualization, RNNs/LSTMs for sequential data like API calls from dynamic analysis) for potentially higher accuracy, especially on obfuscated samples.
*   **UI/UX Enhancements:** Improve the Flask web interface, add dashboards, historical analysis views, and better visualization of results.
*   **Performance Optimization:** Optimize feature extraction and model prediction for speed, especially for batch processing and real-time monitoring.
---

## Contributing

Contributions are welcome! Please feel free to submit pull requests, report issues, or suggest new features.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details (assuming MIT).

---

## Acknowledgements

*   The creators and maintainers of the libraries used (PEFile, python-magic, Scikit-learn, SHAP, etc.).
*   OUR TEAM : MANJESH TIWARI , AKASH YADAV , MANDEEP

---
