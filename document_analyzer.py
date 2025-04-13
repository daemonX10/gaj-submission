import os
import re
import json
import logging
import hashlib
import zipfile
import olefile
import magic
import xml.etree.ElementTree as ET
from io import BytesIO

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='document_analyzer.log'
)
logger = logging.getLogger('DocumentAnalyzer')

class DocumentAnalyzer:
    """
    Analyzes document files (Office documents, PDFs, etc.) for potential malware
    """
    def __init__(self):
        # Initialize known malicious patterns
        self.vba_suspicious_keywords = [
            'Shell', 'CreateObject', 'WScript.Shell', 'Environ', 
            'powershell', 'cmd.exe', 'rundll32', 'bitsadmin', 'certutil',
            'GetObject', 'ExecuteExcel4Macro', 'ExecuteStatement', 'AutoExec',
            'Auto_Open', 'Document_Open', 'Workbook_Open', 'WindowsFolder',
            'ChromeInstall', 'Call Shell', 'ShellExecute', 'WinExec',
            'URLDownloadToFile', 'WinHttpRequest', 'XMLHTTP', 'ActiveXObject',
            'hidden', 'visibl', 'CreateThread', 'RegRead', 'RegWrite'
        ]
        
        self.pdf_suspicious_keywords = [
            '/JavaScript', '/JS', '/Launch', '/OpenAction', '/AA', '/AcroForm', 
            '/URI', '/SubmitForm', '/JBIG2Decode', '/RichMedia', 
            'getAnnots', '/ObjStm', '/XFA', '/Colors > 2^24'
        ]
        
        self.office_macro_patterns = [
            rb'\\macros\\', rb'vbaProject.bin', rb'_VBA_PROJECT', 
            rb'VBA/ThisDocument', rb'VBA/ThisWorkbook'
        ]
        
        self.url_pattern = re.compile(rb'(https?:\/\/[^\s\'">\]]+)')
        self.ip_pattern = re.compile(rb'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
        self.hex_pattern = re.compile(rb'(0x[0-9A-Fa-f]{2}[0-9A-Fa-f]+)')
        self.base64_pattern = re.compile(rb'([A-Za-z0-9+/]{40,}=*)')
        self.email_pattern = re.compile(rb'[\w\.-]+@[\w\.-]+\.\w+')
        
    def analyze_document(self, file_path):
        """
        Analyze a document file for potential malicious content
        
        Args:
            file_path: Path to the document file
            
        Returns:
            dict: Analysis results
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return {"error": "File not found"}
        
        # Get file type using python-magic
        try:
            file_type = magic.from_file(file_path)
            mime_type = magic.from_file(file_path, mime=True)
            logger.info(f"Analyzing file: {file_path}, Type: {file_type}, MIME: {mime_type}")
        except Exception as e:
            logger.error(f"Error determining file type: {e}")
            file_type = "Unknown"
            mime_type = "application/octet-stream"
        
        # Calculate file hash
        file_hash = self._calculate_hash(file_path)
        
        # Initialize results dictionary
        results = {
            "file_path": file_path,
            "file_type": file_type,
            "mime_type": mime_type,
            "file_hash": file_hash,
            "suspicious_indicators": [],
            "extracted_urls": [],
            "extracted_ips": [],
            "risk_score": 0,
            "has_macros": False,
            "has_suspicious_objects": False,
            "embedded_files": []
        }
        
        # Analyze based on file type
        if "Microsoft Office" in file_type or "Composite Document" in file_type:
            self._analyze_office_document(file_path, results)
        elif "PDF" in file_type:
            self._analyze_pdf(file_path, results)
        elif "XML" in file_type or mime_type == "text/xml":
            self._analyze_xml(file_path, results)
        elif "Rich Text" in file_type or mime_type == "text/rtf":
            self._analyze_rtf(file_path, results)
        elif "ASCII text" in file_type or "UTF-8" in file_type:
            self._analyze_text_file(file_path, results)
        elif "Zip archive" in file_type:
            # Could be a DOCX, XLSX, etc. in the new Office format
            self._analyze_zip_archive(file_path, results)
        else:
            logger.warning(f"Unsupported file type for detailed analysis: {file_type}")
            # Still perform basic analysis
            self._analyze_binary_file(file_path, results)
        
        # Calculate the risk score
        self._calculate_risk_score(results)
        
        return results
    
    def _analyze_office_document(self, file_path, results):
        """Analyze Microsoft Office documents (old format)"""
        try:
            with olefile.OleFile(file_path) as ole:
                # Check for macros
                if ole.exists('Macros') or ole.exists('VBA'):
                    results["has_macros"] = True
                    results["suspicious_indicators"].append("Contains macros")
                
                # Look for VBA project streams
                for stream_name in ole.listdir():
                    stream_path = "/".join(stream_name)
                    if "VBA" in stream_path or "Macros" in stream_path:
                        try:
                            stream = ole.openstream(stream_path)
                            content = stream.read()
                            
                            # Check for suspicious VBA keywords
                            for keyword in self.vba_suspicious_keywords:
                                if keyword.encode() in content:
                                    results["suspicious_indicators"].append(f"Suspicious VBA keyword: {keyword}")
                            
                            # Extract URLs, IPs, etc.
                            self._extract_patterns_from_binary(content, results)
                        except Exception as e:
                            logger.error(f"Error reading stream {stream_path}: {e}")
                
                # Check for embedded objects
                if ole.exists('ObjectPool'):
                    results["suspicious_indicators"].append("Contains embedded objects")
                    results["has_suspicious_objects"] = True
                    
                # Look for suspicious streams
                suspicious_streams = ['RootEntry', 'Ole10Native', '\x01Ole10Native', '\x01Ole']
                for sus_stream in suspicious_streams:
                    if ole.exists(sus_stream):
                        results["suspicious_indicators"].append(f"Contains suspicious stream: {sus_stream}")
                        results["has_suspicious_objects"] = True
                        
        except Exception as e:
            logger.error(f"Error analyzing Office document: {e}")
            results["suspicious_indicators"].append(f"Error analyzing document structure: {str(e)}")
    
    def _analyze_zip_archive(self, file_path, results):
        """Analyze Office Open XML documents (new format: docx, xlsx, etc.)"""
        try:
            with zipfile.ZipFile(file_path) as zip_file:
                # List all files in the archive
                file_list = zip_file.namelist()
                results["embedded_files"] = file_list
                
                # Check for macros (vbaProject.bin indicates macros)
                if "word/vbaProject.bin" in file_list or "xl/vbaProject.bin" in file_list:
                    results["has_macros"] = True
                    results["suspicious_indicators"].append("Contains macros (vbaProject.bin)")
                
                # Check for external relationships (could contain links)
                rel_files = [f for f in file_list if f.endswith('.rels')]
                for rel_file in rel_files:
                    try:
                        with zip_file.open(rel_file) as f:
                            content = f.read()
                            # Look for external links
                            if b'Target=' in content and (b'http:' in content or b'https:' in content):
                                results["suspicious_indicators"].append(f"External links found in {rel_file}")
                                # Extract URLs
                                self._extract_patterns_from_binary(content, results)
                    except Exception as e:
                        logger.error(f"Error reading relationship file {rel_file}: {e}")
                
                # Check content types
                if "[Content_Types].xml" in file_list:
                    try:
                        with zip_file.open("[Content_Types].xml") as f:
                            content = f.read()
                            # Look for suspicious content types
                            suspicious_types = [b'application/x-javascript', b'text/javascript', b'application/octet-stream']
                            for s_type in suspicious_types:
                                if s_type in content:
                                    results["suspicious_indicators"].append(f"Suspicious content type: {s_type.decode()}")
                    except Exception as e:
                        logger.error(f"Error reading content types: {e}")
                
                # Check for suspicious files within the archive
                suspicious_extensions = ['.exe', '.dll', '.js', '.vbs', '.ps1', '.bat', '.hta']
                for file_name in file_list:
                    ext = os.path.splitext(file_name)[1].lower()
                    if ext in suspicious_extensions:
                        results["suspicious_indicators"].append(f"Suspicious embedded file: {file_name}")
                        results["has_suspicious_objects"] = True
                
                # Analyze document.xml or other main content files
                main_content_files = [
                    f for f in file_list if "document.xml" in f or "sheet1.xml" in f
                ]
                
                for content_file in main_content_files:
                    try:
                        with zip_file.open(content_file) as f:
                            content = f.read()
                            # Look for URLs, IPs, etc.
                            self._extract_patterns_from_binary(content, results)
                    except Exception as e:
                        logger.error(f"Error reading content file {content_file}: {e}")
                        
        except Exception as e:
            logger.error(f"Error analyzing zip archive: {e}")
            results["suspicious_indicators"].append(f"Error analyzing archive structure: {str(e)}")
    
    def _analyze_pdf(self, file_path, results):
        """Analyze PDF files for suspicious content"""
        try:
            # Read the file as binary to look for patterns
            with open(file_path, 'rb') as f:
                content = f.read()
                
            # Check for suspicious PDF objects
            for keyword in self.pdf_suspicious_keywords:
                keyword_bytes = keyword.encode()
                if keyword_bytes in content:
                    results["suspicious_indicators"].append(f"Suspicious PDF keyword: {keyword}")
                    results["has_suspicious_objects"] = True
            
            # Check for JavaScript in PDF
            js_patterns = [rb'/JavaScript', rb'/JS', rb'/FS']
            js_match = any(pattern in content for pattern in js_patterns)
            if js_match:
                results["suspicious_indicators"].append("PDF contains JavaScript")
                results["has_suspicious_objects"] = True
            
            # Check for auto-action triggers
            action_patterns = [rb'/AA', rb'/OpenAction', rb'/Launch']
            action_match = any(pattern in content for pattern in action_patterns)
            if action_match:
                results["suspicious_indicators"].append("PDF contains auto-action triggers")
            
            # Check for embedded files
            if rb'/EmbeddedFile' in content or rb'/FileSpec' in content:
                results["suspicious_indicators"].append("PDF contains embedded files")
                results["has_suspicious_objects"] = True
            
            # Extract URLs, IPs, etc.
            self._extract_patterns_from_binary(content, results)
            
        except Exception as e:
            logger.error(f"Error analyzing PDF: {e}")
            results["suspicious_indicators"].append(f"Error analyzing PDF structure: {str(e)}")
    
    def _analyze_rtf(self, file_path, results):
        """Analyze RTF files for suspicious content"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Check for OLE objects in RTF
            ole_patterns = [rb'\\objdata', rb'\\objclass', rb'\\objupdate', rb'\\objemb', rb'\\objlink']
            for pattern in ole_patterns:
                if pattern in content:
                    results["suspicious_indicators"].append(f"RTF contains OLE objects: {pattern.decode()}")
                    results["has_suspicious_objects"] = True
            
            # Check for exploits or shellcode
            shellcode_patterns = [rb'\\bin', rb'45786563', rb'shell', rb'\\objupdate', rb'\\objdata', rb'\\objclass']
            for pattern in shellcode_patterns:
                if pattern in content:
                    results["suspicious_indicators"].append(f"RTF may contain shellcode or exploit: {pattern.decode()}")
                    results["has_suspicious_objects"] = True
            
            # Extract URLs, IPs, etc.
            self._extract_patterns_from_binary(content, results)
            
        except Exception as e:
            logger.error(f"Error analyzing RTF: {e}")
            results["suspicious_indicators"].append(f"Error analyzing RTF structure: {str(e)}")
    
    def _analyze_xml(self, file_path, results):
        """Analyze XML files for suspicious content"""
        try:
            # Try to parse as XML
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Convert to string and check for suspicious patterns
            xml_string = ET.tostring(root, encoding='utf-8')
            
            # Check for embedded scripts
            if b'<script>' in xml_string or b'javascript:' in xml_string:
                results["suspicious_indicators"].append("XML contains script tags or JavaScript")
                results["has_suspicious_objects"] = True
            
            # Check for external entities
            if b'<!ENTITY' in xml_string and b'SYSTEM' in xml_string:
                results["suspicious_indicators"].append("XML contains external entities (XXE risk)")
                results["has_suspicious_objects"] = True
            
            # Extract URLs, IPs, etc.
            self._extract_patterns_from_binary(xml_string, results)
            
        except ET.ParseError:
            logger.warning(f"Could not parse {file_path} as valid XML")
            # Try to read as binary and do basic analysis
            self._analyze_binary_file(file_path, results)
        except Exception as e:
            logger.error(f"Error analyzing XML: {e}")
            results["suspicious_indicators"].append(f"Error analyzing XML structure: {str(e)}")
    
    def _analyze_text_file(self, file_path, results):
        """Analyze text files for suspicious content"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Check for scripts
            script_patterns = [b'<script>', b'function()', b'eval(', b'exec(', b'require(', b'import ', b'powershell']
            for pattern in script_patterns:
                if pattern in content:
                    results["suspicious_indicators"].append(f"Text file contains script code: {pattern.decode()}")
                    results["has_suspicious_objects"] = True
            
            # Check for base64 encoded content
            base64_matches = self.base64_pattern.findall(content)
            if base64_matches and len(base64_matches) > 0:
                # If we find long base64 strings, that could be suspicious
                if any(len(match) > 100 for match in base64_matches):
                    results["suspicious_indicators"].append("Text file contains long base64 encoded strings")
            
            # Extract URLs, IPs, etc.
            self._extract_patterns_from_binary(content, results)
            
        except Exception as e:
            logger.error(f"Error analyzing text file: {e}")
            results["suspicious_indicators"].append(f"Error analyzing text file: {str(e)}")
    
    def _analyze_binary_file(self, file_path, results):
        """Perform basic analysis on binary files"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Extract strings from binary
            visible_chars = set(range(32, 127))  # ASCII printable characters
            strings = []
            current_string = []
            
            for byte in content:
                if byte in visible_chars:
                    current_string.append(chr(byte))
                else:
                    if len(current_string) >= 4:  # Only consider strings of 4+ chars
                        strings.append(''.join(current_string))
                    current_string = []
            
            # Check the last string
            if len(current_string) >= 4:
                strings.append(''.join(current_string))
            
            # Check for suspicious strings
            suspicious_strings = ['cmd.exe', 'powershell', 'http://', 'https://', 'CreateProcess',
                                 'WinExec', 'ShellExecute', 'WSASocket', 'GetTickCount']
            
            for s_string in suspicious_strings:
                if any(s_string in s for s in strings):
                    results["suspicious_indicators"].append(f"Binary contains suspicious string: {s_string}")
                    results["has_suspicious_objects"] = True
            
            # Extract URLs, IPs, etc.
            self._extract_patterns_from_binary(content, results)
            
        except Exception as e:
            logger.error(f"Error analyzing binary file: {e}")
            results["suspicious_indicators"].append(f"Error analyzing binary file: {str(e)}")
    
    def _extract_patterns_from_binary(self, content, results):
        """Extract interesting patterns from binary content"""
        # Extract URLs
        urls = self.url_pattern.findall(content)
        for url in urls:
            decoded_url = url.decode('utf-8', errors='ignore')
            if decoded_url not in results["extracted_urls"]:
                results["extracted_urls"].append(decoded_url)
        
        # Extract IP addresses
        ips = self.ip_pattern.findall(content)
        for ip in ips:
            decoded_ip = ip.decode('utf-8', errors='ignore')
            if decoded_ip not in results["extracted_ips"]:
                results["extracted_ips"].append(decoded_ip)
        
        # Count suspicious URL keywords
        suspicious_domains = ['pastebin', 'github', 'raw.githubusercontent', 'bit.ly', 'goo.gl',
                             'dropbox', 'drive.google', 'mediafire', 'megaupload', 'sendspace', 
                             'tinyurl', 'ngrok', 'dyndns', 'no-ip', 'freedns']
        
        for url in results["extracted_urls"]:
            if any(sus_domain in url.lower() for sus_domain in suspicious_domains):
                results["suspicious_indicators"].append(f"URL to potentially suspicious service: {url}")
    
    def _calculate_risk_score(self, results):
        """Calculate a risk score based on findings"""
        score = 0
        
        # Baseline from number of suspicious indicators
        score += len(results["suspicious_indicators"]) * 5
        
        # Add points for macros
        if results["has_macros"]:
            score += 30
        
        # Add points for suspicious objects
        if results["has_suspicious_objects"]:
            score += 25
        
        # Add points for URLs and IPs
        score += len(results["extracted_urls"]) * 2
        score += len(results["extracted_ips"]) * 2
        
        # Cap the score at 100
        score = min(score, 100)
        
        # Determine risk level
        if score < 30:
            risk_level = "Low"
        elif score < 70:
            risk_level = "Medium"
        else:
            risk_level = "High"
        
        results["risk_score"] = {
            "score": score,
            "risk_level": risk_level
        }
    
    def _calculate_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256.update(byte_block)
                
        return sha256.hexdigest()


# Example usage
if __name__ == "__main__":
    analyzer = DocumentAnalyzer()
    
    # Example file path - should be replaced with actual file to analyze
    test_file = "path/to/document.docx"
    
    if os.path.exists(test_file):
        results = analyzer.analyze_document(test_file)
        print(json.dumps(results, indent=2))
    else:
        print(f"Test file not found: {test_file}") 