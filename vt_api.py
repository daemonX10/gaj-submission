import os
import json
import time
import hashlib
import requests
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='vt_api.log'
)
logger = logging.getLogger('VirusTotal-API')

class VirusTotalScanner:
    """
    Provides integration with the VirusTotal API to scan files
    """
    def __init__(self, api_key=None, api_url="https://www.virustotal.com/api/v3"):
        """
        Initialize the VirusTotal scanner
        
        Args:
            api_key: VirusTotal API key (if None, will try to load from VT_API_KEY environment variable)
            api_url: Base URL for the VirusTotal API
        """
        self.api_key = api_key or os.environ.get("VT_API_KEY")
        self.api_url = api_url
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        self.enabled = bool(self.api_key)
        
        if not self.enabled:
            logger.warning("VirusTotal API key not found. Functionality will be limited.")
    
    def scan_file(self, file_path):
        """
        Scan a file with VirusTotal
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            dict: Scan results or error information
        """
        if not self.enabled:
            return {"error": "VirusTotal API key not configured"}
        
        try:
            # Calculate file hash
            sha256_hash = self._calculate_hash(file_path)
            
            # First, check if the file has already been analyzed
            result = self.get_file_report(sha256_hash)
            
            # If the file hasn't been analyzed or if the analysis is not recent, upload it
            if result.get("error") == "Not Found" or result.get("outdated", False):
                # Upload file for scanning
                upload_result = self._upload_file(file_path)
                
                if "error" in upload_result:
                    return upload_result
                
                # Wait for analysis to complete (with timeout)
                result = self._wait_for_analysis(sha256_hash)
            
            return self._format_results(result)
        except Exception as e:
            logger.error(f"Error scanning file with VirusTotal: {e}")
            return {"error": str(e)}
    
    def get_file_report(self, file_hash):
        """
        Get analysis report for a file hash
        
        Args:
            file_hash: SHA-256 hash of the file
            
        Returns:
            dict: Report data or error information
        """
        if not self.enabled:
            return {"error": "VirusTotal API key not configured"}
        
        try:
            url = f"{self.api_url}/files/{file_hash}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"error": "Not Found"}
            else:
                logger.error(f"VirusTotal API error: {response.status_code}, {response.text}")
                return {"error": f"API Error: {response.status_code}"}
        except Exception as e:
            logger.error(f"Error getting file report from VirusTotal: {e}")
            return {"error": str(e)}
    
    def _upload_file(self, file_path):
        """
        Upload a file to VirusTotal for scanning
        
        Args:
            file_path: Path to the file to upload
            
        Returns:
            dict: Upload response or error information
        """
        try:
            url = f"{self.api_url}/files"
            
            with open(file_path, 'rb') as file:
                files = {'file': (os.path.basename(file_path), file)}
                response = requests.post(url, headers=self.headers, files=files)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"VirusTotal upload error: {response.status_code}, {response.text}")
                return {"error": f"Upload Error: {response.status_code}"}
        except Exception as e:
            logger.error(f"Error uploading file to VirusTotal: {e}")
            return {"error": str(e)}
    
    def _wait_for_analysis(self, file_hash, max_wait=60, poll_interval=5):
        """
        Wait for VirusTotal analysis to complete
        
        Args:
            file_hash: SHA-256 hash of the file
            max_wait: Maximum time to wait in seconds
            poll_interval: Time between polls in seconds
            
        Returns:
            dict: Analysis results or error information
        """
        start_time = time.time()
        elapsed = 0
        
        while elapsed < max_wait:
            result = self.get_file_report(file_hash)
            
            # Check if analysis is complete
            if "error" not in result and result.get("data", {}).get("attributes", {}).get("last_analysis_results"):
                return result
            
            # Wait before polling again
            time.sleep(poll_interval)
            elapsed = time.time() - start_time
        
        return {"error": "Analysis timeout", "outdated": True}
    
    def _format_results(self, vt_response):
        """
        Format VirusTotal response into a simplified structure
        
        Args:
            vt_response: Raw VirusTotal API response
            
        Returns:
            dict: Formatted results
        """
        try:
            if "error" in vt_response:
                return vt_response
            
            data = vt_response.get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            results = attributes.get("last_analysis_results", {})
            
            formatted = {
                "scan_id": data.get("id", ""),
                "scan_date": attributes.get("last_analysis_date", ""),
                "total": sum(stats.values()),
                "positives": stats.get("malicious", 0) + stats.get("suspicious", 0),
                "sha256": attributes.get("sha256", ""),
                "md5": attributes.get("md5", ""),
                "permalink": f"https://www.virustotal.com/gui/file/{attributes.get('sha256', '')}",
                "scans": {}
            }
            
            # Format scan results
            for engine, result in results.items():
                formatted["scans"][engine] = {
                    "detected": result.get("category") in ["malicious", "suspicious"],
                    "result": result.get("result", ""),
                    "version": result.get("engine_version", ""),
                    "update": result.get("engine_update", "")
                }
            
            return formatted
        except Exception as e:
            logger.error(f"Error formatting VirusTotal results: {e}")
            return {"error": f"Error formatting results: {str(e)}"}
    
    def _calculate_hash(self, file_path):
        """
        Calculate SHA-256 hash of a file
        
        Args:
            file_path: Path to the file
            
        Returns:
            str: SHA-256 hash
        """
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256.update(byte_block)
                
        return sha256.hexdigest()
    
    def get_status(self):
        """
        Check if VirusTotal API is working correctly
        
        Returns:
            dict: Status information
        """
        if not self.enabled:
            return {
                "enabled": False,
                "status": "disabled",
                "message": "API key not configured"
            }
        
        try:
            # Make a simple API call to check if the key is valid
            url = f"{self.api_url}/users/current"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                user_data = response.json().get("data", {})
                quota = user_data.get("attributes", {}).get("quotas", {})
                
                return {
                    "enabled": True,
                    "status": "operational",
                    "user_type": user_data.get("type", ""),
                    "quota": quota,
                    "message": "API is working correctly"
                }
            else:
                return {
                    "enabled": True,
                    "status": "error",
                    "message": f"API Error: {response.status_code}"
                }
        except Exception as e:
            logger.error(f"Error checking VirusTotal API status: {e}")
            return {
                "enabled": True,
                "status": "error",
                "message": str(e)
            }


# Example usage
if __name__ == "__main__":
    # Initialize scanner
    scanner = VirusTotalScanner()
    
    # Check if API is configured
    status = scanner.get_status()
    print(f"VirusTotal API Status: {status['status']}")
    
    if scanner.enabled:
        # Example scan (replace with an actual file path)
        test_file = "path/to/test/file.exe"
        if os.path.exists(test_file):
            print(f"Scanning file: {test_file}")
            result = scanner.scan_file(test_file)
            print(json.dumps(result, indent=2)) 